```diff
diff --git a/.coveragerc b/.coveragerc
index 3c3efd7..de8cf5f 100644
--- a/.coveragerc
+++ b/.coveragerc
@@ -1,5 +1,3 @@
 [report]
-# Verifier is used for testing only.
 omit =
   */__main__.py
-  */verifier.py
diff --git a/.flake8 b/.flake8
index bb1ce94..3159107 100644
--- a/.flake8
+++ b/.flake8
@@ -13,6 +13,5 @@ ignore =
     # line break after binary operator
     W504
 
-disable-noqa 
 indent-size = 2
 max-line-length = 80
diff --git a/.gitattributes b/.gitattributes
new file mode 100644
index 0000000..5bb982c
--- /dev/null
+++ b/.gitattributes
@@ -0,0 +1 @@
+.python-version eol=lf
diff --git a/.github/dependabot.yml b/.github/dependabot.yml
new file mode 100644
index 0000000..c963e3c
--- /dev/null
+++ b/.github/dependabot.yml
@@ -0,0 +1,12 @@
+version: 2
+updates:
+
+  - package-ecosystem: "github-actions"
+    commit-message:
+      include: "scope"
+      prefix: "Actions"
+    directory: "/"
+    labels:
+      - "enhancement"
+    schedule:
+      interval: "weekly"
diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
index 280af43..754ff15 100644
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -1,34 +1,37 @@
 # This workflow will install Python dependencies, run tests and lint with a variety of Python versions
 # For more information see: https://help.github.com/actions/language-and-framework-guides/using-python-with-github-actions
 
-name: YAPF
+name: Test with pytest
 
-on: [push]
+on:
+  pull_request:
+  push:
 
 jobs:
   build:
-
     runs-on: ${{ matrix.os }}
     strategy:
+      fail-fast: false
       matrix:
-        python-version: [2.7, 3.7, 3.8, 3.9]
-        os: [ubuntu-latest, macos-latest]
-
+        python-version: ["3.8", "3.11", "3.12"]  # no particular need for 3.9 or 3.10
+        os: [macos-latest, ubuntu-latest, windows-latest]
     steps:
-    - uses: actions/checkout@v2
+    - uses: actions/checkout@eef61447b9ff4aafe5dcd4e0bbf5d482be7e7871  # v4.2.1
     - name: Set up Python ${{ matrix.python-version }}
-      uses: actions/setup-python@v2
+      uses: actions/setup-python@82c7e631bb3cdc910f68e0081d67478d79c6982d  # v4.6.0
       with:
         python-version: ${{ matrix.python-version }}
-    - name: Install dependencies
-      run: |
-        python -m pip install --upgrade pip
-    - name: Lint with flake8
-      run: |
-        python -m pip install toml flake8
-        flake8 . --statistics
-    - name: Test with pytest
-      run: |
-        pip install pytest
-        pip install pytest-cov
+    - name: Upgrade pip
+      run: >-
+        python -m pip install
+        --upgrade
+        --disable-pip-version-check
+        pip
+    - name: Perform package installs
+      run: >-
+        pip install
+        .
         pytest
+        pytest-cov
+    - name: Test with pytest
+      run: pytest
diff --git a/.github/workflows/pre-commit-autoupdate.yml b/.github/workflows/pre-commit-autoupdate.yml
new file mode 100644
index 0000000..91b8e46
--- /dev/null
+++ b/.github/workflows/pre-commit-autoupdate.yml
@@ -0,0 +1,63 @@
+# Copyright (c) 2023 Sebastian Pipping <sebastian@pipping.org>
+# Licensed under the Apache License Version 2.0
+
+name: Keep pre-commit hooks up to date
+
+on:
+  schedule:
+    - cron: '0 16 * * 5'  # Every Friday 4pm
+  workflow_dispatch:
+
+# NOTE: This will drop all permissions from GITHUB_TOKEN except metadata read,
+#       and then (re)add the ones listed below:
+permissions:
+  contents: write
+  pull-requests: write
+
+jobs:
+  pre_commit_autoupdate:
+    name: Detect outdated pre-commit hooks
+    runs-on: ubuntu-22.04
+    steps:
+      - uses: actions/checkout@eef61447b9ff4aafe5dcd4e0bbf5d482be7e7871  # v4.2.1
+
+      - name: Set up Python 3.11
+        uses: actions/setup-python@82c7e631bb3cdc910f68e0081d67478d79c6982d  # v5.1.0
+        with:
+          python-version: 3.11
+
+      - name: Install pre-commit
+        run: |-
+          pip install \
+            --disable-pip-version-check \
+            --no-warn-script-location \
+            --user \
+            pre-commit
+          echo "PATH=${HOME}/.local/bin:${PATH}" >> "${GITHUB_ENV}"
+
+      - name: Check for outdated hooks
+        run: |-
+          pre-commit autoupdate
+          git diff -- .pre-commit-config.yaml
+
+      - name: Create pull request from changes (if any)
+        id: create-pull-request
+        uses: peter-evans/create-pull-request@5e914681df9dc83aa4e4905692ca88beb2f9e91f  # v7.0.5
+        with:
+          author: 'pre-commit <pre-commit@tools.invalid>'
+          base: main
+          body: |-
+            For your consideration.
+
+            :warning: Please **CLOSE AND RE-OPEN** this pull request so that [further workflow runs get triggered](https://github.com/peter-evans/create-pull-request/blob/main/docs/concepts-guidelines.md#triggering-further-workflow-runs) for this pull request.
+          branch: precommit-autoupdate
+          commit-message: "pre-commit: Autoupdate"
+          delete-branch: true
+          draft: true
+          labels: enhancement
+          title: "pre-commit: Autoupdate"
+
+      - name: Log pull request URL
+        if: "${{ steps.create-pull-request.outputs.pull-request-url }}"
+        run: |
+          echo "Pull request URL is: ${{ steps.create-pull-request.outputs.pull-request-url }}"
diff --git a/.github/workflows/pre-commit.yml b/.github/workflows/pre-commit.yml
new file mode 100644
index 0000000..c01223a
--- /dev/null
+++ b/.github/workflows/pre-commit.yml
@@ -0,0 +1,37 @@
+# Copyright (c) 2023 Sebastian Pipping <sebastian@pipping.org>
+# Licensed under the Apache License Version 2.0
+
+name: Run pre-commit
+
+# Drop permissions to minimum for security
+permissions:
+  contents: read
+
+on:
+  pull_request:
+  push:
+  schedule:
+    - cron: '0 2 * * 5'  # Every Friday at 2am
+  workflow_dispatch:
+
+jobs:
+  pre_commit_run:
+    name: Run pre-commit
+    runs-on: ubuntu-22.04
+    steps:
+      - uses: actions/checkout@eef61447b9ff4aafe5dcd4e0bbf5d482be7e7871  # v4.2.1
+
+      - uses: actions/setup-python@82c7e631bb3cdc910f68e0081d67478d79c6982d  # v5.1.0
+        with:
+          python-version: 3.11
+
+      - name: Install yapf (to be available to pre-commit)
+        run: |-
+          pip install \
+            --disable-pip-version-check \
+            --no-warn-script-location \
+            --user \
+            .
+          echo "PATH=${HOME}/.local/bin:${PATH}" >> "${GITHUB_ENV}"
+
+      - uses: pre-commit/action@2c7b3805fd2a0fd8c1884dcaebf91fc102a13ecd  # v3.0.1
diff --git a/.gitignore b/.gitignore
index 960818e..6a6928e 100644
--- a/.gitignore
+++ b/.gitignore
@@ -13,8 +13,9 @@
 *~
 # Merge files created by git.
 *.orig
-# Byte compiled python modules.
+# Compiled python.
 *.pyc
+*.pickle
 # vim swap files
 .*.sw?
 .sw?
@@ -33,5 +34,12 @@
 /.tox
 /yapf.egg-info
 
+# IDEs
 /.idea
+/.vscode/settings.json
 
+# Virtual Environment
+/.venv*/
+
+# Worktrees
+/.wt
diff --git a/.isort.cfg b/.isort.cfg
new file mode 100644
index 0000000..d9ce8b8
--- /dev/null
+++ b/.isort.cfg
@@ -0,0 +1,6 @@
+[settings]
+force_single_line=true
+known_third_party=yapf_third_party
+known_yapftests=yapftests
+
+sections=FUTURE,STDLIB,THIRDPARTY,FIRSTPARTY,LOCALFOLDER,YAPFTESTS
diff --git a/.pre-commit-config.yaml b/.pre-commit-config.yaml
index 3bd65c2..906b8cf 100644
--- a/.pre-commit-config.yaml
+++ b/.pre-commit-config.yaml
@@ -2,28 +2,34 @@
 # to enable run `pip install pre-commit && pre-commit install`
 
 repos:
+  - repo: https://github.com/pycqa/isort
+    rev: 5.13.2
+    hooks:
+      - id: isort
+        name: isort (python)
   - repo: local
     hooks:
       - id: yapf
         name: yapf
         language: python
         entry: yapf
-        args: [-i, -vv]
+        args: [-i]
         types: [python]
+  - repo: https://github.com/pycqa/flake8
+    rev: 7.0.0
+    hooks:
+      - id: flake8
   - repo: https://github.com/pre-commit/pre-commit-hooks
-    rev: v3.2.0
+    rev: v4.5.0
     hooks:
       - id: trailing-whitespace
       - id: check-docstring-first
-      - id: check-json
       - id: check-added-large-files
       - id: check-yaml
       - id: debug-statements
-      - id: requirements-txt-fixer
       - id: check-merge-conflict
       - id: double-quote-string-fixer
       - id: end-of-file-fixer
-      - id: sort-simple-yaml
   - repo: meta
     hooks:
       - id: check-hooks-apply
diff --git a/.pre-commit-config.yml b/.pre-commit-config.yml
deleted file mode 100644
index 3bd65c2..0000000
--- a/.pre-commit-config.yml
+++ /dev/null
@@ -1,30 +0,0 @@
-# File introduces automated checks triggered on git events
-# to enable run `pip install pre-commit && pre-commit install`
-
-repos:
-  - repo: local
-    hooks:
-      - id: yapf
-        name: yapf
-        language: python
-        entry: yapf
-        args: [-i, -vv]
-        types: [python]
-  - repo: https://github.com/pre-commit/pre-commit-hooks
-    rev: v3.2.0
-    hooks:
-      - id: trailing-whitespace
-      - id: check-docstring-first
-      - id: check-json
-      - id: check-added-large-files
-      - id: check-yaml
-      - id: debug-statements
-      - id: requirements-txt-fixer
-      - id: check-merge-conflict
-      - id: double-quote-string-fixer
-      - id: end-of-file-fixer
-      - id: sort-simple-yaml
-  - repo: meta
-    hooks:
-      - id: check-hooks-apply
-      - id: check-useless-excludes
diff --git a/.pre-commit-hooks.yaml b/.pre-commit-hooks.yaml
index 3eba1f2..e834fc4 100644
--- a/.pre-commit-hooks.yaml
+++ b/.pre-commit-hooks.yaml
@@ -7,3 +7,15 @@
   args: [-i] #inplace
   language: python
   types: [python]
+
+- id: yapf-diff
+  name: yapf-diff
+  description: "A formatter for Python files. (formats only changes included in commit)"
+  always_run: true
+  language: python
+  pass_filenames: false
+  stages: [pre-commit]
+  entry: |
+    bash -c "git diff -U0 --no-color --relative HEAD \
+                  | yapf-diff \
+                  | tee >(git apply --allow-empty -p0)"
diff --git a/.pre-commit-hooks.yml b/.pre-commit-hooks.yml
deleted file mode 100644
index 3eba1f2..0000000
--- a/.pre-commit-hooks.yml
+++ /dev/null
@@ -1,9 +0,0 @@
-# File configures YAPF to be used as a git hook with https://github.com/pre-commit/pre-commit
-
-- id: yapf
-  name: yapf
-  description: "A formatter for Python files."
-  entry: yapf
-  args: [-i] #inplace
-  language: python
-  types: [python]
diff --git a/.python-version b/.python-version
new file mode 100644
index 0000000..f4bd916
--- /dev/null
+++ b/.python-version
@@ -0,0 +1,5 @@
+3.7.9
+3.8.10
+3.9.13
+3.10.11
+3.11.5
diff --git a/.vscode/extensions.json b/.vscode/extensions.json
new file mode 100644
index 0000000..f3f2fe8
--- /dev/null
+++ b/.vscode/extensions.json
@@ -0,0 +1,15 @@
+{
+    "recommendations": [
+        "eeyore.yapf",
+        "dangmai.workspace-default-settings",
+        "ms-python.flake8",
+        "ms-python.isort",
+        "ms-python.python",
+    ],
+    // These are remarked as extenstions you should disable for this workspace.
+    // VSCode does not support disabling extensions via workspace config files.
+    "unwantedRecommendations": [
+        "ms-python.black-formatter",
+        "ms-python.pylint"
+    ]
+}
diff --git a/.vscode/settings.default.json b/.vscode/settings.default.json
new file mode 100644
index 0000000..502f59d
--- /dev/null
+++ b/.vscode/settings.default.json
@@ -0,0 +1,33 @@
+{
+    "editor.codeActionsOnSave": {
+        "source.organizeImports": true
+    },
+    "files.insertFinalNewline": true,
+    "files.trimFinalNewlines": true,
+    "[python]": {
+        "diffEditor.ignoreTrimWhitespace": false,
+        "editor.defaultFormatter": "eeyore.yapf",
+        "editor.formatOnSaveMode": "file",
+        "editor.formatOnSave": true,
+        "editor.wordBasedSuggestions": false,
+        "files.trimTrailingWhitespace": true,
+    },
+    "python.analysis.extraPaths": [
+        "./third_party"
+    ],
+    "python.analysis.typeCheckingMode": "basic",
+    "python.languageServer": "Pylance",
+    "files.exclude": {
+        "**/*$py.class": true
+    },
+    "json.schemas": [
+        {
+            "fileMatch": [
+                "/.vscode/settings.default.json"
+            ],
+            "url": "vscode://schemas/settings/folder"
+        }
+    ],
+    "workspace-default-settings.runOnActivation": true,
+    "workspace-default-settings.jsonIndentation": 4
+}
diff --git a/CHANGELOG b/CHANGELOG.md
similarity index 89%
rename from CHANGELOG
rename to CHANGELOG.md
index 4e62520..ccc8726 100644
--- a/CHANGELOG
+++ b/CHANGELOG.md
@@ -2,6 +2,119 @@
 # All notable changes to this project will be documented in this file.
 # This project adheres to [Semantic Versioning](http://semver.org/).
 
+## (0.41.0) UNRELEASED
+### Added
+- New `DISABLE_SPLIT_LIST_WITH_COMMENT` flag.
+ `DISABLE_SPLIT_LIST_WITH_COMMENT` is a new knob that changes the
+  behavior of splitting a list when a comment is present inside the list.
+
+  Before, we split a list containing a comment just like we split a list
+  containing a trailing comma: Each element goes on its own line (unless
+  `DISABLE_ENDING_COMMA_HEURISTIC` is true).
+
+  This new flag allows you to control the behavior of a list with a comment
+  *separately* from the behavior when the list contains a trailing comma.
+
+  This mirrors the behavior of clang-format, and is useful for e.g. forming
+  "logical groups" of elements in a list.
+
+  Without this flag:
+
+  ```
+  [
+    a,
+    b,  #
+    c
+  ]
+  ```
+
+  With this flag:
+
+  ```
+  [
+    a, b,  #
+    c
+  ]
+  ```
+
+  Before we had one flag that controlled two behaviors.
+
+    - `DISABLE_ENDING_COMMA_HEURISTIC=false` (default):
+      - Split a list that has a trailing comma.
+      - Split a list that contains a comment.
+    - `DISABLE_ENDING_COMMA_HEURISTIC=true`:
+      - Don't split on trailing comma.
+      - Don't split on comment.
+
+  Now we have two flags.
+
+    - `DISABLE_ENDING_COMMA_HEURISTIC=false` and `DISABLE_SPLIT_LIST_WITH_COMMENT=false` (default):
+      - Split a list that has a trailing comma.
+      - Split a list that contains a comment.
+      Behavior is unchanged from the default before.
+    - `DISABLE_ENDING_COMMA_HEURISTIC=true` and `DISABLE_SPLIT_LIST_WITH_COMMENT=false` :
+      - Don't split on trailing comma.
+      - Do split on comment.  **This is a change in behavior from before.**
+    - `DISABLE_ENDING_COMMA_HEURISTIC=false` and `DISABLE_SPLIT_LIST_WITH_COMMENT=true` :
+      - Split on trailing comma.
+      - Don't split on comment.
+    - `DISABLE_ENDING_COMMA_HEURISTIC=true` and `DISABLE_SPLIT_LIST_WITH_COMMENT=true` :
+      - Don't split on trailing comma.
+      - Don't split on comment.
+      **You used to get this behavior just by setting one flag, but now you have to set both.**
+
+  Note the behavioral change above; if you set
+  `DISABLE_ENDING_COMMA_HEURISTIC=true` and want to keep the old behavior, you
+  now also need to set `DISABLE_SPLIT_LIST_WITH_COMMENT=true`.
+### Changes
+- Remove dependency on importlib-metadata
+- Remove dependency on tomli when using >= py311
+- Format '.pyi' type sub files.
+### Fixed
+- Fix SPLIT_ARGUMENTS_WHEN_COMMA_TERMINATED for one-item named argument lists
+  by taking precedence over SPLIT_BEFORE_NAMED_ASSIGNS.
+- Fix SPLIT_ALL_COMMA_SEPARATED_VALUES and SPLIT_ALL_TOP_LEVEL_COMMA_SEPARATED_VALUES
+  being too agressive for lambdas and unpacking.
+
+## [0.40.2] 2023-09-22
+### Changes
+- The verification module has been removed. NOTE: this changes the public APIs
+  by removing the "verify" parameter.
+- Changed FORCE_MULTILINE_DICT to override SPLIT_ALL_TOP_LEVEL_COMMA_SEPARATED_VALUES.
+- Adopt pyproject.toml (PEP 517) for build system
+### Fixed
+- Do not treat variables named `match` as the match keyword.
+- Fix SPLIT_ARGUMENTS_WHEN_COMMA_TERMINATED for one-item argument lists.
+- Fix trailing backslash-newline on Windows when using stdin.
+
+## [0.40.1] 2023-06-20
+### Fixed
+- Corrected bad distribution v0.40.0 package.
+
+## [0.40.0] 2023-06-13 [YANKED - [#1107](https://github.com/google/yapf/issues/1107)]
+### Added
+- Support for Python 3.11
+- Add the `--print-modified` flag to print out file names of modified files when
+  running in in-place mode.
+### Changes
+- Replace the outdated and no-longer-supported lib2to3 with a fork of blib2to3,
+  Black's version of lib2to3.
+### Removed
+- Support for Python versions < 3.7 are no longer supported.
+
+## [0.33.0] 2023-04-18 [YANKED - [#1154](https://github.com/google/yapf/issues/1154)]
+### Added
+- Add a new Python parser to generate logical lines.
+- Added support for `# fmt: on` and `# fmt: off` pragmas.
+### Changes
+- Moved 'pytree' parsing tools into its own subdirectory.
+- Add support for Python 3.10.
+- Format generated dicts with respect to same rules as regular dicts
+- Generalized the ending comma heuristic to subscripts.
+- Supports "pyproject.toml" by default.
+### Fixed
+- Split line before all comparison operators.
+
 ## [0.32.0] 2021-12-26
 ### Added
 - Look at the 'pyproject.toml' file to see if it contains ignore file information
@@ -18,6 +131,7 @@
 - Rename "unwrapped_line" module to "logical_line."
 - Rename "UnwrappedLine" class to "LogicalLine."
 ### Fixed
+- Added pyproject extra to install toml package as an optional dependency.
 - Enable `BLANK_LINE_BEFORE_NESTED_CLASS_OR_DEF` knob for "pep8" style, so
   method definitions inside a class are surrounded by a single blank line as
   prescribed by PEP8.
@@ -25,7 +139,7 @@
 
 ## [0.31.0] 2021-03-14
 ### Added
-- Renamed 'master' brannch to 'main'.
+- Renamed 'master' branch to 'main'.
 - Add 'BLANK_LINES_BETWEEN_TOP_LEVEL_IMPORTS_AND_VARIABLES' to support setting
   a custom number of blank lines between top-level imports and variable
   definitions.
diff --git a/CONTRIBUTING.rst b/CONTRIBUTING.md
similarity index 62%
rename from CONTRIBUTING.rst
rename to CONTRIBUTING.md
index fa6cda0..4c0273c 100644
--- a/CONTRIBUTING.rst
+++ b/CONTRIBUTING.md
@@ -1,12 +1,13 @@
-Want to contribute? Great! First, read this page (including the small print at the end).
+# How to Contribute
 
-Before you contribute
----------------------
+Want to contribute? Great! First, read this page (including the small print at
+the end).
 
-Before we can use your code, you must sign the `Google Individual Contributor
-License Agreement
-<https://developers.google.com/open-source/cla/individual?csw=1>`_ (CLA), which
-you can do online. The CLA is necessary mainly because you own the
+## Before you contribute
+
+Before we can use your code, you must sign the [Google Individual Contributor
+License Agreement](https://developers.google.com/open-source/cla/individual?csw=1)
+(CLA), which you can do online. The CLA is necessary mainly because you own the
 copyright to your changes, even after your contribution becomes part of our
 codebase, so we need your permission to use and distribute your code. We also
 need to be sure of various other things—for instance that you'll tell us if you
@@ -18,26 +19,31 @@ us first through the issue tracker with your idea so that we can help out and
 possibly guide you. Coordinating up front makes it much easier to avoid
 frustration later on.
 
-Code reviews
-------------
+## Code reviews
 
 All submissions, including submissions by project members, require review. We
 use Github pull requests for this purpose.
 
-YAPF coding style
------------------
+## YAPF coding style
 
-YAPF follows the `Google Python Style Guide
-<https://google.github.io/styleguide/pyguide.html>`_ with two exceptions:
+YAPF follows the [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html)
+with two exceptions:
 
 - 2 spaces for indentation rather than 4.
-- CamelCase for function and method names rather than snake_case.
+- CamelCase for function and method names rather than `snake_case`.
 
 The rationale for this is that YAPF was initially developed at Google where
 these two exceptions are still part of the internal Python style guide.
 
-Small print
------------
+## Getting started
+YAPF supports using tox 3 for creating a local dev environment, testing, and
+building redistributables. See [HACKING.md](HACKING.md) for more info.
+
+```bash
+$ pipx run --spec='tox<4' tox --devenv .venv
+```
+
+## Small print
 
 Contributions made by corporations are covered by a different agreement than
 the one above, the Software Grant and Corporate Contributor License Agreement.
diff --git a/CONTRIBUTORS b/CONTRIBUTORS
index 054ef26..fe6f13d 100644
--- a/CONTRIBUTORS
+++ b/CONTRIBUTORS
@@ -15,3 +15,4 @@ Sam Clegg <sbc@google.com>
 Łukasz Langa <ambv@fb.com>
 Oleg Butuzov <butuzov@made.ua>
 Mauricio Herrera Cuadra <mauricio@arareko.net>
+Kyle Gottfried <kyle.gottfried@outlook.com>
diff --git a/EDITOR SUPPORT.md b/EDITOR SUPPORT.md
new file mode 100644
index 0000000..b6f7acb
--- /dev/null
+++ b/EDITOR SUPPORT.md	
@@ -0,0 +1,82 @@
+# Using YAPF with your editor
+
+YAPF is supported by multiple editors via community extensions or plugins.
+
+- [IntelliJ/PyCharm](#intellijpycharm)
+- [IPython](#ipython)
+- [VSCode](#vscode)
+
+## IntelliJ/PyCharm
+
+Use the `File Watchers` plugin to run YAPF against a file when you perform a save.
+
+1.  Install the [File Watchers](https://www.jetbrains.com/help/idea/using-file-watchers.html) Plugin
+1.  Add the following `.idea/watcherTasks.xml` to your project. If you already have this file just add the `TaskOptions` section from below. This example uses Windows and a virtual environment, modify the `program` option as appropriate.
+    ```xml
+    <?xml version="1.0" encoding="UTF-8"?>
+    <project version="4">
+        <component name="ProjectTasksOptions">
+            <TaskOptions isEnabled="true">
+                <option name="arguments" value="-i $FilePathRelativeToProjectRoot$" />
+                <option name="checkSyntaxErrors" value="true" />
+                <option name="description" />
+                <option name="exitCodeBehavior" value="ERROR" />
+                <option name="fileExtension" value="py" />
+                <option name="immediateSync" value="true" />
+                <option name="name" value="yapf" />
+                <option name="output" value="" />
+                <option name="outputFilters">
+                    <array />
+                </option>
+                <option name="outputFromStdout" value="false" />
+                <option name="program" value="$PROJECT_DIR$/.venv/Scripts/yapf.exe" />
+                <option name="runOnExternalChanges" value="true" />
+                <option name="scopeName" value="Project Files" />
+                <option name="trackOnlyRoot" value="false" />
+                <option name="workingDir" value="$Projectpath$" />
+                <envs />
+            </TaskOptions>
+        </component>
+    </project>
+    ```
+
+## IPython
+
+IPython supports formatting lines automatically when you press the `<Enter>` button to submit the current code block.
+
+Make sure that the YAPF module is available to the IPython runtime:
+
+```shell
+pip install ipython yapf
+```
+
+pipx example:
+
+```shell
+pipx install ipython
+pipx inject ipython yapf
+```
+
+Add following to `~/.ipython/profile_default/ipython_config.py`:
+
+```python
+c.TerminalInteractiveShell.autoformatter = 'yapf'
+```
+
+## VSCode
+
+VSCode has deprecated support for YAPF in its official Python extension [in favor of dedicated formatter extensions](https://github.com/microsoft/vscode-python/wiki/Migration-to-Python-Tools-Extensions).
+
+1. Install EeyoreLee's [yapf](https://marketplace.visualstudio.com/items?itemName=eeyore.yapf) extension.
+1. Install the yapf package from pip.
+   ```
+   pip install yapf
+   ```
+1. Add the following to VSCode's `settings.json`:
+   ```jsonc
+   "[python]": {
+       "editor.formatOnSaveMode": "file",
+       "editor.formatOnSave": true,
+       "editor.defaultFormatter": "eeyore.yapf"  # choose this extension
+   },
+   ```
diff --git a/HACKING.md b/HACKING.md
new file mode 100644
index 0000000..1c03e80
--- /dev/null
+++ b/HACKING.md
@@ -0,0 +1,75 @@
+## Running YAPF on itself
+
+- To run YAPF on all of YAPF:
+
+```bash
+$ pipx run --spec=${PWD} --no-cache yapf -m -i -r yapf/ yapftests/ third_party/
+```
+
+- To run YAPF on just the files changed in the current git branch:
+
+```bash
+$ pipx run --spec=${PWD} --no-cache yapf -m -i $(git diff --name-only @{upstream})
+```
+
+## Testing and building redistributables locally
+
+YAPF uses tox 3 to test against multiple python versions and to build redistributables.
+
+Tox will opportunistically use pyenv environments when available.
+To configure pyenv run the following in bash:
+
+```bash
+$ xargs -t -n1 pyenv install  < .python-version
+```
+
+Test against all supported Python versions that are currently installed:
+```bash
+$ pipx run --spec='tox<4' tox
+```
+
+Build and test the sdist and wheel against your default Python environment. The redistributables will be in the `dist` directory.
+```bash
+$ pipx run --spec='tox<4' tox -e bdist_wheel -e sdist
+```
+
+## Releasing a new version
+
+1. Install all expected pyenv environements
+    ```bash
+    $ xargs -t -n1 pyenv install  < .python-version
+    ```
+
+1. Run tests against Python 3.7 - 3.11 with
+    ```bash
+    $ pipx run --spec='tox<4' tox
+    ```
+
+1. Bump version in `yapf/_version.py`.
+
+1. Build and test redistributables
+
+    ```bash
+    $ pipx run --spec='tox<4' tox -e bdist_wheel -e sdist
+    ```
+
+1. Check that it looks OK.
+   1. Install it onto a virtualenv,
+   1. run tests, and
+   1. run yapf as a tool.
+
+1. Push to PyPI:
+
+    ```bash
+    $ pipx run twine upload dist/*
+    ```
+
+1. Test in a clean virtualenv that 'pip install yapf' works with the new
+  version.
+
+1. Commit the version bump and add tag with:
+
+    ```bash
+    $ git tag v$(VERSION_NUM)
+    $ git push --tags
+    ```
diff --git a/HACKING.rst b/HACKING.rst
deleted file mode 100644
index cc27c5a..0000000
--- a/HACKING.rst
+++ /dev/null
@@ -1,32 +0,0 @@
-Running YAPF on itself
-----------------------
-
-To run YAPF on all of YAPF::
-
- $ PYTHONPATH=$PWD/yapf python -m yapf -i -r .
-
-To run YAPF on just the files changed in the current git branch::
-
- $ PYTHONPATH=$PWD/yapf python -m yapf -i $(git diff --name-only @{upstream})
-
-Releasing a new version
------------------------
-
-* Run tests: python setup.py test
-  [don't forget to run with Python 2.7 and 3.6]
-
-* Bump version in yapf/__init__.py
-
-* Build source distribution: python setup.py sdist
-
-* Check it looks OK, install it onto a virtualenv, run tests, run yapf as a tool
-
-* Build release: python setup.py sdist bdist_wheel
-
-* Push to PyPI: twine upload dist/*
-
-* Test in a clean virtualenv that 'pip install yapf' works with the new version
-
-* Commit the version bump; add tag with git tag v<VERSION_NUM>; git push --tags
-
-TODO: discuss how to use tox to make virtualenv testing easier.
diff --git a/MANIFEST.in b/MANIFEST.in
index 5c70a55..26bd40e 100644
--- a/MANIFEST.in
+++ b/MANIFEST.in
@@ -1,4 +1,4 @@
-include HACKING.rst LICENSE AUTHORS CHANGELOG CONTRIBUTING.rst CONTRIBUTORS
-include .coveragerc .editorconfig .flake8 plugins/README.rst
+include HACKING.md LICENSE AUTHORS CHANGELOG.md CONTRIBUTING.md CONTRIBUTORS
+include .coveragerc .editorconfig .flake8 plugins/README.md
 include plugins/vim/autoload/yapf.vim plugins/vim/plugin/yapf.vim pylintrc
 include .style.yapf tox.ini .travis.yml .vimrc
diff --git a/METADATA b/METADATA
index f278228..4244ec4 100644
--- a/METADATA
+++ b/METADATA
@@ -1,13 +1,19 @@
-name: "yapf"
-description:
-    "A formatter for Python files"
+# This project was upgraded with external_updater.
+# Usage: tools/external_updater/updater.sh update external/yapf
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
+name: "yapf"
+description: "A formatter for Python files"
 third_party {
-  url {
-    type: GIT
+  license_type: NOTICE
+  last_upgrade_date {
+    year: 2025
+    month: 1
+    day: 14
+  }
+  identifier {
+    type: "Git"
     value: "https://github.com/google/yapf.git"
+    version: "v0.43.0"
   }
-  version: "v0.32.0"
-  last_upgrade_date { year: 2022 month: 11 day: 2 }
-  license_type: NOTICE
 }
diff --git a/OWNERS b/OWNERS
index 0124a46..f29d87a 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,3 +1,4 @@
 yim@google.com
 yuexima@google.com
 # Will perform annual update
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/README.md b/README.md
new file mode 100644
index 0000000..7bb6b22
--- /dev/null
+++ b/README.md
@@ -0,0 +1,1071 @@
+# YAPF
+
+<p align="center">
+<a href="https://badge.fury.io/py/yapf"><img alt="PyPI Version" src="https://badge.fury.io/py/yapf.svg"></a>
+<a href="https://github.com/google/yapf/actions/workflows/ci.yml"><img alt="Build Status" src="https://github.com/google/yapf/actions/workflows/ci.yml/badge.svg"></a>
+<a href="https://github.com/google/yapf/actions/workflows/pre-commit.yml"><img alt="Actions Status" src="https://github.com/google/yapf/actions/workflows/pre-commit.yml/badge.svg"></a>
+<a href="https://coveralls.io/github/google/yapf?branch=main"><img alt="Coverage Status" src="https://coveralls.io/repos/github/google/yapf/badge.svg?branch=main"></a>
+</p>
+
+
+## Introduction
+
+YAPF is a Python formatter based on [`clang-format`](https://clang.llvm.org/docs/ClangFormat.html)
+(developed by Daniel Jasper). In essence, the algorithm takes the code and
+calculates the best formatting that conforms to the configured style. It takes
+away a lot of the drudgery of maintaining your code.
+
+The ultimate goal is that the code YAPF produces is as good as the code that a
+programmer would write if they were following the style guide.
+
+> **Note**
+> YAPF is not an official Google product (experimental or otherwise), it is
+> just code that happens to be owned by Google.
+
+
+## Installation
+
+To install YAPF from PyPI:
+
+```bash
+$ pip install yapf
+```
+
+YAPF is still considered in "beta" stage, and the released version may change
+often; therefore, the best way to keep up-to-date with the latest development
+is to clone this repository or install directly from github:
+
+```bash
+$ pip install git+https://github.com/google/yapf.git
+```
+
+Note that if you intend to use YAPF as a command-line tool rather than as a
+library, installation is not necessary. YAPF supports being run as a directory
+by the Python interpreter. If you cloned/unzipped YAPF into `DIR`, it's
+possible to run:
+
+```bash
+$ PYTHONPATH=DIR python DIR/yapf [options] ...
+```
+
+## Using YAPF within your favorite editor
+YAPF is supported by multiple editors via community extensions or plugins. See [Editor Support](EDITOR%20SUPPORT.md) for more info.
+
+## Required Python versions
+
+YAPF supports Python 3.7+.
+
+
+## Usage
+
+```console
+usage: yapf [-h] [-v] [-d | -i | -q] [-r | -l START-END] [-e PATTERN]
+            [--style STYLE] [--style-help] [--no-local-style] [-p] [-m] [-vv]
+            [files ...]
+
+Formatter for Python code.
+
+positional arguments:
+  files                 reads from stdin when no files are specified.
+
+optional arguments:
+  -h, --help            show this help message and exit
+  -v, --version         show program's version number and exit
+  -d, --diff            print the diff for the fixed source
+  -i, --in-place        make changes to files in place
+  -q, --quiet           output nothing and set return value
+  -r, --recursive       run recursively over directories
+  -l START-END, --lines START-END
+                        range of lines to reformat, one-based
+  -e PATTERN, --exclude PATTERN
+                        patterns for files to exclude from formatting
+  --style STYLE         specify formatting style: either a style name (for
+                        example "pep8" or "google"), or the name of a file
+                        with style settings. The default is pep8 unless a
+                        .style.yapf or setup.cfg or pyproject.toml file
+                        located in the same directory as the source or one of
+                        its parent directories (for stdin, the current
+                        directory is used).
+  --style-help          show style settings and exit; this output can be saved
+                        to .style.yapf to make your settings permanent
+  --no-local-style      don't search for local style definition
+  -p, --parallel        run YAPF in parallel when formatting multiple files.
+  -m, --print-modified  print out file names of modified files
+  -vv, --verbose        print out file names while processing
+```
+
+
+### Return Codes
+
+Normally YAPF returns zero on successful program termination and non-zero
+otherwise.
+
+If `--diff` is supplied, YAPF returns zero when no changes were necessary,
+non-zero otherwise (including program error). You can use this in a CI workflow
+to test that code has been YAPF-formatted.
+
+### Excluding files from formatting (.yapfignore or pyproject.toml)
+
+In addition to exclude patterns provided on commandline, YAPF looks for
+additional patterns specified in a file named `.yapfignore` or `pyproject.toml`
+located in the working directory from which YAPF is invoked.
+
+`.yapfignore`'s syntax is similar to UNIX's filename pattern matching:
+
+```
+*       matches everything
+?       matches any single character
+[seq]   matches any character in seq
+[!seq]  matches any character not in seq
+```
+
+Note that no entry should begin with `./`.
+
+If you use `pyproject.toml`, exclude patterns are specified by `ignore_patterns` key
+in `[tool.yapfignore]` section. For example:
+
+```ini
+[tool.yapfignore]
+ignore_patterns = [
+  "temp/**/*.py",
+  "temp2/*.py"
+]
+```
+
+
+Formatting style
+================
+
+The formatting style used by YAPF is configurable and there are many "knobs"
+that can be used to tune how YAPF does formatting. See the `style.py` module
+for the full list.
+
+To control the style, run YAPF with the `--style` argument. It accepts one of
+the predefined styles (e.g., `pep8` or `google`), a path to a configuration
+file that specifies the desired style, or a dictionary of key/value pairs.
+
+The config file is a simple listing of (case-insensitive) `key = value` pairs
+with a `[style]` heading. For example:
+
+```ini
+[style]
+based_on_style = pep8
+spaces_before_comment = 4
+split_before_logical_operator = true
+```
+
+The `based_on_style` setting determines which of the predefined styles this
+custom style is based on (think of it like subclassing). Four
+styles are predefined:
+
+- `pep8` (default)
+- `google` (based off of the [Google Python Style Guide](https://github.com/google/styleguide/blob/gh-pages/pyguide.md))
+- `yapf` (for use with Google open source projects)
+- `facebook`
+
+See `_STYLE_NAME_TO_FACTORY` in [`style.py`](https://github.com/google/yapf/blob/main/yapf/yapflib/style.py) for details.
+
+It's also possible to do the same on the command line with a dictionary. For
+example:
+
+```bash
+--style='{based_on_style: pep8, indent_width: 2}'
+```
+
+This will take the `pep8` base style and modify it to have two space
+indentations.
+
+YAPF will search for the formatting style in the following manner:
+
+1. Specified on the command line
+2. In the `[style]` section of a `.style.yapf` file in either the current
+   directory or one of its parent directories.
+3. In the `[yapf]` section of a `setup.cfg` file in either the current
+   directory or one of its parent directories.
+4. In the `[tool.yapf]` section of a `pyproject.toml` file in either the current
+   directory or one of its parent directories.
+5. In the `[style]` section of a `~/.config/yapf/style` file in your home
+   directory.
+
+If none of those files are found, the default style PEP8 is used.
+
+
+Example
+=======
+
+An example of the type of formatting that YAPF can do, it will take this ugly
+code:
+
+```python
+x = {  'a':37,'b':42,
+
+'c':927}
+
+y = 'hello ''world'
+z = 'hello '+'world'
+a = 'hello {}'.format('world')
+class foo  (     object  ):
+  def f    (self   ):
+    return       37*-+2
+  def g(self, x,y=42):
+      return y
+def f  (   a ) :
+  return      37+-+a[42-x :  y**3]
+```
+
+and reformat it into:
+
+```python
+x = {'a': 37, 'b': 42, 'c': 927}
+
+y = 'hello ' 'world'
+z = 'hello ' + 'world'
+a = 'hello {}'.format('world')
+
+
+class foo(object):
+    def f(self):
+        return 37 * -+2
+
+    def g(self, x, y=42):
+        return y
+
+
+def f(a):
+    return 37 + -+a[42 - x:y**3]
+```
+
+
+## Example as a module
+
+The two main APIs for calling YAPF are `FormatCode` and `FormatFile`, these
+share several arguments which are described below:
+
+```python
+>>> from yapf.yapflib.yapf_api import FormatCode  # reformat a string of code
+
+>>> formatted_code, changed = FormatCode("f ( a = 1, b = 2 )")
+>>> formatted_code
+'f(a=1, b=2)\n'
+>>> changed
+True
+```
+
+A `style_config` argument: Either a style name or a path to a file that
+contains formatting style settings. If None is specified, use the default style
+as set in `style.DEFAULT_STYLE_FACTORY`.
+
+```python
+>>> FormatCode("def g():\n  return True", style_config='pep8')[0]
+'def g():\n    return True\n'
+```
+
+A `lines` argument: A list of tuples of lines (ints), [start, end], that we
+want to format. The lines are 1-based indexed. It can be used by third-party
+code (e.g., IDEs) when reformatting a snippet of code rather than a whole file.
+
+```python
+>>> FormatCode("def g( ):\n    a=1\n    b = 2\n    return a==b", lines=[(1, 1), (2, 3)])[0]
+'def g():\n    a = 1\n    b = 2\n    return a==b\n'
+```
+
+A `print_diff` (bool): Instead of returning the reformatted source, return a
+diff that turns the formatted source into reformatted source.
+
+```diff
+>>> print(FormatCode("a==b", filename="foo.py", print_diff=True)[0])
+--- foo.py (original)
++++ foo.py (reformatted)
+@@ -1 +1 @@
+-a==b
++a == b
+```
+
+Note: the `filename` argument for `FormatCode` is what is inserted into the
+diff, the default is `<unknown>`.
+
+`FormatFile` returns reformatted code from the passed file along with its encoding:
+
+```python
+>>> from yapf.yapflib.yapf_api import FormatFile  # reformat a file
+
+>>> print(open("foo.py").read())  # contents of file
+a==b
+
+>>> reformatted_code, encoding, changed = FormatFile("foo.py")
+>>> formatted_code
+'a == b\n'
+>>> encoding
+'utf-8'
+>>> changed
+True
+```
+
+The `in_place` argument saves the reformatted code back to the file:
+
+```python
+>>> FormatFile("foo.py", in_place=True)[:2]
+(None, 'utf-8')
+
+>>> print(open("foo.py").read())  # contents of file (now fixed)
+a == b
+```
+
+
+## Formatting diffs
+
+Options:
+
+```console
+usage: yapf-diff [-h] [-i] [-p NUM] [--regex PATTERN] [--iregex PATTERN][-v]
+                 [--style STYLE] [--binary BINARY]
+
+This script reads input from a unified diff and reformats all the changed
+lines. This is useful to reformat all the lines touched by a specific patch.
+Example usage for git/svn users:
+
+  git diff -U0 --no-color --relative HEAD^ | yapf-diff -i
+  svn diff --diff-cmd=diff -x-U0 | yapf-diff -p0 -i
+
+It should be noted that the filename contained in the diff is used
+unmodified to determine the source file to update. Users calling this script
+directly should be careful to ensure that the path in the diff is correct
+relative to the current working directory.
+
+optional arguments:
+  -h, --help            show this help message and exit
+  -i, --in-place        apply edits to files instead of displaying a diff
+  -p NUM, --prefix NUM  strip the smallest prefix containing P slashes
+  --regex PATTERN       custom pattern selecting file paths to reformat
+                        (case sensitive, overrides -iregex)
+  --iregex PATTERN      custom pattern selecting file paths to reformat
+                        (case insensitive, overridden by -regex)
+  -v, --verbose         be more verbose, ineffective without -i
+  --style STYLE         specify formatting style: either a style name (for
+                        example "pep8" or "google"), or the name of a file
+                        with style settings. The default is pep8 unless a
+                        .style.yapf or setup.cfg or pyproject.toml file
+                        located in the same directory as the source or one of
+                        its parent directories (for stdin, the current
+                        directory is used).
+  --binary BINARY       location of binary to use for YAPF
+```
+
+## Python features not yet supported
+* Python 3.12 – [PEP 695 – Type Parameter Syntax](https://peps.python.org/pep-0695/) – [YAPF #1170](https://github.com/google/yapf/issues/1170)
+* Python 3.12 – [PEP 701 – Syntactic formalization of f-strings](https://peps.python.org/pep-0701/) – [YAPF #1136](https://github.com/google/yapf/issues/1136)
+
+## Knobs
+
+#### `ALIGN_CLOSING_BRACKET_WITH_VISUAL_INDENT`
+
+>    Align closing bracket with visual indentation.
+
+#### `ALLOW_MULTILINE_LAMBDAS`
+
+>    Allow lambdas to be formatted on more than one line.
+
+#### `ALLOW_MULTILINE_DICTIONARY_KEYS`
+
+>    Allow dictionary keys to exist on multiple lines. For example:
+
+```python
+    x = {
+        ('this is the first element of a tuple',
+         'this is the second element of a tuple'):
+             value,
+    }
+```
+
+#### `ALLOW_SPLIT_BEFORE_DEFAULT_OR_NAMED_ASSIGNS`
+
+>    Allow splitting before a default / named assignment in an argument list.
+
+#### `ALLOW_SPLIT_BEFORE_DICT_VALUE`
+
+>    Allow splits before the dictionary value.
+
+#### `ARITHMETIC_PRECEDENCE_INDICATION`
+
+>    Let spacing indicate operator precedence. For example:
+
+```python
+    a = 1 * 2 + 3 / 4
+    b = 1 / 2 - 3 * 4
+    c = (1 + 2) * (3 - 4)
+    d = (1 - 2) / (3 + 4)
+    e = 1 * 2 - 3
+    f = 1 + 2 + 3 + 4
+```
+
+>    will be formatted as follows to indicate precedence:
+
+```python
+    a = 1*2 + 3/4
+    b = 1/2 - 3*4
+    c = (1+2) * (3-4)
+    d = (1-2) / (3+4)
+    e = 1*2 - 3
+    f = 1 + 2 + 3 + 4
+```
+
+#### `BLANK_LINES_AROUND_TOP_LEVEL_DEFINITION`
+
+>    Sets the number of desired blank lines surrounding top-level function and
+>    class definitions. For example:
+
+```python
+    class Foo:
+        pass
+                       # <------ having two blank lines here
+                       # <------ is the default setting
+    class Bar:
+        pass
+```
+
+#### `BLANK_LINE_BEFORE_CLASS_DOCSTRING`
+
+>    Insert a blank line before a class-level docstring.
+
+#### `BLANK_LINE_BEFORE_MODULE_DOCSTRING`
+
+>    Insert a blank line before a module docstring.
+
+#### `BLANK_LINE_BEFORE_NESTED_CLASS_OR_DEF`
+
+>    Insert a blank line before a `def` or `class` immediately nested within
+>    another `def` or `class`. For example:
+
+```python
+    class Foo:
+                       # <------ this blank line
+        def method():
+            pass
+```
+
+#### `BLANK_LINES_BETWEEN_TOP_LEVEL_IMPORTS_AND_VARIABLES`
+
+>    Sets the number of desired blank lines between top-level imports and
+>    variable definitions. Useful for compatibility with tools like isort.
+
+#### `COALESCE_BRACKETS`
+
+>    Do not split consecutive brackets. Only relevant when
+>    `DEDENT_CLOSING_BRACKETS` or `INDENT_CLOSING_BRACKETS` is set. For example:
+
+```python
+    call_func_that_takes_a_dict(
+        {
+            'key1': 'value1',
+            'key2': 'value2',
+        }
+    )
+```
+
+>    would reformat to:
+
+```python
+    call_func_that_takes_a_dict({
+        'key1': 'value1',
+        'key2': 'value2',
+    })
+```
+
+#### `COLUMN_LIMIT`
+
+>    The column limit (or max line-length)
+
+#### `CONTINUATION_ALIGN_STYLE`
+
+>    The style for continuation alignment. Possible values are:
+
+>    - `SPACE`: Use spaces for continuation alignment. This is default
+>      behavior.
+>    - `FIXED`: Use fixed number (`CONTINUATION_INDENT_WIDTH`) of columns
+>      (i.e. `CONTINUATION_INDENT_WIDTH`/`INDENT_WIDTH` tabs or
+>      `CONTINUATION_INDENT_WIDTH` spaces) for continuation alignment.
+>    - `VALIGN-RIGHT`: Vertically align continuation lines to multiple of
+>      `INDENT_WIDTH` columns. Slightly right (one tab or a few spaces) if cannot
+>      vertically align continuation lines with indent characters.
+
+#### `CONTINUATION_INDENT_WIDTH`
+
+>    Indent width used for line continuations.
+
+#### `DEDENT_CLOSING_BRACKETS`
+
+>    Put closing brackets on a separate line, dedented, if the bracketed
+>    expression can't fit in a single line. Applies to all kinds of brackets,
+>    including function definitions and calls. For example:
+
+```python
+    config = {
+        'key1': 'value1',
+        'key2': 'value2',
+    }  # <--- this bracket is dedented and on a separate line
+
+    time_series = self.remote_client.query_entity_counters(
+        entity='dev3246.region1',
+        key='dns.query_latency_tcp',
+        transform=Transformation.AVERAGE(window=timedelta(seconds=60)),
+        start_ts=now()-timedelta(days=3),
+        end_ts=now(),
+    )  # <--- this bracket is dedented and on a separate line
+```
+
+#### `DISABLE_ENDING_COMMA_HEURISTIC`
+
+>    Disable the heuristic which places each list element on a separate line if
+>    the list is comma-terminated.
+>
+>    Note: The behavior of this flag changed in v0.40.3.  Before, if this flag
+>    was true, we would split lists that contained a trailing comma or a
+>    comment.  Now, we have a separate flag, `DISABLE_SPLIT_LIST_WITH_COMMENT`,
+>    that controls splitting when a list contains a comment.  To get the old
+>    behavior, set both flags to true.  More information in
+>    [CHANGELOG.md](CHANGELOG.md#new-disable_split_list_with_comment-flag).
+
+#### `DISABLE_SPLIT_LIST_WITH_COMMENT`
+
+>    Don't put every element on a new line within a list that contains
+>    interstitial comments.
+>
+>    Without this flag (default):
+>
+>    ```
+>    [
+>      a,
+>      b,  #
+>      c
+>    ]
+>    ```
+>
+>    With this flag:
+>
+>    ```
+>    [
+>      a, b,  #
+>      c
+>    ]
+>    ```
+>
+>    This mirrors the behavior of clang-format and is useful for forming
+>    "logical groups" of elements in a list.  It also works in function
+>    declarations.
+
+#### `EACH_DICT_ENTRY_ON_SEPARATE_LINE`
+
+>    Place each dictionary entry onto its own line.
+
+#### `FORCE_MULTILINE_DICT`
+
+>    Respect `EACH_DICT_ENTRY_ON_SEPARATE_LINE` even if the line is shorter than
+>    `COLUMN_LIMIT`.
+
+#### `I18N_COMMENT`
+
+>    The regex for an internationalization comment. The presence of this comment
+>    stops reformatting of that line, because the comments are required to be
+>    next to the string they translate.
+
+#### `I18N_FUNCTION_CALL`
+
+>    The internationalization function call names. The presence of this function
+>    stops reformatting on that line, because the string it has cannot be moved
+>    away from the i18n comment.
+
+#### `INDENT_BLANK_LINES`
+
+>    Set to `True` to prefer indented blank lines rather than empty
+
+#### `INDENT_CLOSING_BRACKETS`
+
+>    Put closing brackets on a separate line, indented, if the bracketed
+>    expression can't fit in a single line. Applies to all kinds of brackets,
+>    including function definitions and calls. For example:
+
+```python
+    config = {
+        'key1': 'value1',
+        'key2': 'value2',
+        }  # <--- this bracket is indented and on a separate line
+
+    time_series = self.remote_client.query_entity_counters(
+        entity='dev3246.region1',
+        key='dns.query_latency_tcp',
+        transform=Transformation.AVERAGE(window=timedelta(seconds=60)),
+        start_ts=now()-timedelta(days=3),
+        end_ts=now(),
+        )  # <--- this bracket is indented and on a separate line
+```
+
+#### `INDENT_DICTIONARY_VALUE`
+
+>    Indent the dictionary value if it cannot fit on the same line as the
+>    dictionary key. For example:
+
+```python
+    config = {
+        'key1':
+            'value1',
+        'key2': value1 +
+                value2,
+    }
+```
+
+#### `INDENT_WIDTH`
+
+>    The number of columns to use for indentation.
+
+#### `JOIN_MULTIPLE_LINES`
+
+>    Join short lines into one line. E.g., single line `if` statements.
+
+#### `NO_SPACES_AROUND_SELECTED_BINARY_OPERATORS`
+
+>    Do not include spaces around selected binary operators. For example:
+
+```python
+    1 + 2 * 3 - 4 / 5
+```
+
+>    will be formatted as follows when configured with `*`, `/`:
+
+```python
+    1 + 2*3 - 4/5
+```
+
+#### `SPACE_BETWEEN_ENDING_COMMA_AND_CLOSING_BRACKET`
+
+>    Insert a space between the ending comma and closing bracket of a list, etc.
+
+#### `SPACE_INSIDE_BRACKETS`
+
+    Use spaces inside brackets, braces, and parentheses.  For example:
+
+```python
+        method_call( 1 )
+        my_dict[ 3 ][ 1 ][ get_index( *args, **kwargs ) ]
+        my_set = { 1, 2, 3 }
+```
+
+#### `SPACES_AROUND_DEFAULT_OR_NAMED_ASSIGN`
+
+>    Set to `True` to prefer spaces around the assignment operator for default
+>    or keyword arguments.
+
+#### `SPACES_AROUND_DICT_DELIMITERS`
+
+>    Adds a space after the opening '{' and before the ending '}' dict delimiters.
+
+```python
+        {1: 2}
+```
+
+>    will be formatted as:
+
+```python
+        { 1: 2 }
+```
+
+#### `SPACES_AROUND_LIST_DELIMITERS`
+
+>    Adds a space after the opening '[' and before the ending ']' list delimiters.
+
+```python
+    [1, 2]
+```
+
+>    will be formatted as:
+
+```python
+    [ 1, 2 ]
+```
+
+#### `SPACES_AROUND_POWER_OPERATOR`
+
+>    Set to `True` to prefer using spaces around `**`.
+
+#### `SPACES_AROUND_SUBSCRIPT_COLON`
+
+>    Use spaces around the subscript / slice operator.  For example:
+
+```python
+    my_list[1 : 10 : 2]
+```
+
+##### `SPACES_AROUND_TUPLE_DELIMITERS`
+
+>    Adds a space after the opening '(' and before the ending ')' tuple delimiters.
+
+```python
+    (1, 2, 3)
+```
+
+>    will be formatted as:
+
+```python
+    ( 1, 2, 3 )
+```
+
+#### `SPACES_BEFORE_COMMENT`
+
+>    The number of spaces required before a trailing comment.
+>    This can be a single value (representing the number of spaces
+>    before each trailing comment) or list of values (representing
+>    alignment column values; trailing comments within a block will
+>    be aligned to the first column value that is greater than the maximum
+>    line length within the block).
+
+> **Note:** Lists of values may need to be quoted in some contexts
+> (eg. shells or editor config files).
+
+>    For example, with `spaces_before_comment=5`:
+
+```python
+    1 + 1 # Adding values
+```
+
+>    will be formatted as:
+
+```python
+    1 + 1     # Adding values <-- 5 spaces between the end of the statement and comment
+```
+
+>    with `spaces_before_comment="15, 20"`:
+
+```python
+    1 + 1 # Adding values
+    two + two # More adding
+
+    longer_statement # This is a longer statement
+    short # This is a shorter statement
+
+    a_very_long_statement_that_extends_beyond_the_final_column # Comment
+    short # This is a shorter statement
+```
+
+>    will be formatted as:
+
+```python
+    1 + 1          # Adding values <-- end of line comments in block aligned to col 15
+    two + two      # More adding
+
+    longer_statement    # This is a longer statement <-- end of line comments in block aligned to col 20
+    short               # This is a shorter statement
+
+    a_very_long_statement_that_extends_beyond_the_final_column  # Comment <-- the end of line comments are aligned based on the line length
+    short                                                       # This is a shorter statement
+```
+
+#### `SPLIT_ALL_COMMA_SEPARATED_VALUES`
+
+>    If a comma separated list (`dict`, `list`, `tuple`, or function `def`) is
+>    on a line that is too long, split such that each element is on a separate
+>    line.
+
+#### `SPLIT_ALL_TOP_LEVEL_COMMA_SEPARATED_VALUES`
+
+>    Variation on `SPLIT_ALL_COMMA_SEPARATED_VALUES` in which, if a
+>    subexpression with a comma fits in its starting line, then the
+>    subexpression is not split. This avoids splits like the one for
+>    `b` in this code:
+
+```python
+    abcdef(
+        aReallyLongThing: int,
+        b: [Int,
+            Int])
+```
+
+>    with the new knob this is split as:
+
+```python
+    abcdef(
+        aReallyLongThing: int,
+        b: [Int, Int])
+```
+
+#### `SPLIT_ARGUMENTS_WHEN_COMMA_TERMINATED`
+
+>    Split before arguments if the argument list is terminated by a comma.
+
+#### `SPLIT_BEFORE_ARITHMETIC_OPERATOR`
+
+>    Set to `True` to prefer splitting before `+`, `-`, `*`, `/`, `//`, or `@`
+>    rather than after.
+
+#### `SPLIT_BEFORE_BITWISE_OPERATOR`
+
+>    Set to `True` to prefer splitting before `&`, `|` or `^` rather than after.
+
+#### `SPLIT_BEFORE_CLOSING_BRACKET`
+
+>    Split before the closing bracket if a `list` or `dict` literal doesn't fit
+>    on a single line.
+
+#### `SPLIT_BEFORE_DICT_SET_GENERATOR`
+
+>    Split before a dictionary or set generator (`comp_for`). For example, note
+>    the split before the `for`:
+
+```python
+    foo = {
+        variable: 'Hello world, have a nice day!'
+        for variable in bar if variable != 42
+    }
+```
+
+#### `SPLIT_BEFORE_DOT`
+
+>    Split before the `.` if we need to split a longer expression:
+
+```python
+    foo = ('This is a really long string: {}, {}, {}, {}'.format(a, b, c, d))
+```
+
+>    would reformat to something like:
+
+```python
+    foo = ('This is a really long string: {}, {}, {}, {}'
+           .format(a, b, c, d))
+```
+
+#### `SPLIT_BEFORE_EXPRESSION_AFTER_OPENING_PAREN`
+
+>    Split after the opening paren which surrounds an expression if it doesn't
+>    fit on a single line.
+
+#### `SPLIT_BEFORE_FIRST_ARGUMENT`
+
+>    If an argument / parameter list is going to be split, then split before the
+>    first argument.
+
+#### `SPLIT_BEFORE_LOGICAL_OPERATOR`
+
+>    Set to `True` to prefer splitting before `and` or `or` rather than after.
+
+#### `SPLIT_BEFORE_NAMED_ASSIGNS`
+
+>    Split named assignments onto individual lines.
+
+#### `SPLIT_COMPLEX_COMPREHENSION`
+
+>    For list comprehensions and generator expressions with multiple clauses
+>    (e.g multiple `for` calls, `if` filter expressions) and which need to be
+>    reflowed, split each clause onto its own line. For example:
+
+```python
+    result = [
+        a_var + b_var for a_var in xrange(1000) for b_var in xrange(1000)
+        if a_var % b_var]
+```
+
+>    would reformat to something like:
+
+```python
+    result = [
+        a_var + b_var
+        for a_var in xrange(1000)
+        for b_var in xrange(1000)
+        if a_var % b_var]
+```
+
+#### `SPLIT_PENALTY_AFTER_OPENING_BRACKET`
+
+>    The penalty for splitting right after the opening bracket.
+
+#### `SPLIT_PENALTY_AFTER_UNARY_OPERATOR`
+
+>    The penalty for splitting the line after a unary operator.
+
+#### `SPLIT_PENALTY_ARITHMETIC_OPERATOR`
+
+>    The penalty of splitting the line around the `+`, `-`, `*`, `/`, `//`, `%`,
+>    and `@` operators.
+
+#### `SPLIT_PENALTY_BEFORE_IF_EXPR`
+
+>    The penalty for splitting right before an `if` expression.
+
+#### `SPLIT_PENALTY_BITWISE_OPERATOR`
+
+>    The penalty of splitting the line around the `&`, `|`, and `^` operators.
+
+#### `SPLIT_PENALTY_COMPREHENSION`
+
+>    The penalty for splitting a list comprehension or generator expression.
+
+#### `SPLIT_PENALTY_EXCESS_CHARACTER`
+
+>    The penalty for characters over the column limit.
+
+#### `SPLIT_PENALTY_FOR_ADDED_LINE_SPLIT`
+
+>    The penalty incurred by adding a line split to the logical line. The more
+>    line splits added the higher the penalty.
+
+#### `SPLIT_PENALTY_IMPORT_NAMES`
+
+>    The penalty of splitting a list of `import as` names. For example:
+
+```python
+    from a_very_long_or_indented_module_name_yada_yad import (long_argument_1,
+                                                              long_argument_2,
+                                                              long_argument_3)
+```
+
+>    would reformat to something like:
+
+```python
+    from a_very_long_or_indented_module_name_yada_yad import (
+        long_argument_1, long_argument_2, long_argument_3)
+```
+
+#### `SPLIT_PENALTY_LOGICAL_OPERATOR`
+
+>    The penalty of splitting the line around the `and` and `or` operators.
+
+#### `USE_TABS`
+
+>    Use the Tab character for indentation.
+
+
+## (Potentially) Frequently Asked Questions
+
+### Why does YAPF destroy my awesome formatting?
+
+YAPF tries very hard to get the formatting correct. But for some code, it won't
+be as good as hand-formatting. In particular, large data literals may become
+horribly disfigured under YAPF.
+
+The reasons for this are manyfold. In short, YAPF is simply a tool to help
+with development. It will format things to coincide with the style guide, but
+that may not equate with readability.
+
+What can be done to alleviate this situation is to indicate regions YAPF should
+ignore when reformatting something:
+
+```python
+# yapf: disable
+FOO = {
+    # ... some very large, complex data literal.
+}
+
+BAR = [
+    # ... another large data literal.
+]
+# yapf: enable
+```
+
+You can also disable formatting for a single literal like this:
+
+```python
+BAZ = {
+    (1, 2, 3, 4),
+    (5, 6, 7, 8),
+    (9, 10, 11, 12),
+}  # yapf: disable
+```
+
+To preserve the nice dedented closing brackets, use the
+`dedent_closing_brackets` in your style. Note that in this case all
+brackets, including function definitions and calls, are going to use
+that style.  This provides consistency across the formatted codebase.
+
+### Why Not Improve Existing Tools?
+
+We wanted to use clang-format's reformatting algorithm. It's very powerful and
+designed to come up with the best formatting possible. Existing tools were
+created with different goals in mind, and would require extensive modifications
+to convert to using clang-format's algorithm.
+
+### Can I Use YAPF In My Program?
+
+Please do! YAPF was designed to be used as a library as well as a command line
+tool. This means that a tool or IDE plugin is free to use YAPF.
+
+### I still get non-PEP8 compliant code! Why?
+
+YAPF tries very hard to be fully PEP 8 compliant. However, it is paramount
+to not risk altering the semantics of your code. Thus, YAPF tries to be as
+safe as possible and does not change the token stream
+(e.g., by adding parentheses).
+All these cases however, can be easily fixed manually. For instance,
+
+```python
+from my_package import my_function_1, my_function_2, my_function_3, my_function_4, my_function_5
+
+FOO = my_variable_1 + my_variable_2 + my_variable_3 + my_variable_4 + my_variable_5 + my_variable_6 + my_variable_7 + my_variable_8
+```
+
+won't be split, but you can easily get it right by just adding parentheses:
+
+```python
+from my_package import (my_function_1, my_function_2, my_function_3,
+                        my_function_4, my_function_5)
+
+FOO = (my_variable_1 + my_variable_2 + my_variable_3 + my_variable_4 +
+       my_variable_5 + my_variable_6 + my_variable_7 + my_variable_8)
+```
+
+
+## Gory Details
+
+### Algorithm Design
+
+The main data structure in YAPF is the `LogicalLine` object. It holds a list
+of `FormatToken`\s, that we would want to place on a single line if there
+were no column limit. An exception being a comment in the middle of an
+expression statement will force the line to be formatted on more than one line.
+The formatter works on one `LogicalLine` object at a time.
+
+An `LogicalLine` typically won't affect the formatting of lines before or
+after it. There is a part of the algorithm that may join two or more
+`LogicalLine`\s into one line. For instance, an if-then statement with a
+short body can be placed on a single line:
+
+```python
+if a == 42: continue
+```
+
+YAPF's formatting algorithm creates a weighted tree that acts as the solution
+space for the algorithm. Each node in the tree represents the result of a
+formatting decision --- i.e., whether to split or not to split before a token.
+Each formatting decision has a cost associated with it. Therefore, the cost is
+realized on the edge between two nodes. (In reality, the weighted tree doesn't
+have separate edge objects, so the cost resides on the nodes themselves.)
+
+For example, take the following Python code snippet. For the sake of this
+example, assume that line (1) violates the column limit restriction and needs to
+be reformatted.
+
+```python
+def xxxxxxxxxxx(aaaaaaaaaaaa, bbbbbbbbb, cccccccc, dddddddd, eeeeee):  # 1
+    pass                                                               # 2
+```
+
+For line (1), the algorithm will build a tree where each node (a
+`FormattingDecisionState` object) is the state of the line at that token given
+the decision to split before the token or not. Note: the `FormatDecisionState`
+objects are copied by value so each node in the graph is unique and a change in
+one doesn't affect other nodes.
+
+Heuristics are used to determine the costs of splitting or not splitting.
+Because a node holds the state of the tree up to a token's insertion, it can
+easily determine if a splitting decision will violate one of the style
+requirements. For instance, the heuristic is able to apply an extra penalty to
+the edge when not splitting between the previous token and the one being added.
+
+There are some instances where we will never want to split the line, because
+doing so will always be detrimental (i.e., it will require a backslash-newline,
+which is very rarely desirable). For line (1), we will never want to split the
+first three tokens: `def`, `xxxxxxxxxxx`, and `(`. Nor will we want to
+split between the `)` and the `:` at the end. These regions are said to be
+"unbreakable." This is reflected in the tree by there not being a "split"
+decision (left hand branch) within the unbreakable region.
+
+Now that we have the tree, we determine what the "best" formatting is by finding
+the path through the tree with the lowest cost.
+
+And that's it!
diff --git a/README.rst b/README.rst
deleted file mode 100644
index 12286a9..0000000
--- a/README.rst
+++ /dev/null
@@ -1,1019 +0,0 @@
-====
-YAPF
-====
-
-.. image:: https://badge.fury.io/py/yapf.svg
-    :target: https://badge.fury.io/py/yapf
-    :alt: PyPI version
-
-.. image:: https://github.com/google/yapf/actions/workflows/ci.yml/badge.svg
-    :target: https://github.com/google/yapf/actions
-    :alt: Build status
-
-.. image:: https://coveralls.io/repos/google/yapf/badge.svg?branch=main
-    :target: https://coveralls.io/r/google/yapf?branch=main
-    :alt: Coverage status
-
-
-Introduction
-============
-
-Most of the current formatters for Python --- e.g., autopep8, and pep8ify ---
-are made to remove lint errors from code. This has some obvious limitations.
-For instance, code that conforms to the PEP 8 guidelines may not be
-reformatted.  But it doesn't mean that the code looks good.
-
-YAPF takes a different approach. It's based off of `'clang-format' <https://cl
-ang.llvm.org/docs/ClangFormat.html>`_, developed by Daniel Jasper. In essence,
-the algorithm takes the code and reformats it to the best formatting that
-conforms to the style guide, even if the original code didn't violate the
-style guide. The idea is also similar to the `'gofmt' <https://golang.org/cmd/
-gofmt/>`_ tool for the Go programming language: end all holy wars about
-formatting - if the whole codebase of a project is simply piped through YAPF
-whenever modifications are made, the style remains consistent throughout the
-project and there's no point arguing about style in every code review.
-
-The ultimate goal is that the code YAPF produces is as good as the code that a
-programmer would write if they were following the style guide. It takes away
-some of the drudgery of maintaining your code.
-
-.. footer::
-
-    YAPF is not an official Google product (experimental or otherwise), it is
-    just code that happens to be owned by Google.
-
-.. contents::
-
-
-Installation
-============
-
-To install YAPF from PyPI:
-
-.. code-block:: shell
-
-    $ pip install yapf
-
-(optional) If you are using Python 2.7 and want to enable multiprocessing:
-
-.. code-block:: shell
-
-    $ pip install futures
-
-YAPF is still considered in "alpha" stage, and the released version may change
-often; therefore, the best way to keep up-to-date with the latest development
-is to clone this repository.
-
-Note that if you intend to use YAPF as a command-line tool rather than as a
-library, installation is not necessary. YAPF supports being run as a directory
-by the Python interpreter. If you cloned/unzipped YAPF into ``DIR``, it's
-possible to run:
-
-.. code-block:: shell
-
-    $ PYTHONPATH=DIR python DIR/yapf [options] ...
-
-
-Python versions
-===============
-
-YAPF supports Python 2.7 and 3.6.4+. (Note that some Python 3 features may fail
-to parse with Python versions before 3.6.4.)
-
-YAPF requires the code it formats to be valid Python for the version YAPF itself
-runs under. Therefore, if you format Python 3 code with YAPF, run YAPF itself
-under Python 3 (and similarly for Python 2).
-
-
-Usage
-=====
-
-Options::
-
-    usage: yapf [-h] [-v] [-d | -i] [-r | -l START-END] [-e PATTERN]
-                [--style STYLE] [--style-help] [--no-local-style] [-p]
-                [-vv]
-                [files [files ...]]
-
-    Formatter for Python code.
-
-    positional arguments:
-      files
-
-    optional arguments:
-      -h, --help            show this help message and exit
-      -v, --version         show version number and exit
-      -d, --diff            print the diff for the fixed source
-      -i, --in-place        make changes to files in place
-      -r, --recursive       run recursively over directories
-      -l START-END, --lines START-END
-                            range of lines to reformat, one-based
-      -e PATTERN, --exclude PATTERN
-                            patterns for files to exclude from formatting
-      --style STYLE         specify formatting style: either a style name (for
-                            example "pep8" or "google"), or the name of a file
-                            with style settings. The default is pep8 unless a
-                            .style.yapf or setup.cfg or pyproject.toml file
-                            located in the same directory as the source or one of
-                            its parent directories (for stdin, the current
-                            directory is used).
-      --style-help          show style settings and exit; this output can be saved
-                            to .style.yapf to make your settings permanent
-      --no-local-style      don't search for local style definition
-      -p, --parallel        Run yapf in parallel when formatting multiple files.
-                            Requires concurrent.futures in Python 2.X
-      -vv, --verbose        Print out file names while processing
-
-
-------------
-Return Codes
-------------
-
-Normally YAPF returns zero on successful program termination and non-zero otherwise.
-
-If ``--diff`` is supplied, YAPF returns zero when no changes were necessary, non-zero
-otherwise (including program error). You can use this in a CI workflow to test that code
-has been YAPF-formatted.
-
----------------------------------------------
-Excluding files from formatting (.yapfignore or pyproject.toml)
----------------------------------------------
-
-In addition to exclude patterns provided on commandline, YAPF looks for additional
-patterns specified in a file named ``.yapfignore`` or ``pyproject.toml`` located in the
-working directory from which YAPF is invoked.
-
-``.yapfignore``'s syntax is similar to UNIX's filename pattern matching::
-
-    *       matches everything
-    ?       matches any single character
-    [seq]   matches any character in seq
-    [!seq]  matches any character not in seq
-
-Note that no entry should begin with `./`.
-
-If you use ``pyproject.toml``, exclude patterns are specified by ``ignore_pattens`` key
-in ``[tool.yapfignore]`` section. For example:
-
-.. code-block:: ini
-
-   [tool.yapfignore]
-   ignore_patterns = [
-     "temp/**/*.py",
-     "temp2/*.py"
-   ]
-
-Formatting style
-================
-
-The formatting style used by YAPF is configurable and there are many "knobs"
-that can be used to tune how YAPF does formatting. See the ``style.py`` module
-for the full list.
-
-To control the style, run YAPF with the ``--style`` argument. It accepts one of
-the predefined styles (e.g., ``pep8`` or ``google``), a path to a configuration
-file that specifies the desired style, or a dictionary of key/value pairs.
-
-The config file is a simple listing of (case-insensitive) ``key = value`` pairs
-with a ``[style]`` heading. For example:
-
-.. code-block:: ini
-
-    [style]
-    based_on_style = pep8
-    spaces_before_comment = 4
-    split_before_logical_operator = true
-
-The ``based_on_style`` setting determines which of the predefined styles this
-custom style is based on (think of it like subclassing). Four
-styles are predefined:
-
-- ``pep8`` (default)
-- ``google`` (based off of the `Google Python Style Guide`_)
-- ``yapf`` (for use with Google open source projects)
-- ``facebook``
-
-.. _`Google Python Style Guide`: https://github.com/google/styleguide/blob/gh-pages/pyguide.md
-
-See ``_STYLE_NAME_TO_FACTORY`` in style.py_ for details.
-
-.. _style.py: https://github.com/google/yapf/blob/main/yapf/yapflib/style.py
-
-It's also possible to do the same on the command line with a dictionary. For
-example:
-
-.. code-block:: shell
-
-    --style='{based_on_style: pep8, indent_width: 2}'
-
-This will take the ``pep8`` base style and modify it to have two space
-indentations.
-
-YAPF will search for the formatting style in the following manner:
-
-1. Specified on the command line
-2. In the ``[style]`` section of a ``.style.yapf`` file in either the current
-   directory or one of its parent directories.
-3. In the ``[yapf]`` section of a ``setup.cfg`` file in either the current
-   directory or one of its parent directories.
-4. In the ``[tool.yapf]`` section of a ``pyproject.toml`` file in either the current
-   directory or one of its parent directories.
-5. In the ``[style]`` section of a ``~/.config/yapf/style`` file in your home
-   directory.
-
-If none of those files are found, the default style is used (PEP8).
-
-
-Example
-=======
-
-An example of the type of formatting that YAPF can do, it will take this ugly
-code:
-
-.. code-block:: python
-
-    x = {  'a':37,'b':42,
-
-    'c':927}
-
-    y = 'hello ''world'
-    z = 'hello '+'world'
-    a = 'hello {}'.format('world')
-    class foo  (     object  ):
-      def f    (self   ):
-        return       37*-+2
-      def g(self, x,y=42):
-          return y
-    def f  (   a ) :
-      return      37+-+a[42-x :  y**3]
-
-and reformat it into:
-
-.. code-block:: python
-
-    x = {'a': 37, 'b': 42, 'c': 927}
-
-    y = 'hello ' 'world'
-    z = 'hello ' + 'world'
-    a = 'hello {}'.format('world')
-
-
-    class foo(object):
-        def f(self):
-            return 37 * -+2
-
-        def g(self, x, y=42):
-            return y
-
-
-    def f(a):
-        return 37 + -+a[42 - x:y**3]
-
-
-Example as a module
-===================
-
-The two main APIs for calling yapf are ``FormatCode`` and ``FormatFile``, these
-share several arguments which are described below:
-
-.. code-block:: python
-
-    >>> from yapf.yapflib.yapf_api import FormatCode  # reformat a string of code
-
-    >>> formatted_code, changed = FormatCode("f ( a = 1, b = 2 )")
-    >>> formatted_code
-    'f(a=1, b=2)\n'
-    >>> changed
-    True
-
-A ``style_config`` argument: Either a style name or a path to a file that contains
-formatting style settings. If None is specified, use the default style
-as set in ``style.DEFAULT_STYLE_FACTORY``.
-
-.. code-block:: python
-
-    >>> FormatCode("def g():\n  return True", style_config='pep8')[0]
-    'def g():\n    return True\n'
-
-A ``lines`` argument: A list of tuples of lines (ints), [start, end],
-that we want to format. The lines are 1-based indexed. It can be used by
-third-party code (e.g., IDEs) when reformatting a snippet of code rather
-than a whole file.
-
-.. code-block:: python
-
-    >>> FormatCode("def g( ):\n    a=1\n    b = 2\n    return a==b", lines=[(1, 1), (2, 3)])[0]
-    'def g():\n    a = 1\n    b = 2\n    return a==b\n'
-
-A ``print_diff`` (bool): Instead of returning the reformatted source, return a
-diff that turns the formatted source into reformatted source.
-
-.. code-block:: python
-
-    >>> print(FormatCode("a==b", filename="foo.py", print_diff=True)[0])
-    --- foo.py (original)
-    +++ foo.py (reformatted)
-    @@ -1 +1 @@
-    -a==b
-    +a == b
-
-Note: the ``filename`` argument for ``FormatCode`` is what is inserted into
-the diff, the default is ``<unknown>``.
-
-``FormatFile`` returns reformatted code from the passed file along with its encoding:
-
-.. code-block:: python
-
-    >>> from yapf.yapflib.yapf_api import FormatFile  # reformat a file
-
-    >>> print(open("foo.py").read())  # contents of file
-    a==b
-
-    >>> reformatted_code, encoding, changed = FormatFile("foo.py")
-    >>> formatted_code
-    'a == b\n'
-    >>> encoding
-    'utf-8'
-    >>> changed
-    True
-
-The ``in_place`` argument saves the reformatted code back to the file:
-
-.. code-block:: python
-
-    >>> FormatFile("foo.py", in_place=True)[:2]
-    (None, 'utf-8')
-
-    >>> print(open("foo.py").read())  # contents of file (now fixed)
-    a == b
-
-Formatting diffs
-================
-
-Options::
-
-    usage: yapf-diff [-h] [-i] [-p NUM] [--regex PATTERN] [--iregex PATTERN][-v]
-                     [--style STYLE] [--binary BINARY]
-
-    This script reads input from a unified diff and reformats all the changed
-    lines. This is useful to reformat all the lines touched by a specific patch.
-    Example usage for git/svn users:
-
-      git diff -U0 --no-color --relative HEAD^ | yapf-diff -i
-      svn diff --diff-cmd=diff -x-U0 | yapf-diff -p0 -i
-
-    It should be noted that the filename contained in the diff is used
-    unmodified to determine the source file to update. Users calling this script
-    directly should be careful to ensure that the path in the diff is correct
-    relative to the current working directory.
-
-    optional arguments:
-      -h, --help            show this help message and exit
-      -i, --in-place        apply edits to files instead of displaying a diff
-      -p NUM, --prefix NUM  strip the smallest prefix containing P slashes
-      --regex PATTERN       custom pattern selecting file paths to reformat
-                            (case sensitive, overrides -iregex)
-      --iregex PATTERN      custom pattern selecting file paths to reformat
-                            (case insensitive, overridden by -regex)
-      -v, --verbose         be more verbose, ineffective without -i
-      --style STYLE         specify formatting style: either a style name (for
-                            example "pep8" or "google"), or the name of a file
-                            with style settings. The default is pep8 unless a
-                            .style.yapf or setup.cfg or pyproject.toml file
-                            located in the same directory as the source or one of
-                            its parent directories (for stdin, the current
-                            directory is used).
-      --binary BINARY       location of binary to use for yapf
-
-Knobs
-=====
-
-``ALIGN_CLOSING_BRACKET_WITH_VISUAL_INDENT``
-    Align closing bracket with visual indentation.
-
-``ALLOW_MULTILINE_LAMBDAS``
-    Allow lambdas to be formatted on more than one line.
-
-``ALLOW_MULTILINE_DICTIONARY_KEYS``
-    Allow dictionary keys to exist on multiple lines. For example:
-
-    .. code-block:: python
-
-        x = {
-            ('this is the first element of a tuple',
-             'this is the second element of a tuple'):
-                 value,
-        }
-
-``ALLOW_SPLIT_BEFORE_DEFAULT_OR_NAMED_ASSIGNS``
-    Allow splitting before a default / named assignment in an argument list.
-
-``ALLOW_SPLIT_BEFORE_DICT_VALUE``
-    Allow splits before the dictionary value.
-
-``ARITHMETIC_PRECEDENCE_INDICATION``
-    Let spacing indicate operator precedence. For example:
-
-    .. code-block:: python
-
-        a = 1 * 2 + 3 / 4
-        b = 1 / 2 - 3 * 4
-        c = (1 + 2) * (3 - 4)
-        d = (1 - 2) / (3 + 4)
-        e = 1 * 2 - 3
-        f = 1 + 2 + 3 + 4
-
-    will be formatted as follows to indicate precedence:
-
-    .. code-block:: python
-
-        a = 1*2 + 3/4
-        b = 1/2 - 3*4
-        c = (1+2) * (3-4)
-        d = (1-2) / (3+4)
-        e = 1*2 - 3
-        f = 1 + 2 + 3 + 4
-
-``BLANK_LINE_BEFORE_NESTED_CLASS_OR_DEF``
-    Insert a blank line before a ``def`` or ``class`` immediately nested within
-    another ``def`` or ``class``. For example:
-
-    .. code-block:: python
-
-        class Foo:
-                           # <------ this blank line
-            def method():
-                pass
-
-``BLANK_LINE_BEFORE_MODULE_DOCSTRING``
-    Insert a blank line before a module docstring.
-
-``BLANK_LINE_BEFORE_CLASS_DOCSTRING``
-    Insert a blank line before a class-level docstring.
-
-``BLANK_LINES_AROUND_TOP_LEVEL_DEFINITION``
-    Sets the number of desired blank lines surrounding top-level function and
-    class definitions. For example:
-
-    .. code-block:: python
-
-        class Foo:
-            pass
-                           # <------ having two blank lines here
-                           # <------ is the default setting
-        class Bar:
-            pass
-
-``BLANK_LINES_BETWEEN_TOP_LEVEL_IMPORTS_AND_VARIABLES``
-    Sets the number of desired blank lines between top-level imports and
-    variable definitions. Useful for compatibility with tools like isort.
-
-``COALESCE_BRACKETS``
-    Do not split consecutive brackets. Only relevant when
-    ``DEDENT_CLOSING_BRACKETS`` or ``INDENT_CLOSING_BRACKETS``
-    is set. For example:
-
-    .. code-block:: python
-
-        call_func_that_takes_a_dict(
-            {
-                'key1': 'value1',
-                'key2': 'value2',
-            }
-        )
-
-    would reformat to:
-
-    .. code-block:: python
-
-        call_func_that_takes_a_dict({
-            'key1': 'value1',
-            'key2': 'value2',
-        })
-
-
-``COLUMN_LIMIT``
-    The column limit (or max line-length)
-
-``CONTINUATION_ALIGN_STYLE``
-    The style for continuation alignment. Possible values are:
-
-    - ``SPACE``: Use spaces for continuation alignment. This is default
-      behavior.
-    - ``FIXED``: Use fixed number (CONTINUATION_INDENT_WIDTH) of columns
-      (ie: CONTINUATION_INDENT_WIDTH/INDENT_WIDTH tabs or CONTINUATION_INDENT_WIDTH
-      spaces) for continuation alignment.
-    - ``VALIGN-RIGHT``: Vertically align continuation lines to multiple of
-      INDENT_WIDTH columns. Slightly right (one tab or a few spaces) if cannot
-      vertically align continuation lines with indent characters.
-
-``CONTINUATION_INDENT_WIDTH``
-    Indent width used for line continuations.
-
-``DEDENT_CLOSING_BRACKETS``
-    Put closing brackets on a separate line, dedented, if the bracketed
-    expression can't fit in a single line. Applies to all kinds of brackets,
-    including function definitions and calls. For example:
-
-    .. code-block:: python
-
-        config = {
-            'key1': 'value1',
-            'key2': 'value2',
-        }  # <--- this bracket is dedented and on a separate line
-
-        time_series = self.remote_client.query_entity_counters(
-            entity='dev3246.region1',
-            key='dns.query_latency_tcp',
-            transform=Transformation.AVERAGE(window=timedelta(seconds=60)),
-            start_ts=now()-timedelta(days=3),
-            end_ts=now(),
-        )  # <--- this bracket is dedented and on a separate line
-
-``DISABLE_ENDING_COMMA_HEURISTIC``
-    Disable the heuristic which places each list element on a separate line if
-    the list is comma-terminated.
-
-``EACH_DICT_ENTRY_ON_SEPARATE_LINE``
-    Place each dictionary entry onto its own line.
-
-``FORCE_MULTILINE_DICT``
-    Respect EACH_DICT_ENTRY_ON_SEPARATE_LINE even if the line is shorter than
-    COLUMN_LIMIT.
-
-``I18N_COMMENT``
-    The regex for an internationalization comment. The presence of this comment
-    stops reformatting of that line, because the comments are required to be
-    next to the string they translate.
-
-``I18N_FUNCTION_CALL``
-    The internationalization function call names. The presence of this function
-    stops reformatting on that line, because the string it has cannot be moved
-    away from the i18n comment.
-
-``INDENT_DICTIONARY_VALUE``
-    Indent the dictionary value if it cannot fit on the same line as the
-    dictionary key. For example:
-
-    .. code-block:: python
-
-        config = {
-            'key1':
-                'value1',
-            'key2': value1 +
-                    value2,
-        }
-
-``INDENT_WIDTH``
-    The number of columns to use for indentation.
-
-``INDENT_BLANK_LINES``
-    Set to ``True`` to prefer indented blank lines rather than empty
-
-``INDENT_CLOSING_BRACKETS``
-    Put closing brackets on a separate line, indented, if the bracketed
-    expression can't fit in a single line. Applies to all kinds of brackets,
-    including function definitions and calls. For example:
-
-    .. code-block:: python
-
-        config = {
-            'key1': 'value1',
-            'key2': 'value2',
-            }  # <--- this bracket is indented and on a separate line
-
-        time_series = self.remote_client.query_entity_counters(
-            entity='dev3246.region1',
-            key='dns.query_latency_tcp',
-            transform=Transformation.AVERAGE(window=timedelta(seconds=60)),
-            start_ts=now()-timedelta(days=3),
-            end_ts=now(),
-            )  # <--- this bracket is indented and on a separate line
-
-``JOIN_MULTIPLE_LINES``
-    Join short lines into one line. E.g., single line ``if`` statements.
-
-``NO_SPACES_AROUND_SELECTED_BINARY_OPERATORS``
-    Do not include spaces around selected binary operators. For example:
-
-    .. code-block:: python
-
-        1 + 2 * 3 - 4 / 5
-
-    will be formatted as follows when configured with ``*``, ``/``:
-
-    .. code-block:: python
-
-        1 + 2*3 - 4/5
-
-``SPACES_AROUND_POWER_OPERATOR``
-    Set to ``True`` to prefer using spaces around ``**``.
-
-``SPACES_AROUND_DEFAULT_OR_NAMED_ASSIGN``
-    Set to ``True`` to prefer spaces around the assignment operator for default
-    or keyword arguments.
-
-``SPACES_AROUND_DICT_DELIMITERS``
-    Adds a space after the opening '{' and before the ending '}' dict delimiters.
-
-    .. code-block:: python
-
-        {1: 2}
-
-    will be formatted as:
-
-    .. code-block:: python
-
-        { 1: 2 }
-
-``SPACES_AROUND_LIST_DELIMITERS``
-    Adds a space after the opening '[' and before the ending ']' list delimiters.
-
-    .. code-block:: python
-
-        [1, 2]
-
-    will be formatted as:
-
-    .. code-block:: python
-
-        [ 1, 2 ]
-
-``SPACES_AROUND_SUBSCRIPT_COLON``
-    Use spaces around the subscript / slice operator.  For example:
-
-    .. code-block:: python
-
-        my_list[1 : 10 : 2]
-
-``SPACES_AROUND_TUPLE_DELIMITERS``
-    Adds a space after the opening '(' and before the ending ')' tuple delimiters.
-
-    .. code-block:: python
-
-        (1, 2, 3)
-
-    will be formatted as:
-
-    .. code-block:: python
-
-        ( 1, 2, 3 )
-
-``SPACES_BEFORE_COMMENT``
-    The number of spaces required before a trailing comment.
-    This can be a single value (representing the number of spaces
-    before each trailing comment) or list of of values (representing
-    alignment column values; trailing comments within a block will
-    be aligned to the first column value that is greater than the maximum
-    line length within the block). For example:
-
-    With ``spaces_before_comment=5``:
-
-    .. code-block:: python
-
-        1 + 1 # Adding values
-
-    will be formatted as:
-
-    .. code-block:: python
-
-        1 + 1     # Adding values <-- 5 spaces between the end of the statement and comment
-
-    With ``spaces_before_comment=15, 20``:
-
-    .. code-block:: python
-
-        1 + 1 # Adding values
-        two + two # More adding
-
-        longer_statement # This is a longer statement
-        short # This is a shorter statement
-
-        a_very_long_statement_that_extends_beyond_the_final_column # Comment
-        short # This is a shorter statement
-
-    will be formatted as:
-
-    .. code-block:: python
-
-        1 + 1          # Adding values <-- end of line comments in block aligned to col 15
-        two + two      # More adding
-
-        longer_statement    # This is a longer statement <-- end of line comments in block aligned to col 20
-        short               # This is a shorter statement
-
-        a_very_long_statement_that_extends_beyond_the_final_column  # Comment <-- the end of line comments are aligned based on the line length
-        short                                                       # This is a shorter statement
-
-``SPACE_BETWEEN_ENDING_COMMA_AND_CLOSING_BRACKET``
-    Insert a space between the ending comma and closing bracket of a list, etc.
-
-``SPACE_INSIDE_BRACKETS``
-    Use spaces inside brackets, braces, and parentheses.  For example:
-
-    .. code-block:: python
-
-        method_call( 1 )
-        my_dict[ 3 ][ 1 ][ get_index( *args, **kwargs ) ]
-        my_set = { 1, 2, 3 }
-
-``SPLIT_ARGUMENTS_WHEN_COMMA_TERMINATED``
-    Split before arguments if the argument list is terminated by a comma.
-
-``SPLIT_ALL_COMMA_SEPARATED_VALUES``
-    If a comma separated list (``dict``, ``list``, ``tuple``, or function
-    ``def``) is on a line that is too long, split such that each element
-    is on a separate line.
-
-``SPLIT_ALL_TOP_LEVEL_COMMA_SEPARATED_VALUES``
-    Variation on ``SPLIT_ALL_COMMA_SEPARATED_VALUES`` in which, if a
-    subexpression with a comma fits in its starting line, then the
-    subexpression is not split. This avoids splits like the one for
-    ``b`` in this code:
-
-    .. code-block:: python
-
-      abcdef(
-          aReallyLongThing: int,
-          b: [Int,
-              Int])
-
-    With the new knob this is split as:
-
-    .. code-block:: python
-
-      abcdef(
-          aReallyLongThing: int,
-          b: [Int, Int])
-
-``SPLIT_BEFORE_BITWISE_OPERATOR``
-    Set to ``True`` to prefer splitting before ``&``, ``|`` or ``^`` rather
-    than after.
-
-``SPLIT_BEFORE_ARITHMETIC_OPERATOR``
-    Set to ``True`` to prefer splitting before ``+``, ``-``, ``*``, ``/``, ``//``,
-    or ``@`` rather than after.
-
-``SPLIT_BEFORE_CLOSING_BRACKET``
-    Split before the closing bracket if a ``list`` or ``dict`` literal doesn't
-    fit on a single line.
-
-``SPLIT_BEFORE_DICT_SET_GENERATOR``
-    Split before a dictionary or set generator (comp_for). For example, note
-    the split before the ``for``:
-
-    .. code-block:: python
-
-        foo = {
-            variable: 'Hello world, have a nice day!'
-            for variable in bar if variable != 42
-        }
-
-``SPLIT_BEFORE_DOT``
-    Split before the ``.`` if we need to split a longer expression:
-
-    .. code-block:: python
-
-      foo = ('This is a really long string: {}, {}, {}, {}'.format(a, b, c, d))
-
-    would reformat to something like:
-
-    .. code-block:: python
-
-      foo = ('This is a really long string: {}, {}, {}, {}'
-             .format(a, b, c, d))
-
-``SPLIT_BEFORE_EXPRESSION_AFTER_OPENING_PAREN``
-    Split after the opening paren which surrounds an expression if it doesn't
-    fit on a single line.
-
-``SPLIT_BEFORE_FIRST_ARGUMENT``
-    If an argument / parameter list is going to be split, then split before the
-    first argument.
-
-``SPLIT_BEFORE_LOGICAL_OPERATOR``
-    Set to ``True`` to prefer splitting before ``and`` or ``or`` rather than
-    after.
-
-``SPLIT_BEFORE_NAMED_ASSIGNS``
-    Split named assignments onto individual lines.
-
-``SPLIT_COMPLEX_COMPREHENSION``
-    For list comprehensions and generator expressions with multiple clauses
-    (e.g multiple ``for`` calls, ``if`` filter expressions) and which need to
-    be reflowed, split each clause onto its own line. For example:
-
-    .. code-block:: python
-
-      result = [
-          a_var + b_var for a_var in xrange(1000) for b_var in xrange(1000)
-          if a_var % b_var]
-
-    would reformat to something like:
-
-    .. code-block:: python
-
-      result = [
-          a_var + b_var
-          for a_var in xrange(1000)
-          for b_var in xrange(1000)
-          if a_var % b_var]
-
-``SPLIT_PENALTY_AFTER_OPENING_BRACKET``
-    The penalty for splitting right after the opening bracket.
-
-``SPLIT_PENALTY_AFTER_UNARY_OPERATOR``
-    The penalty for splitting the line after a unary operator.
-
-``SPLIT_PENALTY_ARITHMETIC_OPERATOR``
-    The penalty of splitting the line around the ``+``, ``-``, ``*``, ``/``,
-    ``//``, ``%``, and ``@`` operators.
-
-``SPLIT_PENALTY_BEFORE_IF_EXPR``
-    The penalty for splitting right before an ``if`` expression.
-
-``SPLIT_PENALTY_BITWISE_OPERATOR``
-    The penalty of splitting the line around the ``&``, ``|``, and ``^``
-    operators.
-
-``SPLIT_PENALTY_COMPREHENSION``
-    The penalty for splitting a list comprehension or generator expression.
-
-``SPLIT_PENALTY_EXCESS_CHARACTER``
-    The penalty for characters over the column limit.
-
-``SPLIT_PENALTY_FOR_ADDED_LINE_SPLIT``
-    The penalty incurred by adding a line split to the logical line. The more
-    line splits added the higher the penalty.
-
-``SPLIT_PENALTY_IMPORT_NAMES``
-    The penalty of splitting a list of ``import as`` names. For example:
-
-    .. code-block:: python
-
-      from a_very_long_or_indented_module_name_yada_yad import (long_argument_1,
-                                                                long_argument_2,
-                                                                long_argument_3)
-
-    would reformat to something like:
-
-    .. code-block:: python
-
-      from a_very_long_or_indented_module_name_yada_yad import (
-          long_argument_1, long_argument_2, long_argument_3)
-
-``SPLIT_PENALTY_LOGICAL_OPERATOR``
-    The penalty of splitting the line around the ``and`` and ``or`` operators.
-
-``USE_TABS``
-    Use the Tab character for indentation.
-
-(Potentially) Frequently Asked Questions
-========================================
-
---------------------------------------------
-Why does YAPF destroy my awesome formatting?
---------------------------------------------
-
-YAPF tries very hard to get the formatting correct. But for some code, it won't
-be as good as hand-formatting. In particular, large data literals may become
-horribly disfigured under YAPF.
-
-The reasons for this are manyfold. In short, YAPF is simply a tool to help
-with development. It will format things to coincide with the style guide, but
-that may not equate with readability.
-
-What can be done to alleviate this situation is to indicate regions YAPF should
-ignore when reformatting something:
-
-.. code-block:: python
-
-    # yapf: disable
-    FOO = {
-        # ... some very large, complex data literal.
-    }
-
-    BAR = [
-        # ... another large data literal.
-    ]
-    # yapf: enable
-
-You can also disable formatting for a single literal like this:
-
-.. code-block:: python
-
-    BAZ = {
-        (1, 2, 3, 4),
-        (5, 6, 7, 8),
-        (9, 10, 11, 12),
-    }  # yapf: disable
-
-To preserve the nice dedented closing brackets, use the
-``dedent_closing_brackets`` in your style. Note that in this case all
-brackets, including function definitions and calls, are going to use
-that style.  This provides consistency across the formatted codebase.
-
--------------------------------
-Why Not Improve Existing Tools?
--------------------------------
-
-We wanted to use clang-format's reformatting algorithm. It's very powerful and
-designed to come up with the best formatting possible. Existing tools were
-created with different goals in mind, and would require extensive modifications
-to convert to using clang-format's algorithm.
-
------------------------------
-Can I Use YAPF In My Program?
------------------------------
-
-Please do! YAPF was designed to be used as a library as well as a command line
-tool. This means that a tool or IDE plugin is free to use YAPF.
-
------------------------------------------
-I still get non Pep8 compliant code! Why?
------------------------------------------
-
-YAPF tries very hard to be fully PEP 8 compliant. However, it is paramount
-to not risk altering the semantics of your code. Thus, YAPF tries to be as
-safe as possible and does not change the token stream
-(e.g., by adding parentheses).
-All these cases however, can be easily fixed manually. For instance,
-
-.. code-block:: python
-
-    from my_package import my_function_1, my_function_2, my_function_3, my_function_4, my_function_5
-
-    FOO = my_variable_1 + my_variable_2 + my_variable_3 + my_variable_4 + my_variable_5 + my_variable_6 + my_variable_7 + my_variable_8
-
-won't be split, but you can easily get it right by just adding parentheses:
-
-.. code-block:: python
-
-    from my_package import (my_function_1, my_function_2, my_function_3,
-                            my_function_4, my_function_5)
-
-    FOO = (my_variable_1 + my_variable_2 + my_variable_3 + my_variable_4 +
-           my_variable_5 + my_variable_6 + my_variable_7 + my_variable_8)
-
-Gory Details
-============
-
-----------------
-Algorithm Design
-----------------
-
-The main data structure in YAPF is the ``LogicalLine`` object. It holds a list
-of ``FormatToken``\s, that we would want to place on a single line if there
-were no column limit. An exception being a comment in the middle of an
-expression statement will force the line to be formatted on more than one line.
-The formatter works on one ``LogicalLine`` object at a time.
-
-An ``LogicalLine`` typically won't affect the formatting of lines before or
-after it. There is a part of the algorithm that may join two or more
-``LogicalLine``\s into one line. For instance, an if-then statement with a
-short body can be placed on a single line:
-
-.. code-block:: python
-
-    if a == 42: continue
-
-YAPF's formatting algorithm creates a weighted tree that acts as the solution
-space for the algorithm. Each node in the tree represents the result of a
-formatting decision --- i.e., whether to split or not to split before a token.
-Each formatting decision has a cost associated with it. Therefore, the cost is
-realized on the edge between two nodes. (In reality, the weighted tree doesn't
-have separate edge objects, so the cost resides on the nodes themselves.)
-
-For example, take the following Python code snippet. For the sake of this
-example, assume that line (1) violates the column limit restriction and needs to
-be reformatted.
-
-.. code-block:: python
-
-    def xxxxxxxxxxx(aaaaaaaaaaaa, bbbbbbbbb, cccccccc, dddddddd, eeeeee):  # 1
-        pass                                                               # 2
-
-For line (1), the algorithm will build a tree where each node (a
-``FormattingDecisionState`` object) is the state of the line at that token given
-the decision to split before the token or not. Note: the ``FormatDecisionState``
-objects are copied by value so each node in the graph is unique and a change in
-one doesn't affect other nodes.
-
-Heuristics are used to determine the costs of splitting or not splitting.
-Because a node holds the state of the tree up to a token's insertion, it can
-easily determine if a splitting decision will violate one of the style
-requirements. For instance, the heuristic is able to apply an extra penalty to
-the edge when not splitting between the previous token and the one being added.
-
-There are some instances where we will never want to split the line, because
-doing so will always be detrimental (i.e., it will require a backslash-newline,
-which is very rarely desirable). For line (1), we will never want to split the
-first three tokens: ``def``, ``xxxxxxxxxxx``, and ``(``. Nor will we want to
-split between the ``)`` and the ``:`` at the end. These regions are said to be
-"unbreakable." This is reflected in the tree by there not being a "split"
-decision (left hand branch) within the unbreakable region.
-
-Now that we have the tree, we determine what the "best" formatting is by finding
-the path through the tree with the lowest cost.
-
-And that's it!
diff --git a/plugins/README.md b/plugins/README.md
new file mode 100644
index 0000000..d2b1aaa
--- /dev/null
+++ b/plugins/README.md
@@ -0,0 +1,106 @@
+# IDE Plugins
+
+## Emacs
+
+The `Emacs` plugin is maintained separately. Installation directions can be
+found here: https://github.com/paetzke/py-yapf.el
+
+
+## Vim
+
+The `vim` plugin allows you to reformat a range of code. Copy `plugin` and
+`autoload` directories into your `~/.vim` or use `:packadd` in Vim 8. Or use
+a plugin manager like Plug or Vundle:
+
+```vim
+" Plug
+Plug 'google/yapf', { 'rtp': 'plugins/vim', 'for': 'python' }
+
+" Vundle
+Plugin 'google/yapf', { 'rtp': 'plugins/vim' }
+```
+
+You can add key bindings in the `.vimrc` file:
+
+```vim
+map <C-Y> :call yapf#YAPF()<cr>
+imap <C-Y> <c-o>:call yapf#YAPF()<cr>
+```
+
+Alternatively, you can call the command `YAPF`. If you omit the range, it will
+reformat the whole buffer.
+
+example:
+
+```vim
+:YAPF       " formats whole buffer
+:'<,'>YAPF  " formats lines selected in visual mode
+```
+
+
+## Sublime Text
+
+The `Sublime Text` plugin is also maintained separately. It is compatible with
+both Sublime Text 2 and 3.
+
+The plugin can be easily installed by using *Sublime Package Control*. Check
+the project page of the plugin for more information: https://github.com/jason-kane/PyYapf
+
+
+## git Pre-Commit Hook
+
+The `git` pre-commit hook automatically formats your Python files before they
+are committed to your local repository. Any changes `yapf` makes to the files
+will stay unstaged so that you can diff them manually.
+
+To install, simply download the raw file and copy it into your git hooks
+directory:
+
+```bash
+# From the root of your git project.
+$ curl -o pre-commit.sh https://raw.githubusercontent.com/google/yapf/main/plugins/pre-commit.sh
+$ chmod a+x pre-commit.sh
+$ mv pre-commit.sh .git/hooks/pre-commit
+```
+
+
+## Textmate 2
+
+Plugin for `Textmate 2` requires `yapf` Python package installed on your
+system:
+
+```bash
+$ pip install yapf
+```
+
+Also, you will need to activate `Python` bundle from `Preferences > Bundles`.
+
+Finally, create a `~/Library/Application Support/TextMate/Bundles/Python.tmbundle/Commands/YAPF.tmCommand`
+file with the following content:
+
+```xml
+<?xml version="1.0" encoding="UTF-8"?>
+<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
+<plist version="1.0">
+<dict>
+  <key>beforeRunningCommand</key>
+  <string>saveActiveFile</string>
+  <key>command</key>
+  <string>#!/bin/bash
+
+TPY=${TM_PYTHON:-python}
+
+"$TPY" "/usr/local/bin/yapf" "$TM_FILEPATH"</string>
+  <key>input</key>
+  <string>document</string>
+  <key>name</key>
+  <string>YAPF</string>
+  <key>scope</key>
+  <string>source.python</string>
+  <key>uuid</key>
+  <string>297D5A82-2616-4950-9905-BD2D1C94D2D4</string>
+</dict>
+</plist>
+```
+
+You will see a new menu item `Bundles > Python > YAPF`.
diff --git a/plugins/README.rst b/plugins/README.rst
deleted file mode 100644
index b87bb2d..0000000
--- a/plugins/README.rst
+++ /dev/null
@@ -1,115 +0,0 @@
-===========
-IDE Plugins
-===========
-
-Emacs
-=====
-
-The ``Emacs`` plugin is maintained separately. Installation directions can be
-found here: https://github.com/paetzke/py-yapf.el
-
-VIM
-===
-
-The ``vim`` plugin allows you to reformat a range of code. Copy ``plugin`` and
-``autoload`` directories into your ~/.vim or use ``:packadd`` in Vim 8. Or use
-a plugin manager like Plug or Vundle:
-
-.. code-block:: vim
-
-     " Plug
-     Plug 'google/yapf', { 'rtp': 'plugins/vim', 'for': 'python' }
-
-     " Vundle
-     Plugin 'google/yapf', { 'rtp': 'plugins/vim' }
-
-
-You can add key bindings in the ``.vimrc`` file:
-
-.. code-block:: vim
-
-    map <C-Y> :call yapf#YAPF()<cr>
-    imap <C-Y> <c-o>:call yapf#YAPF()<cr>
-
-Alternatively, you can call the command ``YAPF``. If you omit the range, it
-will reformat the whole buffer.
-
-example:
-
-.. code-block:: vim
-
-    :YAPF       " formats whole buffer
-    :'<,'>YAPF  " formats lines selected in visual mode
-
-Sublime Text
-============
-
-The ``Sublime Text`` plugin is also maintained separately. It is compatible
-with both Sublime Text 2 and 3.
-
-The plugin can be easily installed by using *Sublime Package Control*. Check
-the project page of the plugin for more information:
-https://github.com/jason-kane/PyYapf
-
-===================
-git Pre-Commit Hook
-===================
-
-The ``git`` pre-commit hook automatically formats your Python files before they
-are committed to your local repository. Any changes ``yapf`` makes to the files
-will stay unstaged so that you can diff them manually.
-
-To install, simply download the raw file and copy it into your git hooks
-directory:
-
-.. code-block:: bash
-
-    # From the root of your git project.
-    curl -o pre-commit.sh https://raw.githubusercontent.com/google/yapf/main/plugins/pre-commit.sh
-    chmod a+x pre-commit.sh
-    mv pre-commit.sh .git/hooks/pre-commit
-
-==========
-Textmate 2
-==========
-
-Plugin for ``Textmate 2`` requires ``yapf`` Python package installed on your
-system:
-
-.. code-block:: shell
-
-    pip install yapf
-
-Also, you will need to activate ``Python`` bundle from ``Preferences >>
-Bundles``.
-
-Finally, create a ``~/Library/Application
-Support/TextMate/Bundles/Python.tmbundle/Commands/YAPF.tmCommand`` file with
-the following content:
-
-.. code-block:: xml
-
-    <?xml version="1.0" encoding="UTF-8"?>
-    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
-    <plist version="1.0">
-    <dict>
-      <key>beforeRunningCommand</key>
-      <string>saveActiveFile</string>
-      <key>command</key>
-      <string>#!/bin/bash
-
-    TPY=${TM_PYTHON:-python}
-
-    "$TPY" "/usr/local/bin/yapf" "$TM_FILEPATH"</string>
-      <key>input</key>
-      <string>document</string>
-      <key>name</key>
-      <string>YAPF</string>
-      <key>scope</key>
-      <string>source.python</string>
-      <key>uuid</key>
-      <string>297D5A82-2616-4950-9905-BD2D1C94D2D4</string>
-    </dict>
-    </plist>
-
-You will see a new menu item ``Bundles > Python > YAPF``.
diff --git a/pyproject.toml b/pyproject.toml
new file mode 100644
index 0000000..0b4bde3
--- /dev/null
+++ b/pyproject.toml
@@ -0,0 +1,63 @@
+[build-system]
+requires = ["setuptools>=58.5.0"]
+build-backend = "setuptools.build_meta"
+
+[project]
+name = "yapf"
+description = "A formatter for Python code"
+authors = [{ name = "Google Inc." }]
+maintainers = [{ name = "Bill Wendling", email = "morbo@google.com" }]
+dynamic = ["version"]
+license = { file = "LICENSE" }
+readme = "README.md"
+requires-python = ">=3.7"
+classifiers = [
+    'Development Status :: 4 - Beta',
+    'Environment :: Console',
+    'Intended Audience :: Developers',
+    'License :: OSI Approved :: Apache Software License',
+    'Operating System :: OS Independent',
+    'Programming Language :: Python',
+    'Programming Language :: Python :: 3 :: Only',
+    'Programming Language :: Python :: 3.7',
+    'Programming Language :: Python :: 3.8',
+    'Programming Language :: Python :: 3.9',
+    'Programming Language :: Python :: 3.10',
+    'Programming Language :: Python :: 3.11',
+    'Topic :: Software Development :: Libraries :: Python Modules',
+    'Topic :: Software Development :: Quality Assurance',
+]
+dependencies = ['platformdirs>=3.5.1', 'tomli>=2.0.1; python_version<"3.11"']
+
+[project.scripts]
+yapf = "yapf:run_main"
+yapf-diff = "yapf_third_party.yapf_diff.yapf_diff:main"
+
+[project.urls]
+# https://daniel.feldroy.com/posts/2023-08-pypi-project-urls-cheatsheet
+Home = 'https://github.com/google/yapf'
+Changelog = 'https://github.com/google/yapf/blob/main/CHANGELOG.md'
+Docs = 'https://github.com/google/yapf/blob/main/README.md#yapf'
+Issues = 'https://github.com/google/yapf/issues'
+
+[tool.distutils.bdist_wheel]
+python_tag = "py3"
+
+[tool.setuptools]
+include-package-data = true
+package-dir = { yapf_third_party = 'third_party/yapf_third_party' }
+
+[tool.setuptools.dynamic]
+version = { attr = "yapf._version.__version__" }
+
+[tool.setuptools.packages.find]
+where = [".", 'third_party']
+include = ["yapf*", 'yapftests*']
+
+[tool.setuptools.package-data]
+yapf_third_party = [
+    'yapf_diff/LICENSE',
+    '_ylib2to3/Grammar.txt',
+    '_ylib2to3/PatternGrammar.txt',
+    '_ylib2to3/LICENSE',
+]
diff --git a/setup.cfg b/setup.cfg
deleted file mode 100644
index 2a9acf1..0000000
--- a/setup.cfg
+++ /dev/null
@@ -1,2 +0,0 @@
-[bdist_wheel]
-universal = 1
diff --git a/setup.py b/setup.py
deleted file mode 100644
index 70e57da..0000000
--- a/setup.py
+++ /dev/null
@@ -1,76 +0,0 @@
-#!/usr/bin/env python
-# Copyright 2015 Google Inc. All Rights Reserved.
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#     http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-
-import codecs
-import sys
-import unittest
-
-from setuptools import find_packages, setup, Command
-
-import yapf
-
-
-class RunTests(Command):
-  user_options = []
-
-  def initialize_options(self):
-    pass
-
-  def finalize_options(self):
-    pass
-
-  def run(self):
-    loader = unittest.TestLoader()
-    tests = loader.discover('yapftests', pattern='*_test.py', top_level_dir='.')
-    runner = unittest.TextTestRunner()
-    results = runner.run(tests)
-    sys.exit(0 if results.wasSuccessful() else 1)
-
-
-with codecs.open('README.rst', 'r', 'utf-8') as fd:
-  setup(
-      name='yapf',
-      version=yapf.__version__,
-      description='A formatter for Python code.',
-      long_description=fd.read(),
-      license='Apache License, Version 2.0',
-      author='Google Inc.',
-      maintainer='Bill Wendling',
-      maintainer_email='morbo@google.com',
-      packages=find_packages('.'),
-      classifiers=[
-          'Development Status :: 4 - Beta',
-          'Environment :: Console',
-          'Intended Audience :: Developers',
-          'License :: OSI Approved :: Apache Software License',
-          'Operating System :: OS Independent',
-          'Programming Language :: Python',
-          'Programming Language :: Python :: 2',
-          'Programming Language :: Python :: 2.7',
-          'Programming Language :: Python :: 3',
-          'Programming Language :: Python :: 3.6',
-          'Topic :: Software Development :: Libraries :: Python Modules',
-          'Topic :: Software Development :: Quality Assurance',
-      ],
-      entry_points={
-          'console_scripts': [
-              'yapf = yapf:run_main',
-              'yapf-diff = yapf.third_party.yapf_diff.yapf_diff:main',
-          ],
-      },
-      cmdclass={
-          'test': RunTests,
-      },
-  )
diff --git a/yapf/third_party/__init__.py b/third_party/__init__.py
similarity index 100%
rename from yapf/third_party/__init__.py
rename to third_party/__init__.py
diff --git a/yapf/third_party/yapf_diff/__init__.py b/third_party/yapf_third_party/__init__.py
similarity index 100%
rename from yapf/third_party/yapf_diff/__init__.py
rename to third_party/yapf_third_party/__init__.py
diff --git a/third_party/yapf_third_party/_ylib2to3/Grammar.txt b/third_party/yapf_third_party/_ylib2to3/Grammar.txt
new file mode 100644
index 0000000..bd8a452
--- /dev/null
+++ b/third_party/yapf_third_party/_ylib2to3/Grammar.txt
@@ -0,0 +1,252 @@
+# Grammar for 2to3. This grammar supports Python 2.x and 3.x.
+
+# NOTE WELL: You should also follow all the steps listed at
+# https://devguide.python.org/grammar/
+
+# Start symbols for the grammar:
+#	file_input is a module or sequence of commands read from an input file;
+#	single_input is a single interactive statement;
+#	eval_input is the input for the eval() and input() functions.
+# NB: compound_stmt in single_input is followed by extra NEWLINE!
+file_input: (NEWLINE | stmt)* ENDMARKER
+single_input: NEWLINE | simple_stmt | compound_stmt NEWLINE
+eval_input: testlist NEWLINE* ENDMARKER
+
+decorator: '@' namedexpr_test NEWLINE
+decorators: decorator+
+decorated: decorators (classdef | funcdef | async_funcdef)
+async_funcdef: ASYNC funcdef
+funcdef: 'def' NAME parameters ['->' test] ':' suite
+parameters: '(' [typedargslist] ')'
+
+# The following definition for typedarglist is equivalent to this set of rules:
+#
+#     arguments = argument (',' argument)*
+#     argument = tfpdef ['=' test]
+#     kwargs = '**' tname [',']
+#     args = '*' [tname_star]
+#     kwonly_kwargs = (',' argument)* [',' [kwargs]]
+#     args_kwonly_kwargs = args kwonly_kwargs | kwargs
+#     poskeyword_args_kwonly_kwargs = arguments [',' [args_kwonly_kwargs]]
+#     typedargslist_no_posonly  = poskeyword_args_kwonly_kwargs | args_kwonly_kwargs
+#     typedarglist = arguments ',' '/' [',' [typedargslist_no_posonly]])|(typedargslist_no_posonly)"
+#
+# It needs to be fully expanded to allow our LL(1) parser to work on it.
+
+typedargslist: tfpdef ['=' test] (',' tfpdef ['=' test])* ',' '/' [
+                     ',' [((tfpdef ['=' test] ',')* ('*' [tname_star] (',' tname ['=' test])*
+                            [',' ['**' tname [',']]] | '**' tname [','])
+                     | tfpdef ['=' test] (',' tfpdef ['=' test])* [','])]
+                ] | ((tfpdef ['=' test] ',')* ('*' [tname_star] (',' tname ['=' test])*
+                     [',' ['**' tname [',']]] | '**' tname [','])
+                     | tfpdef ['=' test] (',' tfpdef ['=' test])* [','])
+
+tname: NAME [':' test]
+tname_star: NAME [':' (test|star_expr)]
+tfpdef: tname | '(' tfplist ')'
+tfplist: tfpdef (',' tfpdef)* [',']
+
+# The following definition for varargslist is equivalent to this set of rules:
+#
+#     arguments = argument (',' argument )*
+#     argument = vfpdef ['=' test]
+#     kwargs = '**' vname [',']
+#     args = '*' [vname]
+#     kwonly_kwargs = (',' argument )* [',' [kwargs]]
+#     args_kwonly_kwargs = args kwonly_kwargs | kwargs
+#     poskeyword_args_kwonly_kwargs = arguments [',' [args_kwonly_kwargs]]
+#     vararglist_no_posonly = poskeyword_args_kwonly_kwargs | args_kwonly_kwargs
+#     varargslist = arguments ',' '/' [','[(vararglist_no_posonly)]] | (vararglist_no_posonly)
+#
+# It needs to be fully expanded to allow our LL(1) parser to work on it.
+
+varargslist: vfpdef ['=' test ](',' vfpdef ['=' test])* ',' '/' [',' [
+                     ((vfpdef ['=' test] ',')* ('*' [vname] (',' vname ['=' test])*
+                            [',' ['**' vname [',']]] | '**' vname [','])
+                            | vfpdef ['=' test] (',' vfpdef ['=' test])* [','])
+                     ]] | ((vfpdef ['=' test] ',')*
+                     ('*' [vname] (',' vname ['=' test])*  [',' ['**' vname [',']]]| '**' vname [','])
+                     | vfpdef ['=' test] (',' vfpdef ['=' test])* [','])
+
+vname: NAME
+vfpdef: vname | '(' vfplist ')'
+vfplist: vfpdef (',' vfpdef)* [',']
+
+stmt: simple_stmt | compound_stmt
+simple_stmt: small_stmt (';' small_stmt)* [';'] NEWLINE
+small_stmt: (expr_stmt | print_stmt  | del_stmt | pass_stmt | flow_stmt |
+             import_stmt | global_stmt | exec_stmt | assert_stmt)
+expr_stmt: testlist_star_expr (annassign | augassign (yield_expr|testlist) |
+                     ('=' (yield_expr|testlist_star_expr))*)
+annassign: ':' test ['=' (yield_expr|testlist_star_expr)]
+testlist_star_expr: (test|star_expr) (',' (test|star_expr))* [',']
+augassign: ('+=' | '-=' | '*=' | '@=' | '/=' | '%=' | '&=' | '|=' | '^=' |
+            '<<=' | '>>=' | '**=' | '//=')
+# For normal and annotated assignments, additional restrictions enforced by the interpreter
+print_stmt: 'print' ( [ test (',' test)* [','] ] |
+                      '>>' test [ (',' test)+ [','] ] )
+del_stmt: 'del' exprlist
+pass_stmt: 'pass'
+flow_stmt: break_stmt | continue_stmt | return_stmt | raise_stmt | yield_stmt
+break_stmt: 'break'
+continue_stmt: 'continue'
+return_stmt: 'return' [testlist_star_expr]
+yield_stmt: yield_expr
+raise_stmt: 'raise' [test ['from' test | ',' test [',' test]]]
+import_stmt: import_name | import_from
+import_name: 'import' dotted_as_names
+import_from: ('from' ('.'* dotted_name | '.'+)
+              'import' ('*' | '(' import_as_names ')' | import_as_names))
+import_as_name: NAME ['as' NAME]
+dotted_as_name: dotted_name ['as' NAME]
+import_as_names: import_as_name (',' import_as_name)* [',']
+dotted_as_names: dotted_as_name (',' dotted_as_name)*
+dotted_name: NAME ('.' NAME)*
+global_stmt: ('global' | 'nonlocal') NAME (',' NAME)*
+exec_stmt: 'exec' expr ['in' test [',' test]]
+assert_stmt: 'assert' test [',' test]
+
+compound_stmt: if_stmt | while_stmt | for_stmt | try_stmt | with_stmt | funcdef | classdef | decorated | async_stmt | match_stmt
+async_stmt: ASYNC (funcdef | with_stmt | for_stmt)
+if_stmt: 'if' namedexpr_test ':' suite ('elif' namedexpr_test ':' suite)* ['else' ':' suite]
+while_stmt: 'while' namedexpr_test ':' suite ['else' ':' suite]
+for_stmt: 'for' exprlist 'in' testlist_star_expr ':' suite ['else' ':' suite]
+try_stmt: ('try' ':' suite
+           ((except_clause ':' suite)+
+	    ['else' ':' suite]
+	    ['finally' ':' suite] |
+	   'finally' ':' suite))
+with_stmt: 'with' asexpr_test (',' asexpr_test)*  ':' suite
+
+# NB compile.c makes sure that the default except clause is last
+except_clause: 'except' ['*'] [test [(',' | 'as') test]]
+suite: simple_stmt | NEWLINE INDENT stmt+ DEDENT
+
+# Backward compatibility cruft to support:
+# [ x for x in lambda: True, lambda: False if x() ]
+# even while also allowing:
+# lambda x: 5 if x else 2
+# (But not a mix of the two)
+testlist_safe: old_test [(',' old_test)+ [',']]
+old_test: or_test | old_lambdef
+old_lambdef: 'lambda' [varargslist] ':' old_test
+
+namedexpr_test: asexpr_test [':=' asexpr_test]
+
+# This is actually not a real rule, though since the parser is very
+# limited in terms of the strategy about match/case rules, we are inserting
+# a virtual case (<expr> as <expr>) as a valid expression. Unless a better
+# approach is thought, the only side effect of this seem to be just allowing
+# more stuff to be parser (which would fail on the ast).
+asexpr_test: test ['as' test]
+
+test: or_test ['if' or_test 'else' test] | lambdef
+or_test: and_test ('or' and_test)*
+and_test: not_test ('and' not_test)*
+not_test: 'not' not_test | comparison
+comparison: expr (comp_op expr)*
+comp_op: '<'|'>'|'=='|'>='|'<='|'<>'|'!='|'in'|'not' 'in'|'is'|'is' 'not'
+star_expr: '*' expr
+expr: xor_expr ('|' xor_expr)*
+xor_expr: and_expr ('^' and_expr)*
+and_expr: shift_expr ('&' shift_expr)*
+shift_expr: arith_expr (('<<'|'>>') arith_expr)*
+arith_expr: term (('+'|'-') term)*
+term: factor (('*'|'@'|'/'|'%'|'//') factor)*
+factor: ('+'|'-'|'~') factor | power
+power: [AWAIT] atom trailer* ['**' factor]
+atom: ('(' [yield_expr|testlist_gexp] ')' |
+       '[' [listmaker] ']' |
+       '{' [dictsetmaker] '}' |
+       '`' testlist1 '`' |
+       NAME | NUMBER | STRING+ | '.' '.' '.')
+listmaker: (namedexpr_test|star_expr) ( old_comp_for | (',' (namedexpr_test|star_expr))* [','] )
+testlist_gexp: (namedexpr_test|star_expr) ( old_comp_for | (',' (namedexpr_test|star_expr))* [','] )
+lambdef: 'lambda' [varargslist] ':' test
+trailer: '(' [arglist] ')' | '[' subscriptlist ']' | '.' NAME
+subscriptlist: (subscript|star_expr) (',' (subscript|star_expr))* [',']
+subscript: test [':=' test] | [test] ':' [test] [sliceop]
+sliceop: ':' [test]
+exprlist: (expr|star_expr) (',' (expr|star_expr))* [',']
+testlist: test (',' test)* [',']
+dictsetmaker: ( ((test ':' asexpr_test | '**' expr)
+                 (comp_for | (',' (test ':' asexpr_test | '**' expr))* [','])) |
+                ((test [':=' test] | star_expr)
+		 (comp_for | (',' (test [':=' test] | star_expr))* [','])) )
+
+classdef: 'class' NAME ['(' [arglist] ')'] ':' suite
+
+arglist: argument (',' argument)* [',']
+
+# "test '=' test" is really "keyword '=' test", but we have no such token.
+# These need to be in a single rule to avoid grammar that is ambiguous
+# to our LL(1) parser. Even though 'test' includes '*expr' in star_expr,
+# we explicitly match '*' here, too, to give it proper precedence.
+# Illegal combinations and orderings are blocked in ast.c:
+# multiple (test comp_for) arguments are blocked; keyword unpackings
+# that precede iterable unpackings are blocked; etc.
+argument: ( test [comp_for] |
+            test ':=' test [comp_for] |
+            test 'as' test |
+            test '=' asexpr_test |
+	    '**' test |
+            '*' test )
+
+comp_iter: comp_for | comp_if
+comp_for: [ASYNC] 'for' exprlist 'in' or_test [comp_iter]
+comp_if: 'if' old_test [comp_iter]
+
+# As noted above, testlist_safe extends the syntax allowed in list
+# comprehensions and generators. We can't use it indiscriminately in all
+# derivations using a comp_for-like pattern because the testlist_safe derivation
+# contains comma which clashes with trailing comma in arglist.
+#
+# This was an issue because the parser would not follow the correct derivation
+# when parsing syntactically valid Python code. Since testlist_safe was created
+# specifically to handle list comprehensions and generator expressions enclosed
+# with parentheses, it's safe to only use it in those. That avoids the issue; we
+# can parse code like set(x for x in [],).
+#
+# The syntax supported by this set of rules is not a valid Python 3 syntax,
+# hence the prefix "old".
+#
+# See https://bugs.python.org/issue27494
+old_comp_iter: old_comp_for | old_comp_if
+old_comp_for: [ASYNC] 'for' exprlist 'in' testlist_safe [old_comp_iter]
+old_comp_if: 'if' old_test [old_comp_iter]
+
+testlist1: test (',' test)*
+
+# not used in grammar, but may appear in "node" passed from Parser to Compiler
+encoding_decl: NAME
+
+yield_expr: 'yield' [yield_arg]
+yield_arg: 'from' test | testlist_star_expr
+
+
+# 3.10 match statement definition
+
+# PS: normally the grammar is much much more restricted, but
+# at this moment for not trying to bother much with encoding the
+# exact same DSL in a LL(1) parser, we will just accept an expression
+# and let the ast.parse() step of the safe mode to reject invalid
+# grammar.
+
+# The reason why it is more restricted is that, patterns are some
+# sort of a DSL (more advanced than our LHS on assignments, but
+# still in a very limited python subset). They are not really
+# expressions, but who cares. If we can parse them, that is enough
+# to reformat them.
+
+match_stmt: "match" subject_expr ':' NEWLINE INDENT case_block+ DEDENT
+
+# This is more permissive than the actual version. For example it
+# accepts `match *something:`, even though single-item starred expressions
+# are forbidden.
+subject_expr: (namedexpr_test|star_expr) (',' (namedexpr_test|star_expr))* [',']
+
+# cases
+case_block: "case" patterns [guard] ':' suite
+guard: 'if' namedexpr_test
+patterns: pattern (',' pattern)* [',']
+pattern: (expr|star_expr) ['as' expr]
diff --git a/third_party/yapf_third_party/_ylib2to3/LICENSE b/third_party/yapf_third_party/_ylib2to3/LICENSE
new file mode 100644
index 0000000..ef8df06
--- /dev/null
+++ b/third_party/yapf_third_party/_ylib2to3/LICENSE
@@ -0,0 +1,254 @@
+A. HISTORY OF THE SOFTWARE
+==========================
+
+Python was created in the early 1990s by Guido van Rossum at Stichting
+Mathematisch Centrum (CWI, see https://www.cwi.nl) in the Netherlands
+as a successor of a language called ABC.  Guido remains Python's
+principal author, although it includes many contributions from others.
+
+In 1995, Guido continued his work on Python at the Corporation for
+National Research Initiatives (CNRI, see https://www.cnri.reston.va.us)
+in Reston, Virginia where he released several versions of the
+software.
+
+In May 2000, Guido and the Python core development team moved to
+BeOpen.com to form the BeOpen PythonLabs team.  In October of the same
+year, the PythonLabs team moved to Digital Creations, which became
+Zope Corporation.  In 2001, the Python Software Foundation (PSF, see
+https://www.python.org/psf/) was formed, a non-profit organization
+created specifically to own Python-related Intellectual Property.
+Zope Corporation was a sponsoring member of the PSF.
+
+All Python releases are Open Source (see https://opensource.org for
+the Open Source Definition).  Historically, most, but not all, Python
+releases have also been GPL-compatible; the table below summarizes
+the various releases.
+
+    Release         Derived     Year        Owner       GPL-
+                    from                                compatible? (1)
+
+    0.9.0 thru 1.2              1991-1995   CWI         yes
+    1.3 thru 1.5.2  1.2         1995-1999   CNRI        yes
+    1.6             1.5.2       2000        CNRI        no
+    2.0             1.6         2000        BeOpen.com  no
+    1.6.1           1.6         2001        CNRI        yes (2)
+    2.1             2.0+1.6.1   2001        PSF         no
+    2.0.1           2.0+1.6.1   2001        PSF         yes
+    2.1.1           2.1+2.0.1   2001        PSF         yes
+    2.1.2           2.1.1       2002        PSF         yes
+    2.1.3           2.1.2       2002        PSF         yes
+    2.2 and above   2.1.1       2001-now    PSF         yes
+
+Footnotes:
+
+(1) GPL-compatible doesn't mean that we're distributing Python under
+    the GPL.  All Python licenses, unlike the GPL, let you distribute
+    a modified version without making your changes open source.  The
+    GPL-compatible licenses make it possible to combine Python with
+    other software that is released under the GPL; the others don't.
+
+(2) According to Richard Stallman, 1.6.1 is not GPL-compatible,
+    because its license has a choice of law clause.  According to
+    CNRI, however, Stallman's lawyer has told CNRI's lawyer that 1.6.1
+    is "not incompatible" with the GPL.
+
+Thanks to the many outside volunteers who have worked under Guido's
+direction to make these releases possible.
+
+
+B. TERMS AND CONDITIONS FOR ACCESSING OR OTHERWISE USING PYTHON
+===============================================================
+
+PYTHON SOFTWARE FOUNDATION LICENSE VERSION 2
+--------------------------------------------
+
+1. This LICENSE AGREEMENT is between the Python Software Foundation
+("PSF"), and the Individual or Organization ("Licensee") accessing and
+otherwise using this software ("Python") in source or binary form and
+its associated documentation.
+
+2. Subject to the terms and conditions of this License Agreement, PSF hereby
+grants Licensee a nonexclusive, royalty-free, world-wide license to reproduce,
+analyze, test, perform and/or display publicly, prepare derivative works,
+distribute, and otherwise use Python alone or in any derivative version,
+provided, however, that PSF's License Agreement and PSF's notice of copyright,
+i.e., "Copyright (c) 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010,
+2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018 Python Software Foundation; All
+Rights Reserved" are retained in Python alone or in any derivative version
+prepared by Licensee.
+
+3. In the event Licensee prepares a derivative work that is based on
+or incorporates Python or any part thereof, and wants to make
+the derivative work available to others as provided herein, then
+Licensee hereby agrees to include in any such work a brief summary of
+the changes made to Python.
+
+4. PSF is making Python available to Licensee on an "AS IS"
+basis.  PSF MAKES NO REPRESENTATIONS OR WARRANTIES, EXPRESS OR
+IMPLIED.  BY WAY OF EXAMPLE, BUT NOT LIMITATION, PSF MAKES NO AND
+DISCLAIMS ANY REPRESENTATION OR WARRANTY OF MERCHANTABILITY OR FITNESS
+FOR ANY PARTICULAR PURPOSE OR THAT THE USE OF PYTHON WILL NOT
+INFRINGE ANY THIRD PARTY RIGHTS.
+
+5. PSF SHALL NOT BE LIABLE TO LICENSEE OR ANY OTHER USERS OF PYTHON
+FOR ANY INCIDENTAL, SPECIAL, OR CONSEQUENTIAL DAMAGES OR LOSS AS
+A RESULT OF MODIFYING, DISTRIBUTING, OR OTHERWISE USING PYTHON,
+OR ANY DERIVATIVE THEREOF, EVEN IF ADVISED OF THE POSSIBILITY THEREOF.
+
+6. This License Agreement will automatically terminate upon a material
+breach of its terms and conditions.
+
+7. Nothing in this License Agreement shall be deemed to create any
+relationship of agency, partnership, or joint venture between PSF and
+Licensee.  This License Agreement does not grant permission to use PSF
+trademarks or trade name in a trademark sense to endorse or promote
+products or services of Licensee, or any third party.
+
+8. By copying, installing or otherwise using Python, Licensee
+agrees to be bound by the terms and conditions of this License
+Agreement.
+
+
+BEOPEN.COM LICENSE AGREEMENT FOR PYTHON 2.0
+-------------------------------------------
+
+BEOPEN PYTHON OPEN SOURCE LICENSE AGREEMENT VERSION 1
+
+1. This LICENSE AGREEMENT is between BeOpen.com ("BeOpen"), having an
+office at 160 Saratoga Avenue, Santa Clara, CA 95051, and the
+Individual or Organization ("Licensee") accessing and otherwise using
+this software in source or binary form and its associated
+documentation ("the Software").
+
+2. Subject to the terms and conditions of this BeOpen Python License
+Agreement, BeOpen hereby grants Licensee a non-exclusive,
+royalty-free, world-wide license to reproduce, analyze, test, perform
+and/or display publicly, prepare derivative works, distribute, and
+otherwise use the Software alone or in any derivative version,
+provided, however, that the BeOpen Python License is retained in the
+Software, alone or in any derivative version prepared by Licensee.
+
+3. BeOpen is making the Software available to Licensee on an "AS IS"
+basis.  BEOPEN MAKES NO REPRESENTATIONS OR WARRANTIES, EXPRESS OR
+IMPLIED.  BY WAY OF EXAMPLE, BUT NOT LIMITATION, BEOPEN MAKES NO AND
+DISCLAIMS ANY REPRESENTATION OR WARRANTY OF MERCHANTABILITY OR FITNESS
+FOR ANY PARTICULAR PURPOSE OR THAT THE USE OF THE SOFTWARE WILL NOT
+INFRINGE ANY THIRD PARTY RIGHTS.
+
+4. BEOPEN SHALL NOT BE LIABLE TO LICENSEE OR ANY OTHER USERS OF THE
+SOFTWARE FOR ANY INCIDENTAL, SPECIAL, OR CONSEQUENTIAL DAMAGES OR LOSS
+AS A RESULT OF USING, MODIFYING OR DISTRIBUTING THE SOFTWARE, OR ANY
+DERIVATIVE THEREOF, EVEN IF ADVISED OF THE POSSIBILITY THEREOF.
+
+5. This License Agreement will automatically terminate upon a material
+breach of its terms and conditions.
+
+6. This License Agreement shall be governed by and interpreted in all
+respects by the law of the State of California, excluding conflict of
+law provisions.  Nothing in this License Agreement shall be deemed to
+create any relationship of agency, partnership, or joint venture
+between BeOpen and Licensee.  This License Agreement does not grant
+permission to use BeOpen trademarks or trade names in a trademark
+sense to endorse or promote products or services of Licensee, or any
+third party.  As an exception, the "BeOpen Python" logos available at
+http://www.pythonlabs.com/logos.html may be used according to the
+permissions granted on that web page.
+
+7. By copying, installing or otherwise using the software, Licensee
+agrees to be bound by the terms and conditions of this License
+Agreement.
+
+
+CNRI LICENSE AGREEMENT FOR PYTHON 1.6.1
+---------------------------------------
+
+1. This LICENSE AGREEMENT is between the Corporation for National
+Research Initiatives, having an office at 1895 Preston White Drive,
+Reston, VA 20191 ("CNRI"), and the Individual or Organization
+("Licensee") accessing and otherwise using Python 1.6.1 software in
+source or binary form and its associated documentation.
+
+2. Subject to the terms and conditions of this License Agreement, CNRI
+hereby grants Licensee a nonexclusive, royalty-free, world-wide
+license to reproduce, analyze, test, perform and/or display publicly,
+prepare derivative works, distribute, and otherwise use Python 1.6.1
+alone or in any derivative version, provided, however, that CNRI's
+License Agreement and CNRI's notice of copyright, i.e., "Copyright (c)
+1995-2001 Corporation for National Research Initiatives; All Rights
+Reserved" are retained in Python 1.6.1 alone or in any derivative
+version prepared by Licensee.  Alternately, in lieu of CNRI's License
+Agreement, Licensee may substitute the following text (omitting the
+quotes): "Python 1.6.1 is made available subject to the terms and
+conditions in CNRI's License Agreement.  This Agreement together with
+Python 1.6.1 may be located on the Internet using the following
+unique, persistent identifier (known as a handle): 1895.22/1013.  This
+Agreement may also be obtained from a proxy server on the Internet
+using the following URL: http://hdl.handle.net/1895.22/1013".
+
+3. In the event Licensee prepares a derivative work that is based on
+or incorporates Python 1.6.1 or any part thereof, and wants to make
+the derivative work available to others as provided herein, then
+Licensee hereby agrees to include in any such work a brief summary of
+the changes made to Python 1.6.1.
+
+4. CNRI is making Python 1.6.1 available to Licensee on an "AS IS"
+basis.  CNRI MAKES NO REPRESENTATIONS OR WARRANTIES, EXPRESS OR
+IMPLIED.  BY WAY OF EXAMPLE, BUT NOT LIMITATION, CNRI MAKES NO AND
+DISCLAIMS ANY REPRESENTATION OR WARRANTY OF MERCHANTABILITY OR FITNESS
+FOR ANY PARTICULAR PURPOSE OR THAT THE USE OF PYTHON 1.6.1 WILL NOT
+INFRINGE ANY THIRD PARTY RIGHTS.
+
+5. CNRI SHALL NOT BE LIABLE TO LICENSEE OR ANY OTHER USERS OF PYTHON
+1.6.1 FOR ANY INCIDENTAL, SPECIAL, OR CONSEQUENTIAL DAMAGES OR LOSS AS
+A RESULT OF MODIFYING, DISTRIBUTING, OR OTHERWISE USING PYTHON 1.6.1,
+OR ANY DERIVATIVE THEREOF, EVEN IF ADVISED OF THE POSSIBILITY THEREOF.
+
+6. This License Agreement will automatically terminate upon a material
+breach of its terms and conditions.
+
+7. This License Agreement shall be governed by the federal
+intellectual property law of the United States, including without
+limitation the federal copyright law, and, to the extent such
+U.S. federal law does not apply, by the law of the Commonwealth of
+Virginia, excluding Virginia's conflict of law provisions.
+Notwithstanding the foregoing, with regard to derivative works based
+on Python 1.6.1 that incorporate non-separable material that was
+previously distributed under the GNU General Public License (GPL), the
+law of the Commonwealth of Virginia shall govern this License
+Agreement only as to issues arising under or with respect to
+Paragraphs 4, 5, and 7 of this License Agreement.  Nothing in this
+License Agreement shall be deemed to create any relationship of
+agency, partnership, or joint venture between CNRI and Licensee.  This
+License Agreement does not grant permission to use CNRI trademarks or
+trade name in a trademark sense to endorse or promote products or
+services of Licensee, or any third party.
+
+8. By clicking on the "ACCEPT" button where indicated, or by copying,
+installing or otherwise using Python 1.6.1, Licensee agrees to be
+bound by the terms and conditions of this License Agreement.
+
+        ACCEPT
+
+
+CWI LICENSE AGREEMENT FOR PYTHON 0.9.0 THROUGH 1.2
+--------------------------------------------------
+
+Copyright (c) 1991 - 1995, Stichting Mathematisch Centrum Amsterdam,
+The Netherlands.  All rights reserved.
+
+Permission to use, copy, modify, and distribute this software and its
+documentation for any purpose and without fee is hereby granted,
+provided that the above copyright notice appear in all copies and that
+both that copyright notice and this permission notice appear in
+supporting documentation, and that the name of Stichting Mathematisch
+Centrum or CWI not be used in advertising or publicity pertaining to
+distribution of the software without specific, written prior
+permission.
+
+STICHTING MATHEMATISCH CENTRUM DISCLAIMS ALL WARRANTIES WITH REGARD TO
+THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
+FITNESS, IN NO EVENT SHALL STICHTING MATHEMATISCH CENTRUM BE LIABLE
+FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
+WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
+ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
+OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
diff --git a/third_party/yapf_third_party/_ylib2to3/PatternGrammar.txt b/third_party/yapf_third_party/_ylib2to3/PatternGrammar.txt
new file mode 100644
index 0000000..36bf814
--- /dev/null
+++ b/third_party/yapf_third_party/_ylib2to3/PatternGrammar.txt
@@ -0,0 +1,28 @@
+# Copyright 2006 Google, Inc. All Rights Reserved.
+# Licensed to PSF under a Contributor Agreement.
+
+# A grammar to describe tree matching patterns.
+# Not shown here:
+# - 'TOKEN' stands for any token (leaf node)
+# - 'any' stands for any node (leaf or interior)
+# With 'any' we can still specify the sub-structure.
+
+# The start symbol is 'Matcher'.
+
+Matcher: Alternatives ENDMARKER
+
+Alternatives: Alternative ('|' Alternative)*
+
+Alternative: (Unit | NegatedUnit)+
+
+Unit: [NAME '='] ( STRING [Repeater]
+                 | NAME [Details] [Repeater]
+                 | '(' Alternatives ')' [Repeater]
+                 | '[' Alternatives ']'
+		 )
+
+NegatedUnit: 'not' (STRING | NAME [Details] | '(' Alternatives ')')
+
+Repeater: '*' | '+' | '{' NUMBER [',' NUMBER] '}'
+
+Details: '<' Alternatives '>'
diff --git a/third_party/yapf_third_party/_ylib2to3/README.rst b/third_party/yapf_third_party/_ylib2to3/README.rst
new file mode 100644
index 0000000..21d69b8
--- /dev/null
+++ b/third_party/yapf_third_party/_ylib2to3/README.rst
@@ -0,0 +1,9 @@
+A fork of python's lib2to3 with select features backported from black's blib2to3.
+
+Reasons for forking:
+
+- black's fork of lib2to3 already considers newer features like Structured Pattern matching
+- lib2to3 itself is deprecated and no longer getting support
+
+Maintenance moving forward:
+- Most changes moving forward should only have to be done to the grammar files in this project.
diff --git a/third_party/yapf_third_party/_ylib2to3/__init__.py b/third_party/yapf_third_party/_ylib2to3/__init__.py
new file mode 100644
index 0000000..1de9436
--- /dev/null
+++ b/third_party/yapf_third_party/_ylib2to3/__init__.py
@@ -0,0 +1 @@
+"""fork of python's lib2to3 with some backports from black's blib2to3"""
diff --git a/third_party/yapf_third_party/_ylib2to3/fixer_base.py b/third_party/yapf_third_party/_ylib2to3/fixer_base.py
new file mode 100644
index 0000000..92fd0f6
--- /dev/null
+++ b/third_party/yapf_third_party/_ylib2to3/fixer_base.py
@@ -0,0 +1,187 @@
+# Copyright 2006 Google, Inc. All Rights Reserved.
+# Licensed to PSF under a Contributor Agreement.
+"""Base class for fixers (optional, but recommended)."""
+
+# Python imports
+import itertools
+
+from . import pygram
+from .fixer_util import does_tree_import
+# Local imports
+from .patcomp import PatternCompiler
+
+
+class BaseFix(object):
+  """Optional base class for fixers.
+
+  The subclass name must be FixFooBar where FooBar is the result of
+  removing underscores and capitalizing the words of the fix name.
+  For example, the class name for a fixer named 'has_key' should be
+  FixHasKey.
+  """
+
+  PATTERN = None  # Most subclasses should override with a string literal
+  pattern = None  # Compiled pattern, set by compile_pattern()
+  pattern_tree = None  # Tree representation of the pattern
+  options = None  # Options object passed to initializer
+  filename = None  # The filename (set by set_filename)
+  numbers = itertools.count(1)  # For new_name()
+  used_names = set()  # A set of all used NAMEs
+  order = 'post'  # Does the fixer prefer pre- or post-order traversal
+  explicit = False  # Is this ignored by refactor.py -f all?
+  run_order = 5  # Fixers will be sorted by run order before execution
+  # Lower numbers will be run first.
+  _accept_type = None  # [Advanced and not public] This tells RefactoringTool
+  # which node type to accept when there's not a pattern.
+
+  keep_line_order = False  # For the bottom matcher: match with the
+  # original line order
+  BM_compatible = False  # Compatibility with the bottom matching
+  # module; every fixer should set this
+  # manually
+
+  # Shortcut for access to Python grammar symbols
+  syms = pygram.python_symbols
+
+  def __init__(self, options, log):
+    """Initializer.  Subclass may override.
+
+    Args:
+        options: a dict containing the options passed to RefactoringTool
+        that could be used to customize the fixer through the command line.
+        log: a list to append warnings and other messages to.
+    """
+    self.options = options
+    self.log = log
+    self.compile_pattern()
+
+  def compile_pattern(self):
+    """Compiles self.PATTERN into self.pattern.
+
+    Subclass may override if it doesn't want to use
+    self.{pattern,PATTERN} in .match().
+    """
+    if self.PATTERN is not None:
+      PC = PatternCompiler()
+      self.pattern, self.pattern_tree = PC.compile_pattern(
+          self.PATTERN, with_tree=True)
+
+  def set_filename(self, filename):
+    """Set the filename.
+
+    The main refactoring tool should call this.
+    """
+    self.filename = filename
+
+  def match(self, node):
+    """Returns match for a given parse tree node.
+
+    Should return a true or false object (not necessarily a bool).
+    It may return a non-empty dict of matching sub-nodes as
+    returned by a matching pattern.
+
+    Subclass may override.
+    """
+    results = {'node': node}
+    return self.pattern.match(node, results) and results
+
+  def transform(self, node, results):
+    """Returns the transformation for a given parse tree node.
+
+    Args:
+        node: the root of the parse tree that matched the fixer.
+        results: a dict mapping symbolic names to part of the match.
+
+    Returns:
+        None, or a node that is a modified copy of the
+        argument node.  The node argument may also be modified in-place to
+        effect the same change.
+
+    Subclass *must* override.
+    """
+    raise NotImplementedError()
+
+  def new_name(self, template='xxx_todo_changeme'):
+    """Return a string suitable for use as an identifier
+
+    The new name is guaranteed not to conflict with other identifiers.
+    """
+    name = template
+    while name in self.used_names:
+      name = template + str(next(self.numbers))
+    self.used_names.add(name)
+    return name
+
+  def log_message(self, message):
+    if self.first_log:
+      self.first_log = False
+      self.log.append('### In file %s ###' % self.filename)
+    self.log.append(message)
+
+  def cannot_convert(self, node, reason=None):
+    """Warn the user that a given chunk of code is not valid Python 3,
+       but that it cannot be converted automatically.
+
+    First argument is the top-level node for the code in question.
+    Optional second argument is why it can't be converted.
+    """
+    lineno = node.get_lineno()
+    for_output = node.clone()
+    for_output.prefix = ''
+    msg = 'Line %d: could not convert: %s'
+    self.log_message(msg % (lineno, for_output))
+    if reason:
+      self.log_message(reason)
+
+  def warning(self, node, reason):
+    """Used for warning the user about possible uncertainty in the translation.
+
+    First argument is the top-level node for the code in question.
+    Optional second argument is why it can't be converted.
+    """
+    lineno = node.get_lineno()
+    self.log_message('Line %d: %s' % (lineno, reason))
+
+  def start_tree(self, tree, filename):
+    """Some fixers need to maintain tree-wide state.
+
+    This method is called once, at the start of tree fix-up.
+
+    tree - the root node of the tree to be processed.
+    filename - the name of the file the tree came from.
+    """
+    self.used_names = tree.used_names
+    self.set_filename(filename)
+    self.numbers = itertools.count(1)
+    self.first_log = True
+
+  def finish_tree(self, tree, filename):
+    """Some fixers need to maintain tree-wide state.
+
+    This method is called once, at the conclusion of tree fix-up.
+
+    tree - the root node of the tree to be processed.
+    filename - the name of the file the tree came from.
+    """
+    pass
+
+
+class ConditionalFix(BaseFix):
+  """ Base class for fixers which not execute if an import is found. """
+
+  # This is the name of the import which, if found, will cause the test to be
+  # skipped.
+  skip_on = None
+
+  def start_tree(self, *args):
+    super(ConditionalFix, self).start_tree(*args)
+    self._should_skip = None
+
+  def should_skip(self, node):
+    if self._should_skip is not None:
+      return self._should_skip
+    pkg = self.skip_on.split('.')
+    name = pkg[-1]
+    pkg = '.'.join(pkg[:-1])
+    self._should_skip = does_tree_import(pkg, name, node)
+    return self._should_skip
diff --git a/third_party/yapf_third_party/_ylib2to3/fixer_util.py b/third_party/yapf_third_party/_ylib2to3/fixer_util.py
new file mode 100644
index 0000000..373b2be
--- /dev/null
+++ b/third_party/yapf_third_party/_ylib2to3/fixer_util.py
@@ -0,0 +1,493 @@
+"""Utility functions, node construction macros, etc."""
+# Author: Collin Winter
+
+from . import patcomp
+# Local imports
+from .pgen2 import token
+from .pygram import python_symbols as syms
+from .pytree import Leaf
+from .pytree import Node
+
+###########################################################
+# Common node-construction "macros"
+###########################################################
+
+
+def KeywordArg(keyword, value):
+  return Node(syms.argument, [keyword, Leaf(token.EQUAL, '='), value])
+
+
+def LParen():
+  return Leaf(token.LPAR, '(')
+
+
+def RParen():
+  return Leaf(token.RPAR, ')')
+
+
+def Assign(target, source):
+  """Build an assignment statement"""
+  if not isinstance(target, list):
+    target = [target]
+  if not isinstance(source, list):
+    source.prefix = ' '
+    source = [source]
+
+  return Node(syms.atom, target + [Leaf(token.EQUAL, '=', prefix=' ')] + source)
+
+
+def Name(name, prefix=None):
+  """Return a NAME leaf"""
+  return Leaf(token.NAME, name, prefix=prefix)
+
+
+def Attr(obj, attr):
+  """A node tuple for obj.attr"""
+  return [obj, Node(syms.trailer, [Dot(), attr])]
+
+
+def Comma():
+  """A comma leaf"""
+  return Leaf(token.COMMA, ',')
+
+
+def Dot():
+  """A period (.) leaf"""
+  return Leaf(token.DOT, '.')
+
+
+def ArgList(args, lparen=LParen(), rparen=RParen()):
+  """A parenthesised argument list, used by Call()"""
+  node = Node(syms.trailer, [lparen.clone(), rparen.clone()])
+  if args:
+    node.insert_child(1, Node(syms.arglist, args))
+  return node
+
+
+def Call(func_name, args=None, prefix=None):
+  """A function call"""
+  node = Node(syms.power, [func_name, ArgList(args)])
+  if prefix is not None:
+    node.prefix = prefix
+  return node
+
+
+def Newline():
+  """A newline literal"""
+  return Leaf(token.NEWLINE, '\n')
+
+
+def BlankLine():
+  """A blank line"""
+  return Leaf(token.NEWLINE, '')
+
+
+def Number(n, prefix=None):
+  return Leaf(token.NUMBER, n, prefix=prefix)
+
+
+def Subscript(index_node):
+  """A numeric or string subscript"""
+  return Node(syms.trailer,
+              [Leaf(token.LBRACE, '['), index_node,
+               Leaf(token.RBRACE, ']')])
+
+
+def String(string, prefix=None):
+  """A string leaf"""
+  return Leaf(token.STRING, string, prefix=prefix)
+
+
+def ListComp(xp, fp, it, test=None):
+  """A list comprehension of the form [xp for fp in it if test].
+
+  If test is None, the "if test" part is omitted.
+  """
+  xp.prefix = ''
+  fp.prefix = ' '
+  it.prefix = ' '
+  for_leaf = Leaf(token.NAME, 'for')
+  for_leaf.prefix = ' '
+  in_leaf = Leaf(token.NAME, 'in')
+  in_leaf.prefix = ' '
+  inner_args = [for_leaf, fp, in_leaf, it]
+  if test:
+    test.prefix = ' '
+    if_leaf = Leaf(token.NAME, 'if')
+    if_leaf.prefix = ' '
+    inner_args.append(Node(syms.comp_if, [if_leaf, test]))
+  inner = Node(syms.listmaker, [xp, Node(syms.comp_for, inner_args)])
+  return Node(syms.atom,
+              [Leaf(token.LBRACE, '['), inner,
+               Leaf(token.RBRACE, ']')])
+
+
+def FromImport(package_name, name_leafs):
+  """ Return an import statement in the form:
+
+       from package import name_leafs
+  """
+  # XXX: May not handle dotted imports properly (eg, package_name='foo.bar')
+  # #assert package_name == '.' or '.' not in package_name, "FromImport has "\
+  #       "not been tested with dotted package names -- use at your own "\
+  #       "peril!"
+
+  for leaf in name_leafs:
+    # Pull the leaves out of their old tree
+    leaf.remove()
+
+  children = [
+      Leaf(token.NAME, 'from'),
+      Leaf(token.NAME, package_name, prefix=' '),
+      Leaf(token.NAME, 'import', prefix=' '),
+      Node(syms.import_as_names, name_leafs)
+  ]
+  imp = Node(syms.import_from, children)
+  return imp
+
+
+def ImportAndCall(node, results, names):
+  """Returns an import statement and calls a method of the module:
+
+      import module
+      module.name()
+  """
+  obj = results['obj'].clone()
+  if obj.type == syms.arglist:
+    newarglist = obj.clone()
+  else:
+    newarglist = Node(syms.arglist, [obj.clone()])
+  after = results['after']
+  if after:
+    after = [n.clone() for n in after]
+  new = Node(
+      syms.power,
+      Attr(Name(names[0]), Name(names[1])) + [
+          Node(syms.trailer,
+               [results['lpar'].clone(), newarglist, results['rpar'].clone()])
+      ] + after)
+  new.prefix = node.prefix
+  return new
+
+
+###########################################################
+# Determine whether a node represents a given literal
+###########################################################
+
+
+def is_tuple(node):
+  """Does the node represent a tuple literal?"""
+  if isinstance(node, Node) and node.children == [LParen(), RParen()]:
+    return True
+  return (isinstance(node, Node) and len(node.children) == 3 and
+          isinstance(node.children[0], Leaf) and
+          isinstance(node.children[1], Node) and
+          isinstance(node.children[2], Leaf) and
+          node.children[0].value == '(' and node.children[2].value == ')')
+
+
+def is_list(node):
+  """Does the node represent a list literal?"""
+  return (isinstance(node, Node) and len(node.children) > 1 and
+          isinstance(node.children[0], Leaf) and
+          isinstance(node.children[-1], Leaf) and
+          node.children[0].value == '[' and node.children[-1].value == ']')
+
+
+###########################################################
+# Misc
+###########################################################
+
+
+def parenthesize(node):
+  return Node(syms.atom, [LParen(), node, RParen()])
+
+
+consuming_calls = {
+    'sorted', 'list', 'set', 'any', 'all', 'tuple', 'sum', 'min', 'max',
+    'enumerate'
+}
+
+
+def attr_chain(obj, attr):
+  """Follow an attribute chain.
+
+  If you have a chain of objects where a.foo -> b, b.foo-> c, etc, use this to
+  iterate over all objects in the chain. Iteration is terminated by getattr(x,
+  attr) is None.
+
+  Args:
+      obj: the starting object
+      attr: the name of the chaining attribute
+
+  Yields:
+      Each successive object in the chain.
+  """
+  next = getattr(obj, attr)
+  while next:
+    yield next
+    next = getattr(next, attr)
+
+
+p0 = """for_stmt< 'for' any 'in' node=any ':' any* >
+        | comp_for< 'for' any 'in' node=any any* >
+     """
+p1 = """
+power<
+    ( 'iter' | 'list' | 'tuple' | 'sorted' | 'set' | 'sum' |
+      'any' | 'all' | 'enumerate' | (any* trailer< '.' 'join' >) )
+    trailer< '(' node=any ')' >
+    any*
+>
+"""
+p2 = """
+power<
+    ( 'sorted' | 'enumerate' )
+    trailer< '(' arglist<node=any any*> ')' >
+    any*
+>
+"""
+pats_built = False
+
+
+def in_special_context(node):
+  """ Returns true if node is in an environment where all that is required
+      of it is being iterable (ie, it doesn't matter if it returns a list
+      or an iterator).
+      See test_map_nochange in test_fixers.py for some examples and tests.
+  """
+  global p0, p1, p2, pats_built
+  if not pats_built:
+    p0 = patcomp.compile_pattern(p0)
+    p1 = patcomp.compile_pattern(p1)
+    p2 = patcomp.compile_pattern(p2)
+    pats_built = True
+  patterns = [p0, p1, p2]
+  for pattern, parent in zip(patterns, attr_chain(node, 'parent')):
+    results = {}
+    if pattern.match(parent, results) and results['node'] is node:
+      return True
+  return False
+
+
+def is_probably_builtin(node):
+  """Check that something isn't an attribute or function name etc."""
+  prev = node.prev_sibling
+  if prev is not None and prev.type == token.DOT:
+    # Attribute lookup.
+    return False
+  parent = node.parent
+  if parent.type in (syms.funcdef, syms.classdef):
+    return False
+  if parent.type == syms.expr_stmt and parent.children[0] is node:
+    # Assignment.
+    return False
+  if parent.type == syms.parameters or (parent.type == syms.typedargslist and (
+      (prev is not None and prev.type == token.COMMA) or
+      parent.children[0] is node)):
+    # The name of an argument.
+    return False
+  return True
+
+
+def find_indentation(node):
+  """Find the indentation of *node*."""
+  while node is not None:
+    if node.type == syms.suite and len(node.children) > 2:
+      indent = node.children[1]
+      if indent.type == token.INDENT:
+        return indent.value
+    node = node.parent
+  return ''
+
+
+###########################################################
+# The following functions are to find bindings in a suite
+###########################################################
+
+
+def make_suite(node):
+  if node.type == syms.suite:
+    return node
+  node = node.clone()
+  parent, node.parent = node.parent, None
+  suite = Node(syms.suite, [node])
+  suite.parent = parent
+  return suite
+
+
+def find_root(node):
+  """Find the top level namespace."""
+  # Scamper up to the top level namespace
+  while node.type != syms.file_input:
+    node = node.parent
+    if not node:
+      raise ValueError('root found before file_input node was found.')
+  return node
+
+
+def does_tree_import(package, name, node):
+  """ Returns true if name is imported from package at the
+      top level of the tree which node belongs to.
+      To cover the case of an import like 'import foo', use
+      None for the package and 'foo' for the name.
+  """
+  binding = find_binding(name, find_root(node), package)
+  return bool(binding)
+
+
+def is_import(node):
+  """Returns true if the node is an import statement."""
+  return node.type in (syms.import_name, syms.import_from)
+
+
+def touch_import(package, name, node):
+  """ Works like `does_tree_import` but adds an import statement
+      if it was not imported. """
+
+  def is_import_stmt(node):
+    return (node.type == syms.simple_stmt and node.children and
+            is_import(node.children[0]))
+
+  root = find_root(node)
+
+  if does_tree_import(package, name, root):
+    return
+
+  # figure out where to insert the new import.  First try to find
+  # the first import and then skip to the last one.
+  insert_pos = offset = 0
+  for idx, node in enumerate(root.children):
+    if not is_import_stmt(node):
+      continue
+    for offset, node2 in enumerate(root.children[idx:]):
+      if not is_import_stmt(node2):
+        break
+    insert_pos = idx + offset
+    break
+
+  # if there are no imports where we can insert, find the docstring.
+  # if that also fails, we stick to the beginning of the file
+  if insert_pos == 0:
+    for idx, node in enumerate(root.children):
+      if (node.type == syms.simple_stmt and node.children and
+          node.children[0].type == token.STRING):
+        insert_pos = idx + 1
+        break
+
+  if package is None:
+    import_ = Node(
+        syms.import_name,
+        [Leaf(token.NAME, 'import'),
+         Leaf(token.NAME, name, prefix=' ')])
+  else:
+    import_ = FromImport(package, [Leaf(token.NAME, name, prefix=' ')])
+
+  children = [import_, Newline()]
+  root.insert_child(insert_pos, Node(syms.simple_stmt, children))
+
+
+_def_syms = {syms.classdef, syms.funcdef}
+
+
+def find_binding(name, node, package=None):
+  """ Returns the node which binds variable name, otherwise None.
+      If optional argument package is supplied, only imports will
+      be returned.
+      See test cases for examples.
+  """
+  for child in node.children:
+    ret = None
+    if child.type == syms.for_stmt:
+      if _find(name, child.children[1]):
+        return child
+      n = find_binding(name, make_suite(child.children[-1]), package)
+      if n:
+        ret = n
+    elif child.type in (syms.if_stmt, syms.while_stmt):
+      n = find_binding(name, make_suite(child.children[-1]), package)
+      if n:
+        ret = n
+    elif child.type == syms.try_stmt:
+      n = find_binding(name, make_suite(child.children[2]), package)
+      if n:
+        ret = n
+      else:
+        for i, kid in enumerate(child.children[3:]):
+          if kid.type == token.COLON and kid.value == ':':
+            # i+3 is the colon, i+4 is the suite
+            n = find_binding(name, make_suite(child.children[i + 4]), package)
+            if n:
+              ret = n
+    elif child.type in _def_syms and child.children[1].value == name:
+      ret = child
+    elif _is_import_binding(child, name, package):
+      ret = child
+    elif child.type == syms.simple_stmt:
+      ret = find_binding(name, child, package)
+    elif child.type == syms.expr_stmt:
+      if _find(name, child.children[0]):
+        ret = child
+
+    if ret:
+      if not package:
+        return ret
+      if is_import(ret):
+        return ret
+  return None
+
+
+_block_syms = {syms.funcdef, syms.classdef, syms.trailer}
+
+
+def _find(name, node):
+  nodes = [node]
+  while nodes:
+    node = nodes.pop()
+    if node.type > 256 and node.type not in _block_syms:
+      nodes.extend(node.children)
+    elif node.type == token.NAME and node.value == name:
+      return node
+  return None
+
+
+def _is_import_binding(node, name, package=None):
+  """ Will return node if node will import name, or node
+      will import * from package.  None is returned otherwise.
+      See test cases for examples.
+  """
+  if node.type == syms.import_name and not package:
+    imp = node.children[1]
+    if imp.type == syms.dotted_as_names:
+      for child in imp.children:
+        if child.type == syms.dotted_as_name:
+          if child.children[2].value == name:
+            return node
+        elif child.type == token.NAME and child.value == name:
+          return node
+    elif imp.type == syms.dotted_as_name:
+      last = imp.children[-1]
+      if last.type == token.NAME and last.value == name:
+        return node
+    elif imp.type == token.NAME and imp.value == name:
+      return node
+  elif node.type == syms.import_from:
+    # str(...) is used to make life easier here, because
+    # from a.b import parses to ['import', ['a', '.', 'b'], ...]
+    if package and str(node.children[1]).strip() != package:
+      return None
+    n = node.children[3]
+    if package and _find('as', n):
+      # See test_from_import_as for explanation
+      return None
+    elif n.type == syms.import_as_names and _find(name, n):
+      return node
+    elif n.type == syms.import_as_name:
+      child = n.children[2]
+      if child.type == token.NAME and child.value == name:
+        return node
+    elif n.type == token.NAME and n.value == name:
+      return node
+    elif package and n.type == token.STAR:
+      return node
+  return None
diff --git a/third_party/yapf_third_party/_ylib2to3/patcomp.py b/third_party/yapf_third_party/_ylib2to3/patcomp.py
new file mode 100644
index 0000000..20b7893
--- /dev/null
+++ b/third_party/yapf_third_party/_ylib2to3/patcomp.py
@@ -0,0 +1,209 @@
+# Copyright 2006 Google, Inc. All Rights Reserved.
+# Licensed to PSF under a Contributor Agreement.
+"""Pattern compiler.
+
+The grammar is taken from PatternGrammar.txt.
+
+The compiler compiles a pattern to a pytree.*Pattern instance.
+"""
+
+__author__ = 'Guido van Rossum <guido@python.org>'
+
+# Python imports
+import io
+
+# Really local imports
+from . import pygram
+from . import pytree
+# Fairly local imports
+from .pgen2 import driver
+from .pgen2 import grammar
+from .pgen2 import literals
+from .pgen2 import parse
+from .pgen2 import token
+from .pgen2 import tokenize
+
+
+class PatternSyntaxError(Exception):
+  pass
+
+
+def tokenize_wrapper(input):
+  """Tokenizes a string suppressing significant whitespace."""
+  skip = {token.NEWLINE, token.INDENT, token.DEDENT}
+  tokens = tokenize.generate_tokens(io.StringIO(input).readline)
+  for quintuple in tokens:
+    type, value, start, end, line_text = quintuple
+    if type not in skip:
+      yield quintuple
+
+
+class PatternCompiler(object):
+
+  def __init__(self, grammar_file=None):
+    """Initializer.
+
+        Takes an optional alternative filename for the pattern grammar.
+        """
+    if grammar_file is None:
+      self.grammar = pygram.pattern_grammar
+      self.syms = pygram.pattern_symbols
+    else:
+      self.grammar = driver.load_grammar(grammar_file)
+      self.syms = pygram.Symbols(self.grammar)
+    self.pygrammar = pygram.python_grammar
+    self.pysyms = pygram.python_symbols
+    self.driver = driver.Driver(self.grammar, convert=pattern_convert)
+
+  def compile_pattern(self, input, debug=False, with_tree=False):
+    """Compiles a pattern string to a nested pytree.*Pattern object."""
+    tokens = tokenize_wrapper(input)
+    try:
+      root = self.driver.parse_tokens(tokens, debug=debug)
+    except parse.ParseError as e:
+      raise PatternSyntaxError(str(e)) from None
+    if with_tree:
+      return self.compile_node(root), root
+    else:
+      return self.compile_node(root)
+
+  def compile_node(self, node):
+    """Compiles a node, recursively.
+
+        This is one big switch on the node type.
+        """
+    # XXX Optimize certain Wildcard-containing-Wildcard patterns
+    # that can be merged
+    if node.type == self.syms.Matcher:
+      node = node.children[0]  # Avoid unneeded recursion
+
+    if node.type == self.syms.Alternatives:
+      # Skip the odd children since they are just '|' tokens
+      alts = [self.compile_node(ch) for ch in node.children[::2]]
+      if len(alts) == 1:
+        return alts[0]
+      p = pytree.WildcardPattern([[a] for a in alts], min=1, max=1)
+      return p.optimize()
+
+    if node.type == self.syms.Alternative:
+      units = [self.compile_node(ch) for ch in node.children]
+      if len(units) == 1:
+        return units[0]
+      p = pytree.WildcardPattern([units], min=1, max=1)
+      return p.optimize()
+
+    if node.type == self.syms.NegatedUnit:
+      pattern = self.compile_basic(node.children[1:])
+      p = pytree.NegatedPattern(pattern)
+      return p.optimize()
+
+    assert node.type == self.syms.Unit
+
+    name = None
+    nodes = node.children
+    if len(nodes) >= 3 and nodes[1].type == token.EQUAL:
+      name = nodes[0].value
+      nodes = nodes[2:]
+    repeat = None
+    if len(nodes) >= 2 and nodes[-1].type == self.syms.Repeater:
+      repeat = nodes[-1]
+      nodes = nodes[:-1]
+
+    # Now we've reduced it to: STRING | NAME [Details] | (...) | [...]
+    pattern = self.compile_basic(nodes, repeat)
+
+    if repeat is not None:
+      assert repeat.type == self.syms.Repeater
+      children = repeat.children
+      child = children[0]
+      if child.type == token.STAR:
+        min = 0
+        max = pytree.HUGE
+      elif child.type == token.PLUS:
+        min = 1
+        max = pytree.HUGE
+      elif child.type == token.LBRACE:
+        assert children[-1].type == token.RBRACE
+        assert len(children) in (3, 5)
+        min = max = self.get_int(children[1])
+        if len(children) == 5:
+          max = self.get_int(children[3])
+      else:
+        assert False
+      if min != 1 or max != 1:
+        pattern = pattern.optimize()
+        pattern = pytree.WildcardPattern([[pattern]], min=min, max=max)
+
+    if name is not None:
+      pattern.name = name
+    return pattern.optimize()
+
+  def compile_basic(self, nodes, repeat=None):
+    # Compile STRING | NAME [Details] | (...) | [...]
+    assert len(nodes) >= 1
+    node = nodes[0]
+    if node.type == token.STRING:
+      value = str(literals.evalString(node.value))
+      return pytree.LeafPattern(_type_of_literal(value), value)
+    elif node.type == token.NAME:
+      value = node.value
+      if value.isupper():
+        if value not in TOKEN_MAP:
+          raise PatternSyntaxError('Invalid token: %r' % value)
+        if nodes[1:]:
+          raise PatternSyntaxError("Can't have details for token")
+        return pytree.LeafPattern(TOKEN_MAP[value])
+      else:
+        if value == 'any':
+          type = None
+        elif not value.startswith('_'):
+          type = getattr(self.pysyms, value, None)
+          if type is None:
+            raise PatternSyntaxError('Invalid symbol: %r' % value)
+        if nodes[1:]:  # Details present
+          content = [self.compile_node(nodes[1].children[1])]
+        else:
+          content = None
+        return pytree.NodePattern(type, content)
+    elif node.value == '(':
+      return self.compile_node(nodes[1])
+    elif node.value == '[':
+      assert repeat is None
+      subpattern = self.compile_node(nodes[1])
+      return pytree.WildcardPattern([[subpattern]], min=0, max=1)
+    assert False, node
+
+  def get_int(self, node):
+    assert node.type == token.NUMBER
+    return int(node.value)
+
+
+# Map named tokens to the type value for a LeafPattern
+TOKEN_MAP = {
+    'NAME': token.NAME,
+    'STRING': token.STRING,
+    'NUMBER': token.NUMBER,
+    'TOKEN': None
+}
+
+
+def _type_of_literal(value):
+  if value[0].isalpha():
+    return token.NAME
+  elif value in grammar.opmap:
+    return grammar.opmap[value]
+  else:
+    return None
+
+
+def pattern_convert(grammar, raw_node_info):
+  """Converts raw node information to a Node or Leaf instance."""
+  type, value, context, children = raw_node_info
+  if children or type in grammar.number2symbol:
+    return pytree.Node(type, children, context=context)
+  else:
+    return pytree.Leaf(type, value, context=context)
+
+
+def compile_pattern(pattern):
+  return PatternCompiler().compile_pattern(pattern)
diff --git a/third_party/yapf_third_party/_ylib2to3/pgen2/__init__.py b/third_party/yapf_third_party/_ylib2to3/pgen2/__init__.py
new file mode 100644
index 0000000..7c8380a
--- /dev/null
+++ b/third_party/yapf_third_party/_ylib2to3/pgen2/__init__.py
@@ -0,0 +1,3 @@
+# Copyright 2004-2005 Elemental Security, Inc. All Rights Reserved.
+# Licensed to PSF under a Contributor Agreement.
+"""The pgen2 package."""
diff --git a/third_party/yapf_third_party/_ylib2to3/pgen2/conv.py b/third_party/yapf_third_party/_ylib2to3/pgen2/conv.py
new file mode 100644
index 0000000..a446771
--- /dev/null
+++ b/third_party/yapf_third_party/_ylib2to3/pgen2/conv.py
@@ -0,0 +1,254 @@
+# Copyright 2004-2005 Elemental Security, Inc. All Rights Reserved.
+# Licensed to PSF under a Contributor Agreement.
+"""Convert graminit.[ch] spit out by pgen to Python code.
+
+Pgen is the Python parser generator.  It is useful to quickly create a
+parser from a grammar file in Python's grammar notation.  But I don't
+want my parsers to be written in C (yet), so I'm translating the
+parsing tables to Python data structures and writing a Python parse
+engine.
+
+Note that the token numbers are constants determined by the standard
+Python tokenizer.  The standard token module defines these numbers and
+their names (the names are not used much).  The token numbers are
+hardcoded into the Python tokenizer and into pgen.  A Python
+implementation of the Python tokenizer is also available, in the
+standard tokenize module.
+
+On the other hand, symbol numbers (representing the grammar's
+non-terminals) are assigned by pgen based on the actual grammar
+input.
+
+Note: this module is pretty much obsolete; the pgen module generates
+equivalent grammar tables directly from the Grammar.txt input file
+without having to invoke the Python pgen C program.
+
+"""
+
+# Python imports
+import re
+
+# Local imports
+from pgen2 import grammar
+from pgen2 import token
+
+
+class Converter(grammar.Grammar):
+  """Grammar subclass that reads classic pgen output files.
+
+    The run() method reads the tables as produced by the pgen parser
+    generator, typically contained in two C files, graminit.h and
+    graminit.c.  The other methods are for internal use only.
+
+    See the base class for more documentation.
+
+    """
+
+  def run(self, graminit_h, graminit_c):
+    """Load the grammar tables from the text files written by pgen."""
+    self.parse_graminit_h(graminit_h)
+    self.parse_graminit_c(graminit_c)
+    self.finish_off()
+
+  def parse_graminit_h(self, filename):
+    """Parse the .h file written by pgen.  (Internal)
+
+        This file is a sequence of #define statements defining the
+        nonterminals of the grammar as numbers.  We build two tables
+        mapping the numbers to names and back.
+
+        """
+    try:
+      f = open(filename)
+    except OSError as err:
+      print("Can't open %s: %s" % (filename, err))
+      return False
+    self.symbol2number = {}
+    self.number2symbol = {}
+    lineno = 0
+    for line in f:
+      lineno += 1
+      mo = re.match(r'^#define\s+(\w+)\s+(\d+)$', line)
+      if not mo and line.strip():
+        print("%s(%s): can't parse %s" % (filename, lineno, line.strip()))
+      else:
+        symbol, number = mo.groups()
+        number = int(number)
+        assert symbol not in self.symbol2number
+        assert number not in self.number2symbol
+        self.symbol2number[symbol] = number
+        self.number2symbol[number] = symbol
+    return True
+
+  def parse_graminit_c(self, filename):
+    """Parse the .c file written by pgen.  (Internal)
+
+        The file looks as follows.  The first two lines are always this:
+
+        #include "pgenheaders.h"
+        #include "grammar.h"
+
+        After that come four blocks:
+
+        1) one or more state definitions
+        2) a table defining dfas
+        3) a table defining labels
+        4) a struct defining the grammar
+
+        A state definition has the following form:
+        - one or more arc arrays, each of the form:
+          static arc arcs_<n>_<m>[<k>] = {
+                  {<i>, <j>},
+                  ...
+          };
+        - followed by a state array, of the form:
+          static state states_<s>[<t>] = {
+                  {<k>, arcs_<n>_<m>},
+                  ...
+          };
+
+        """
+    try:
+      f = open(filename)
+    except OSError as err:
+      print("Can't open %s: %s" % (filename, err))
+      return False
+    # The code below essentially uses f's iterator-ness!
+    lineno = 0
+
+    # Expect the two #include lines
+    lineno, line = lineno + 1, next(f)
+    assert line == '#include "pgenheaders.h"\n', (lineno, line)
+    lineno, line = lineno + 1, next(f)
+    assert line == '#include "grammar.h"\n', (lineno, line)
+
+    # Parse the state definitions
+    lineno, line = lineno + 1, next(f)
+    allarcs = {}
+    states = []
+    while line.startswith('static arc '):
+      while line.startswith('static arc '):
+        mo = re.match(r'static arc arcs_(\d+)_(\d+)\[(\d+)\] = {$', line)
+        assert mo, (lineno, line)
+        n, m, k = list(map(int, mo.groups()))
+        arcs = []
+        for _ in range(k):
+          lineno, line = lineno + 1, next(f)
+          mo = re.match(r'\s+{(\d+), (\d+)},$', line)
+          assert mo, (lineno, line)
+          i, j = list(map(int, mo.groups()))
+          arcs.append((i, j))
+        lineno, line = lineno + 1, next(f)
+        assert line == '};\n', (lineno, line)
+        allarcs[(n, m)] = arcs
+        lineno, line = lineno + 1, next(f)
+      mo = re.match(r'static state states_(\d+)\[(\d+)\] = {$', line)
+      assert mo, (lineno, line)
+      s, t = list(map(int, mo.groups()))
+      assert s == len(states), (lineno, line)
+      state = []
+      for _ in range(t):
+        lineno, line = lineno + 1, next(f)
+        mo = re.match(r'\s+{(\d+), arcs_(\d+)_(\d+)},$', line)
+        assert mo, (lineno, line)
+        k, n, m = list(map(int, mo.groups()))
+        arcs = allarcs[n, m]
+        assert k == len(arcs), (lineno, line)
+        state.append(arcs)
+      states.append(state)
+      lineno, line = lineno + 1, next(f)
+      assert line == '};\n', (lineno, line)
+      lineno, line = lineno + 1, next(f)
+    self.states = states
+
+    # Parse the dfas
+    dfas = {}
+    mo = re.match(r'static dfa dfas\[(\d+)\] = {$', line)
+    assert mo, (lineno, line)
+    ndfas = int(mo.group(1))
+    for i in range(ndfas):
+      lineno, line = lineno + 1, next(f)
+      mo = re.match(r'\s+{(\d+), "(\w+)", (\d+), (\d+), states_(\d+),$', line)
+      assert mo, (lineno, line)
+      symbol = mo.group(2)
+      number, x, y, z = list(map(int, mo.group(1, 3, 4, 5)))
+      assert self.symbol2number[symbol] == number, (lineno, line)
+      assert self.number2symbol[number] == symbol, (lineno, line)
+      assert x == 0, (lineno, line)
+      state = states[z]
+      assert y == len(state), (lineno, line)
+      lineno, line = lineno + 1, next(f)
+      mo = re.match(r'\s+("(?:\\\d\d\d)*")},$', line)
+      assert mo, (lineno, line)
+      first = {}
+      rawbitset = eval(mo.group(1))
+      for i, c in enumerate(rawbitset):
+        byte = ord(c)
+        for j in range(8):
+          if byte & (1 << j):
+            first[i * 8 + j] = 1
+      dfas[number] = (state, first)
+    lineno, line = lineno + 1, next(f)
+    assert line == '};\n', (lineno, line)
+    self.dfas = dfas
+
+    # Parse the labels
+    labels = []
+    lineno, line = lineno + 1, next(f)
+    mo = re.match(r'static label labels\[(\d+)\] = {$', line)
+    assert mo, (lineno, line)
+    nlabels = int(mo.group(1))
+    for i in range(nlabels):
+      lineno, line = lineno + 1, next(f)
+      mo = re.match(r'\s+{(\d+), (0|"\w+")},$', line)
+      assert mo, (lineno, line)
+      x, y = mo.groups()
+      x = int(x)
+      if y == '0':
+        y = None
+      else:
+        y = eval(y)
+      labels.append((x, y))
+    lineno, line = lineno + 1, next(f)
+    assert line == '};\n', (lineno, line)
+    self.labels = labels
+
+    # Parse the grammar struct
+    lineno, line = lineno + 1, next(f)
+    assert line == 'grammar _PyParser_Grammar = {\n', (lineno, line)
+    lineno, line = lineno + 1, next(f)
+    mo = re.match(r'\s+(\d+),$', line)
+    assert mo, (lineno, line)
+    ndfas = int(mo.group(1))
+    assert ndfas == len(self.dfas)
+    lineno, line = lineno + 1, next(f)
+    assert line == '\tdfas,\n', (lineno, line)
+    lineno, line = lineno + 1, next(f)
+    mo = re.match(r'\s+{(\d+), labels},$', line)
+    assert mo, (lineno, line)
+    nlabels = int(mo.group(1))
+    assert nlabels == len(self.labels), (lineno, line)
+    lineno, line = lineno + 1, next(f)
+    mo = re.match(r'\s+(\d+)$', line)
+    assert mo, (lineno, line)
+    start = int(mo.group(1))
+    assert start in self.number2symbol, (lineno, line)
+    self.start = start
+    lineno, line = lineno + 1, next(f)
+    assert line == '};\n', (lineno, line)
+    try:
+      lineno, line = lineno + 1, next(f)
+    except StopIteration:
+      pass
+    else:
+      assert 0, (lineno, line)
+
+  def finish_off(self):
+    """Create additional useful structures.  (Internal)."""
+    self.keywords = {}  # map from keyword strings to arc labels
+    self.tokens = {}  # map from numeric token values to arc labels
+    for ilabel, (type, value) in enumerate(self.labels):
+      if type == token.NAME and value is not None:
+        self.keywords[value] = ilabel
+      elif value is None:
+        self.tokens[type] = ilabel
diff --git a/third_party/yapf_third_party/_ylib2to3/pgen2/driver.py b/third_party/yapf_third_party/_ylib2to3/pgen2/driver.py
new file mode 100644
index 0000000..76b31a1
--- /dev/null
+++ b/third_party/yapf_third_party/_ylib2to3/pgen2/driver.py
@@ -0,0 +1,296 @@
+# Copyright 2004-2005 Elemental Security, Inc. All Rights Reserved.
+# Licensed to PSF under a Contributor Agreement.
+
+# Modifications:
+# Copyright 2006 Google, Inc. All Rights Reserved.
+# Licensed to PSF under a Contributor Agreement.
+"""Parser driver.
+
+This provides a high-level interface to parse a file into a syntax tree.
+
+"""
+
+__author__ = 'Guido van Rossum <guido@python.org>'
+
+__all__ = ['Driver', 'load_grammar']
+
+import io
+import logging
+import os
+import pkgutil
+import sys
+# Python imports
+from contextlib import contextmanager
+from dataclasses import dataclass
+from dataclasses import field
+from pathlib import Path
+from typing import Any
+from typing import Iterator
+from typing import List
+from typing import Optional
+
+from platformdirs import user_cache_dir
+
+from yapf._version import __version__ as yapf_version
+
+# Pgen imports
+from . import grammar
+from . import parse
+from . import pgen
+from . import token
+from . import tokenize
+
+
+@dataclass
+class ReleaseRange:
+  start: int
+  end: Optional[int] = None
+  tokens: List[Any] = field(default_factory=list)
+
+  def lock(self) -> None:
+    total_eaten = len(self.tokens)
+    self.end = self.start + total_eaten
+
+
+class TokenProxy:
+
+  def __init__(self, generator: Any) -> None:
+    self._tokens = generator
+    self._counter = 0
+    self._release_ranges: List[ReleaseRange] = []
+
+  @contextmanager
+  def release(self) -> Iterator['TokenProxy']:
+    release_range = ReleaseRange(self._counter)
+    self._release_ranges.append(release_range)
+    try:
+      yield self
+    finally:
+      # Lock the last release range to the final position that
+      # has been eaten.
+      release_range.lock()
+
+  def eat(self, point: int) -> Any:
+    eaten_tokens = self._release_ranges[-1].tokens
+    if point < len(eaten_tokens):
+      return eaten_tokens[point]
+    else:
+      while point >= len(eaten_tokens):
+        token = next(self._tokens)
+        eaten_tokens.append(token)
+      return token
+
+  def __iter__(self) -> 'TokenProxy':
+    return self
+
+  def __next__(self) -> Any:
+    # If the current position is already compromised (looked up)
+    # return the eaten token, if not just go further on the given
+    # token producer.
+    for release_range in self._release_ranges:
+      assert release_range.end is not None
+
+      start, end = release_range.start, release_range.end
+      if start <= self._counter < end:
+        token = release_range.tokens[self._counter - start]
+        break
+    else:
+      token = next(self._tokens)
+    self._counter += 1
+    return token
+
+  def can_advance(self, to: int) -> bool:
+    # Try to eat, fail if it can't. The eat operation is cached
+    # so there wont be any additional cost of eating here
+    try:
+      self.eat(to)
+    except StopIteration:
+      return False
+    else:
+      return True
+
+
+class Driver(object):
+
+  def __init__(self, grammar, convert=None, logger=None):
+    self.grammar = grammar
+    if logger is None:
+      logger = logging.getLogger()
+    self.logger = logger
+    self.convert = convert
+
+  def parse_tokens(self, tokens, debug=False):
+    """Parse a series of tokens and return the syntax tree."""
+    # XXX Move the prefix computation into a wrapper around tokenize.
+    p = parse.Parser(self.grammar, self.convert)
+    proxy = TokenProxy(tokens)
+    p.setup(proxy=proxy)
+    lineno = 1
+    column = 0
+    type = value = start = end = line_text = None
+    prefix = ''
+    for quintuple in proxy:
+      type, value, start, end, line_text = quintuple
+      if start != (lineno, column):
+        assert (lineno, column) <= start, ((lineno, column), start)
+        s_lineno, s_column = start
+        if lineno < s_lineno:
+          prefix += '\n' * (s_lineno - lineno)
+          lineno = s_lineno
+          column = 0
+        if column < s_column:
+          prefix += line_text[column:s_column]
+          column = s_column
+      if type in (tokenize.COMMENT, tokenize.NL):
+        prefix += value
+        lineno, column = end
+        if value.endswith('\n'):
+          lineno += 1
+          column = 0
+        continue
+      if type == token.OP:
+        type = grammar.opmap[value]
+      if debug:
+        self.logger.debug('%s %r (prefix=%r)', token.tok_name[type], value,
+                          prefix)
+      if p.addtoken(type, value, (prefix, start)):
+        if debug:
+          self.logger.debug('Stop.')
+        break
+      prefix = ''
+      lineno, column = end
+      if value.endswith('\n'):
+        lineno += 1
+        column = 0
+    else:
+      # We never broke out -- EOF is too soon (how can this happen???)
+      raise parse.ParseError('incomplete input', type, value, (prefix, start))
+    return p.rootnode
+
+  def parse_stream_raw(self, stream, debug=False):
+    """Parse a stream and return the syntax tree."""
+    tokens = tokenize.generate_tokens(stream.readline)
+    return self.parse_tokens(tokens, debug)
+
+  def parse_stream(self, stream, debug=False):
+    """Parse a stream and return the syntax tree."""
+    return self.parse_stream_raw(stream, debug)
+
+  def parse_file(self, filename, encoding=None, debug=False):
+    """Parse a file and return the syntax tree."""
+    with io.open(filename, 'r', encoding=encoding) as stream:
+      return self.parse_stream(stream, debug)
+
+  def parse_string(self, text, debug=False):
+    """Parse a string and return the syntax tree."""
+    tokens = tokenize.generate_tokens(io.StringIO(text).readline)
+    return self.parse_tokens(tokens, debug)
+
+
+def _generate_pickle_name(gt):
+  # type:(str) -> str
+  """Get the filepath to write a pickle file to
+  given the path of a grammar textfile.
+
+  The returned filepath should be in a user-specific cache directory.
+
+  Args:
+      gt (str): path to grammar text file
+
+  Returns:
+      str: path to pickle file
+  """
+
+  grammar_textfile_name = os.path.basename(gt)
+  head, tail = os.path.splitext(grammar_textfile_name)
+  if tail == '.txt':
+    tail = ''
+  cache_dir = user_cache_dir(
+      appname='YAPF', appauthor='Google', version=yapf_version)
+  return cache_dir + os.sep + head + tail + '-py' + '.'.join(
+      map(str, sys.version_info)) + '.pickle'
+
+
+def load_grammar(gt='Grammar.txt',
+                 gp=None,
+                 save=True,
+                 force=False,
+                 logger=None):
+  # type:(str, str | None, bool, bool, logging.Logger | None) -> grammar.Grammar
+  """Load the grammar (maybe from a pickle)."""
+  if logger is None:
+    logger = logging.getLogger()
+  gp = _generate_pickle_name(gt) if gp is None else gp
+  grammar_text = gt
+  try:
+    newer = _newer(gp, gt)
+  except OSError as err:
+    logger.debug('OSError, could not check if newer: %s', err.args)
+    newer = True
+  if not os.path.exists(gt):
+    # Assume package data
+    gt_basename = os.path.basename(gt)
+    pd = pkgutil.get_data('yapf_third_party._ylib2to3', gt_basename)
+    if pd is None:
+      raise RuntimeError('Failed to load grammer %s from package' % gt_basename)
+    grammar_text = io.StringIO(pd.decode(encoding='utf-8'))
+  if force or not newer:
+    g = pgen.generate_grammar(grammar_text)
+    if save:
+      try:
+        Path(gp).parent.mkdir(parents=True, exist_ok=True)
+        g.dump(gp)
+      except OSError:
+        # Ignore error, caching is not vital.
+        pass
+  else:
+    g = grammar.Grammar()
+    g.load(gp)
+  return g
+
+
+def _newer(a, b):
+  """Inquire whether file a was written since file b."""
+  if not os.path.exists(a):
+    return False
+  if not os.path.exists(b):
+    return True
+  return os.path.getmtime(a) >= os.path.getmtime(b)
+
+
+def load_packaged_grammar(package, grammar_source):
+  """Normally, loads a pickled grammar by doing
+        pkgutil.get_data(package, pickled_grammar)
+    where *pickled_grammar* is computed from *grammar_source* by adding the
+    Python version and using a ``.pickle`` extension.
+
+    However, if *grammar_source* is an extant file, load_grammar(grammar_source)
+    is called instead. This facilitates using a packaged grammar file when needed
+    but preserves load_grammar's automatic regeneration behavior when possible.
+
+    """  # noqa: E501
+  if os.path.isfile(grammar_source):
+    return load_grammar(grammar_source)
+  pickled_name = _generate_pickle_name(os.path.basename(grammar_source))
+  data = pkgutil.get_data(package, pickled_name)
+  g = grammar.Grammar()
+  g.loads(data)
+  return g
+
+
+def main(*args):
+  """Main program, when run as a script: produce grammar pickle files.
+
+    Calls load_grammar for each argument, a path to a grammar text file.
+    """
+  if not args:
+    args = sys.argv[1:]
+  logging.basicConfig(
+      level=logging.INFO, stream=sys.stdout, format='%(message)s')
+  for gt in args:
+    load_grammar(gt, save=True, force=True)
+  return True
+
+
+if __name__ == '__main__':
+  sys.exit(int(not main()))
diff --git a/third_party/yapf_third_party/_ylib2to3/pgen2/grammar.py b/third_party/yapf_third_party/_ylib2to3/pgen2/grammar.py
new file mode 100644
index 0000000..3825ce7
--- /dev/null
+++ b/third_party/yapf_third_party/_ylib2to3/pgen2/grammar.py
@@ -0,0 +1,221 @@
+# Copyright 2004-2005 Elemental Security, Inc. All Rights Reserved.
+# Licensed to PSF under a Contributor Agreement.
+"""This module defines the data structures used to represent a grammar.
+
+These are a bit arcane because they are derived from the data
+structures used by Python's 'pgen' parser generator.
+
+There's also a table here mapping operators to their names in the
+token module; the Python tokenize module reports all operators as the
+fallback token code OP, but the parser needs the actual token code.
+
+"""
+
+# Python imports
+import os
+import pickle
+import tempfile
+
+# Local imports
+from . import token
+
+
+class Grammar(object):
+  """Pgen parsing tables conversion class.
+
+    Once initialized, this class supplies the grammar tables for the
+    parsing engine implemented by parse.py.  The parsing engine
+    accesses the instance variables directly.  The class here does not
+    provide initialization of the tables; several subclasses exist to
+    do this (see the conv and pgen modules).
+
+    The load() method reads the tables from a pickle file, which is
+    much faster than the other ways offered by subclasses.  The pickle
+    file is written by calling dump() (after loading the grammar
+    tables using a subclass).  The report() method prints a readable
+    representation of the tables to stdout, for debugging.
+
+    The instance variables are as follows:
+
+    symbol2number -- a dict mapping symbol names to numbers.  Symbol
+                     numbers are always 256 or higher, to distinguish
+                     them from token numbers, which are between 0 and
+                     255 (inclusive).
+
+    number2symbol -- a dict mapping numbers to symbol names;
+                     these two are each other's inverse.
+
+    states        -- a list of DFAs, where each DFA is a list of
+                     states, each state is a list of arcs, and each
+                     arc is a (i, j) pair where i is a label and j is
+                     a state number.  The DFA number is the index into
+                     this list.  (This name is slightly confusing.)
+                     Final states are represented by a special arc of
+                     the form (0, j) where j is its own state number.
+
+    dfas          -- a dict mapping symbol numbers to (DFA, first)
+                     pairs, where DFA is an item from the states list
+                     above, and first is a set of tokens that can
+                     begin this grammar rule (represented by a dict
+                     whose values are always 1).
+
+    labels        -- a list of (x, y) pairs where x is either a token
+                     number or a symbol number, and y is either None
+                     or a string; the strings are keywords.  The label
+                     number is the index in this list; label numbers
+                     are used to mark state transitions (arcs) in the
+                     DFAs.
+
+    start         -- the number of the grammar's start symbol.
+
+    keywords      -- a dict mapping keyword strings to arc labels.
+
+    tokens        -- a dict mapping token numbers to arc labels.
+
+    """
+
+  def __init__(self):
+    self.symbol2number = {}
+    self.number2symbol = {}
+    self.states = []
+    self.dfas = {}
+    self.labels = [(0, 'EMPTY')]
+    self.keywords = {}
+    self.soft_keywords = {}
+    self.tokens = {}
+    self.symbol2label = {}
+    self.start = 256
+
+  def dump(self, filename):
+    """Dump the grammar tables to a pickle file."""
+    # NOTE:
+    # - We're writing a tempfile first so that there is no chance
+    #   for someone to read a half-written file from this very spot
+    #   while we're were not done writing.
+    # - We're using ``os.rename`` to sure not copy data around (which
+    #   would get us back to square one with a reading-half-written file
+    #   race condition).
+    # - We're making the tempfile go to the same directory as the eventual
+    #   target ``filename`` so that there is no chance of failing from
+    #   cross-file-system renames in ``os.rename``.
+    # - We're using the same prefix and suffix for the tempfile so if we
+    #   ever have to leave a tempfile around for failure of deletion,
+    #   it will have a reasonable filename extension and its name will help
+    #   explain is nature.
+    tempfile_dir = os.path.dirname(filename)
+    tempfile_prefix, tempfile_suffix = os.path.splitext(filename)
+    with tempfile.NamedTemporaryFile(
+        mode='wb',
+        suffix=tempfile_suffix,
+        prefix=tempfile_prefix,
+        dir=tempfile_dir,
+        delete=False) as f:
+      pickle.dump(self.__dict__, f.file, pickle.HIGHEST_PROTOCOL)
+      try:
+        os.rename(f.name, filename)
+      except OSError:
+        # This makes sure that we do not leave the tempfile around
+        # unless we have to...
+        try:
+          os.remove(f.name)
+        except OSError:
+          pass
+        raise
+
+  def load(self, filename):
+    """Load the grammar tables from a pickle file."""
+    with open(filename, 'rb') as f:
+      d = pickle.load(f)
+    self.__dict__.update(d)
+
+  def loads(self, pkl):
+    """Load the grammar tables from a pickle bytes object."""
+    self.__dict__.update(pickle.loads(pkl))
+
+  def copy(self):
+    """
+        Copy the grammar.
+        """
+    new = self.__class__()
+    for dict_attr in ('symbol2number', 'number2symbol', 'dfas', 'keywords',
+                      'soft_keywords', 'tokens', 'symbol2label'):
+      setattr(new, dict_attr, getattr(self, dict_attr).copy())
+    new.labels = self.labels[:]
+    new.states = self.states[:]
+    new.start = self.start
+    return new
+
+  def report(self):
+    """Dump the grammar tables to standard output, for debugging."""
+    from pprint import pprint
+    print('s2n')
+    pprint(self.symbol2number)
+    print('n2s')
+    pprint(self.number2symbol)
+    print('states')
+    pprint(self.states)
+    print('dfas')
+    pprint(self.dfas)
+    print('labels')
+    pprint(self.labels)
+    print('start', self.start)
+
+
+# Map from operator to number (since tokenize doesn't do this)
+
+opmap_raw = """
+( LPAR
+) RPAR
+[ LSQB
+] RSQB
+: COLON
+, COMMA
+; SEMI
++ PLUS
+- MINUS
+* STAR
+/ SLASH
+| VBAR
+& AMPER
+< LESS
+> GREATER
+= EQUAL
+. DOT
+% PERCENT
+` BACKQUOTE
+{ LBRACE
+} RBRACE
+@ AT
+@= ATEQUAL
+== EQEQUAL
+!= NOTEQUAL
+<> NOTEQUAL
+<= LESSEQUAL
+>= GREATEREQUAL
+~ TILDE
+^ CIRCUMFLEX
+<< LEFTSHIFT
+>> RIGHTSHIFT
+** DOUBLESTAR
++= PLUSEQUAL
+-= MINEQUAL
+*= STAREQUAL
+/= SLASHEQUAL
+%= PERCENTEQUAL
+&= AMPEREQUAL
+|= VBAREQUAL
+^= CIRCUMFLEXEQUAL
+<<= LEFTSHIFTEQUAL
+>>= RIGHTSHIFTEQUAL
+**= DOUBLESTAREQUAL
+// DOUBLESLASH
+//= DOUBLESLASHEQUAL
+-> RARROW
+:= COLONEQUAL
+"""
+
+opmap = {}
+for line in opmap_raw.splitlines():
+  if line:
+    op, name = line.split()
+    opmap[op] = getattr(token, name)
diff --git a/third_party/yapf_third_party/_ylib2to3/pgen2/literals.py b/third_party/yapf_third_party/_ylib2to3/pgen2/literals.py
new file mode 100644
index 0000000..62d1d26
--- /dev/null
+++ b/third_party/yapf_third_party/_ylib2to3/pgen2/literals.py
@@ -0,0 +1,64 @@
+# Copyright 2004-2005 Elemental Security, Inc. All Rights Reserved.
+# Licensed to PSF under a Contributor Agreement.
+"""Safely evaluate Python string literals without using eval()."""
+
+import re
+
+simple_escapes = {
+    'a': '\a',
+    'b': '\b',
+    'f': '\f',
+    'n': '\n',
+    'r': '\r',
+    't': '\t',
+    'v': '\v',
+    "'": "'",
+    '"': '"',
+    '\\': '\\'
+}
+
+
+def escape(m):
+  all, tail = m.group(0, 1)
+  assert all.startswith('\\')
+  esc = simple_escapes.get(tail)
+  if esc is not None:
+    return esc
+  if tail.startswith('x'):
+    hexes = tail[1:]
+    if len(hexes) < 2:
+      raise ValueError("invalid hex string escape ('\\%s')" % tail)
+    try:
+      i = int(hexes, 16)
+    except ValueError:
+      raise ValueError("invalid hex string escape ('\\%s')" % tail) from None
+  else:
+    try:
+      i = int(tail, 8)
+    except ValueError:
+      raise ValueError("invalid octal string escape ('\\%s')" % tail) from None
+  return chr(i)
+
+
+def evalString(s):
+  assert s.startswith("'") or s.startswith('"'), repr(s[:1])
+  q = s[0]
+  if s[:3] == q * 3:
+    q = q * 3
+  assert s.endswith(q), repr(s[-len(q):])
+  assert len(s) >= 2 * len(q)
+  s = s[len(q):-len(q)]
+  return re.sub(r"\\(\'|\"|\\|[abfnrtv]|x.{0,2}|[0-7]{1,3})", escape, s)
+
+
+def test():
+  for i in range(256):
+    c = chr(i)
+    s = repr(c)
+    e = evalString(s)
+    if e != c:
+      print(i, c, s, e)
+
+
+if __name__ == '__main__':
+  test()
diff --git a/third_party/yapf_third_party/_ylib2to3/pgen2/parse.py b/third_party/yapf_third_party/_ylib2to3/pgen2/parse.py
new file mode 100644
index 0000000..924b0e7
--- /dev/null
+++ b/third_party/yapf_third_party/_ylib2to3/pgen2/parse.py
@@ -0,0 +1,378 @@
+# Copyright 2004-2005 Elemental Security, Inc. All Rights Reserved.
+# Licensed to PSF under a Contributor Agreement.
+"""Parser engine for the grammar tables generated by pgen.
+
+The grammar table must be loaded first.
+
+See Parser/parser.c in the Python distribution for additional info on
+how this parsing engine works.
+
+"""
+from contextlib import contextmanager
+from typing import Any
+from typing import Callable
+from typing import Dict
+from typing import Iterator
+from typing import List
+from typing import Optional
+from typing import Set
+from typing import Text
+from typing import Tuple
+from typing import cast
+
+from ..pytree import Context
+from ..pytree import RawNode
+from ..pytree import convert
+# Local imports
+from . import grammar
+from . import token
+from . import tokenize
+
+DFA = List[List[Tuple[int, int]]]
+DFAS = Tuple[DFA, Dict[int, int]]
+
+# A placeholder node, used when parser is backtracking.
+DUMMY_NODE = (-1, None, None, None)
+
+
+def stack_copy(
+    stack: List[Tuple[DFAS, int, RawNode]]) -> List[Tuple[DFAS, int, RawNode]]:
+  """Nodeless stack copy."""
+  return [(dfa, label, DUMMY_NODE) for dfa, label, _ in stack]
+
+
+class Recorder:
+
+  def __init__(self, parser: 'Parser', ilabels: List[int],
+               context: Context) -> None:
+    self.parser = parser
+    self._ilabels = ilabels
+    self.context = context  # not really matter
+
+    self._dead_ilabels: Set[int] = set()
+    self._start_point = self.parser.stack
+    self._points = {ilabel: stack_copy(self._start_point) for ilabel in ilabels}
+
+  @property
+  def ilabels(self) -> Set[int]:
+    return self._dead_ilabels.symmetric_difference(self._ilabels)
+
+  @contextmanager
+  def switch_to(self, ilabel: int) -> Iterator[None]:
+    with self.backtrack():
+      self.parser.stack = self._points[ilabel]
+      try:
+        yield
+      except ParseError:
+        self._dead_ilabels.add(ilabel)
+      finally:
+        self.parser.stack = self._start_point
+
+  @contextmanager
+  def backtrack(self) -> Iterator[None]:
+    """
+        Use the node-level invariant ones for basic parsing operations (push/pop/shift).
+        These still will operate on the stack; but they won't create any new nodes, or
+        modify the contents of any other existing nodes.
+        This saves us a ton of time when we are backtracking, since we
+        want to restore to the initial state as quick as possible, which
+        can only be done by having as little mutatations as possible.
+        """  # noqa: E501
+    is_backtracking = self.parser.is_backtracking
+    try:
+      self.parser.is_backtracking = True
+      yield
+    finally:
+      self.parser.is_backtracking = is_backtracking
+
+  def add_token(self, tok_type: int, tok_val: Text, raw: bool = False) -> None:
+    func: Callable[..., Any]
+    if raw:
+      func = self.parser._addtoken
+    else:
+      func = self.parser.addtoken
+
+    for ilabel in self.ilabels:
+      with self.switch_to(ilabel):
+        args = [tok_type, tok_val, self.context]
+        if raw:
+          args.insert(0, ilabel)
+        func(*args)
+
+  def determine_route(self,
+                      value: Text = None,
+                      force: bool = False) -> Optional[int]:
+    alive_ilabels = self.ilabels
+    if len(alive_ilabels) == 0:
+      *_, most_successful_ilabel = self._dead_ilabels
+      raise ParseError('bad input', most_successful_ilabel, value, self.context)
+
+    ilabel, *rest = alive_ilabels
+    if force or not rest:
+      return ilabel
+    else:
+      return None
+
+
+class ParseError(Exception):
+  """Exception to signal the parser is stuck."""
+
+  def __init__(self, msg, type, value, context):
+    Exception.__init__(
+        self, '%s: type=%r, value=%r, context=%r' % (msg, type, value, context))
+    self.msg = msg
+    self.type = type
+    self.value = value
+    self.context = context
+
+  def __reduce__(self):
+    return type(self), (self.msg, self.type, self.value, self.context)
+
+
+class Parser(object):
+  """Parser engine.
+
+    The proper usage sequence is:
+
+    p = Parser(grammar, [converter])  # create instance
+    p.setup([start])                  # prepare for parsing
+    <for each input token>:
+        if p.addtoken(...):           # parse a token; may raise ParseError
+            break
+    root = p.rootnode                 # root of abstract syntax tree
+
+    A Parser instance may be reused by calling setup() repeatedly.
+
+    A Parser instance contains state pertaining to the current token
+    sequence, and should not be used concurrently by different threads
+    to parse separate token sequences.
+
+    See driver.py for how to get input tokens by tokenizing a file or
+    string.
+
+    Parsing is complete when addtoken() returns True; the root of the
+    abstract syntax tree can then be retrieved from the rootnode
+    instance variable.  When a syntax error occurs, addtoken() raises
+    the ParseError exception.  There is no error recovery; the parser
+    cannot be used after a syntax error was reported (but it can be
+    reinitialized by calling setup()).
+
+    """
+
+  def __init__(self, grammar, convert=None):
+    """Constructor.
+
+        The grammar argument is a grammar.Grammar instance; see the
+        grammar module for more information.
+
+        The parser is not ready yet for parsing; you must call the
+        setup() method to get it started.
+
+        The optional convert argument is a function mapping concrete
+        syntax tree nodes to abstract syntax tree nodes.  If not
+        given, no conversion is done and the syntax tree produced is
+        the concrete syntax tree.  If given, it must be a function of
+        two arguments, the first being the grammar (a grammar.Grammar
+        instance), and the second being the concrete syntax tree node
+        to be converted.  The syntax tree is converted from the bottom
+        up.
+
+        A concrete syntax tree node is a (type, value, context, nodes)
+        tuple, where type is the node type (a token or symbol number),
+        value is None for symbols and a string for tokens, context is
+        None or an opaque value used for error reporting (typically a
+        (lineno, offset) pair), and nodes is a list of children for
+        symbols, and None for tokens.
+
+        An abstract syntax tree node may be anything; this is entirely
+        up to the converter function.
+
+        """
+    self.grammar = grammar
+    self.convert = convert or (lambda grammar, node: node)
+    self.is_backtracking = False
+
+  def setup(self, proxy, start=None):
+    """Prepare for parsing.
+
+        This *must* be called before starting to parse.
+
+        The optional argument is an alternative start symbol; it
+        defaults to the grammar's start symbol.
+
+        You can use a Parser instance to parse any number of programs;
+        each time you call setup() the parser is reset to an initial
+        state determined by the (implicit or explicit) start symbol.
+
+        """
+    if start is None:
+      start = self.grammar.start
+    # Each stack entry is a tuple: (dfa, state, node).
+    # A node is a tuple: (type, value, context, children),
+    # where children is a list of nodes or None, and context may be None.
+    newnode = (start, None, None, [])
+    stackentry = (self.grammar.dfas[start], 0, newnode)
+    self.stack = [stackentry]
+    self.rootnode = None
+    self.used_names = set()  # Aliased to self.rootnode.used_names in pop()
+    self.proxy = proxy
+
+  def addtoken(self, type, value, context):
+    """Add a token; return True iff this is the end of the program."""
+    # Map from token to label
+    ilabels = self.classify(type, value, context)
+    assert len(ilabels) >= 1
+
+    # If we have only one state to advance, we'll directly
+    # take it as is.
+    if len(ilabels) == 1:
+      [ilabel] = ilabels
+      return self._addtoken(ilabel, type, value, context)
+
+    # If there are multiple states which we can advance (only
+    # happen under soft-keywords), then we will try all of them
+    # in parallel and as soon as one state can reach further than
+    # the rest, we'll choose that one. This is a pretty hacky
+    # and hopefully temporary algorithm.
+    #
+    # For a more detailed explanation, check out this post:
+    # https://tree.science/what-the-backtracking.html
+
+    with self.proxy.release() as proxy:
+      counter, force = 0, False
+      recorder = Recorder(self, ilabels, context)
+      recorder.add_token(type, value, raw=True)
+
+      next_token_value = value
+      while recorder.determine_route(next_token_value) is None:
+        if not proxy.can_advance(counter):
+          force = True
+          break
+
+        next_token_type, next_token_value, *_ = proxy.eat(counter)
+        if next_token_type in (tokenize.COMMENT, tokenize.NL):
+          counter += 1
+          continue
+
+        if next_token_type == tokenize.OP:
+          next_token_type = grammar.opmap[next_token_value]
+
+        recorder.add_token(next_token_type, next_token_value)
+        counter += 1
+
+      ilabel = cast(int,
+                    recorder.determine_route(next_token_value, force=force))
+      assert ilabel is not None
+
+    return self._addtoken(ilabel, type, value, context)
+
+  def _addtoken(self, ilabel: int, type: int, value: Text,
+                context: Context) -> bool:
+    # Loop until the token is shifted; may raise exceptions
+    while True:
+      dfa, state, node = self.stack[-1]
+      states, first = dfa
+      arcs = states[state]
+      # Look for a state with this label
+      for i, newstate in arcs:
+        t = self.grammar.labels[i][0]
+        if t >= 256:
+          # See if it's a symbol and if we're in its first set
+          itsdfa = self.grammar.dfas[t]
+          itsstates, itsfirst = itsdfa
+          if ilabel in itsfirst:
+            # Push a symbol
+            self.push(t, itsdfa, newstate, context)
+            break  # To continue the outer while loop
+
+        elif ilabel == i:
+          # Look it up in the list of labels
+          # Shift a token; we're done with it
+          self.shift(type, value, newstate, context)
+          # Pop while we are in an accept-only state
+          state = newstate
+          while states[state] == [(0, state)]:
+            self.pop()
+            if not self.stack:
+              # Done parsing!
+              return True
+            dfa, state, node = self.stack[-1]
+            states, first = dfa
+          # Done with this token
+          return False
+
+      else:
+        if (0, state) in arcs:
+          # An accepting state, pop it and try something else
+          self.pop()
+          if not self.stack:
+            # Done parsing, but another token is input
+            raise ParseError('too much input', type, value, context)
+        else:
+          # No success finding a transition
+          raise ParseError('bad input', type, value, context)
+
+  def classify(self, type, value, context):
+    """Turn a token into a label.  (Internal)
+
+        Depending on whether the value is a soft-keyword or not,
+        this function may return multiple labels to choose from."""
+    if type == token.NAME:
+      # Keep a listing of all used names
+      self.used_names.add(value)
+      # Check for reserved words
+      if value in self.grammar.keywords:
+        return [self.grammar.keywords[value]]
+      elif value in self.grammar.soft_keywords:
+        assert type in self.grammar.tokens
+        return [
+            self.grammar.soft_keywords[value],
+            self.grammar.tokens[type],
+        ]
+
+    ilabel = self.grammar.tokens.get(type)
+    if ilabel is None:
+      raise ParseError('bad token', type, value, context)
+    return [ilabel]
+
+  def shift(self, type: int, value: Text, newstate: int,
+            context: Context) -> None:
+    """Shift a token.  (Internal)"""
+    if self.is_backtracking:
+      dfa, state, _ = self.stack[-1]
+      self.stack[-1] = (dfa, newstate, DUMMY_NODE)
+    else:
+      dfa, state, node = self.stack[-1]
+      rawnode: RawNode = (type, value, context, None)
+      newnode = convert(self.grammar, rawnode)
+      assert node[-1] is not None
+      node[-1].append(newnode)
+      self.stack[-1] = (dfa, newstate, node)
+
+  def push(self, type: int, newdfa: DFAS, newstate: int,
+           context: Context) -> None:
+    """Push a nonterminal.  (Internal)"""
+    if self.is_backtracking:
+      dfa, state, _ = self.stack[-1]
+      self.stack[-1] = (dfa, newstate, DUMMY_NODE)
+      self.stack.append((newdfa, 0, DUMMY_NODE))
+    else:
+      dfa, state, node = self.stack[-1]
+      newnode: RawNode = (type, None, context, [])
+      self.stack[-1] = (dfa, newstate, node)
+      self.stack.append((newdfa, 0, newnode))
+
+  def pop(self) -> None:
+    """Pop a nonterminal.  (Internal)"""
+    if self.is_backtracking:
+      self.stack.pop()
+    else:
+      popdfa, popstate, popnode = self.stack.pop()
+      newnode = convert(self.grammar, popnode)
+      if self.stack:
+        dfa, state, node = self.stack[-1]
+        assert node[-1] is not None
+        node[-1].append(newnode)
+      else:
+        self.rootnode = newnode
+        self.rootnode.used_names = self.used_names
diff --git a/third_party/yapf_third_party/_ylib2to3/pgen2/pgen.py b/third_party/yapf_third_party/_ylib2to3/pgen2/pgen.py
new file mode 100644
index 0000000..6b96478
--- /dev/null
+++ b/third_party/yapf_third_party/_ylib2to3/pgen2/pgen.py
@@ -0,0 +1,409 @@
+# Copyright 2004-2005 Elemental Security, Inc. All Rights Reserved.
+# Licensed to PSF under a Contributor Agreement.
+
+# Pgen imports
+from io import StringIO
+
+from . import grammar
+from . import token
+from . import tokenize
+
+
+class PgenGrammar(grammar.Grammar):
+  pass
+
+
+class ParserGenerator(object):
+
+  def __init__(self, filename=None, stream=None):
+    close_stream = None
+    if filename is None and stream is None:
+      raise RuntimeError(
+          'Either a filename or a stream is expected, both were none')
+    if stream is None:
+      stream = open(filename, encoding='utf-8')
+      close_stream = stream.close
+    self.filename = filename
+    self.stream = stream
+    self.generator = tokenize.generate_tokens(stream.readline)
+    self.gettoken()  # Initialize lookahead
+    self.dfas, self.startsymbol = self.parse()
+    if close_stream is not None:
+      close_stream()
+    self.first = {}  # map from symbol name to set of tokens
+    self.addfirstsets()
+
+  def make_grammar(self):
+    c = PgenGrammar()
+    names = list(self.dfas.keys())
+    names.sort()
+    names.remove(self.startsymbol)
+    names.insert(0, self.startsymbol)
+    for name in names:
+      i = 256 + len(c.symbol2number)
+      c.symbol2number[name] = i
+      c.number2symbol[i] = name
+    for name in names:
+      dfa = self.dfas[name]
+      states = []
+      for state in dfa:
+        arcs = []
+        for label, next in sorted(state.arcs.items()):
+          arcs.append((self.make_label(c, label), dfa.index(next)))
+        if state.isfinal:
+          arcs.append((0, dfa.index(state)))
+        states.append(arcs)
+      c.states.append(states)
+      c.dfas[c.symbol2number[name]] = (states, self.make_first(c, name))
+    c.start = c.symbol2number[self.startsymbol]
+    return c
+
+  def make_first(self, c, name):
+    rawfirst = self.first[name]
+    first = {}
+    for label in sorted(rawfirst):
+      ilabel = self.make_label(c, label)
+      # assert ilabel not in first # XXX failed on <> ... !=
+      first[ilabel] = 1
+    return first
+
+  def make_label(self, c, label):
+    # XXX Maybe this should be a method on a subclass of converter?
+    ilabel = len(c.labels)
+    if label[0].isalpha():
+      # Either a symbol name or a named token
+      if label in c.symbol2number:
+        # A symbol name (a non-terminal)
+        if label in c.symbol2label:
+          return c.symbol2label[label]
+        else:
+          c.labels.append((c.symbol2number[label], None))
+          c.symbol2label[label] = ilabel
+          return ilabel
+      else:
+        # A named token (NAME, NUMBER, STRING)
+        itoken = getattr(token, label, None)
+        assert isinstance(itoken, int), label
+        assert itoken in token.tok_name, label
+        if itoken in c.tokens:
+          return c.tokens[itoken]
+        else:
+          c.labels.append((itoken, None))
+          c.tokens[itoken] = ilabel
+          return ilabel
+    else:
+      # Either a keyword or an operator
+      assert label[0] in ('"', "'"), label
+      value = eval(label)
+      if value[0].isalpha():
+        if label[0] == '"':
+          keywords = c.soft_keywords
+        else:
+          keywords = c.keywords
+
+        # A keyword
+        if value in keywords:
+          return keywords[value]
+        else:
+          c.labels.append((token.NAME, value))
+          keywords[value] = ilabel
+          return ilabel
+      else:
+        # An operator (any non-numeric token)
+        itoken = grammar.opmap[value]  # Fails if unknown token
+        if itoken in c.tokens:
+          return c.tokens[itoken]
+        else:
+          c.labels.append((itoken, None))
+          c.tokens[itoken] = ilabel
+          return ilabel
+
+  def addfirstsets(self):
+    names = list(self.dfas.keys())
+    names.sort()
+    for name in names:
+      if name not in self.first:
+        self.calcfirst(name)
+      # print name, self.first[name].keys()
+
+  def calcfirst(self, name):
+    dfa = self.dfas[name]
+    self.first[name] = None  # dummy to detect left recursion
+    state = dfa[0]
+    totalset = {}
+    overlapcheck = {}
+    for label, next in state.arcs.items():
+      if label in self.dfas:
+        if label in self.first:
+          fset = self.first[label]
+          if fset is None:
+            raise ValueError('recursion for rule %r' % name)
+        else:
+          self.calcfirst(label)
+          fset = self.first[label]
+        totalset.update(fset)
+        overlapcheck[label] = fset
+      else:
+        totalset[label] = 1
+        overlapcheck[label] = {label: 1}
+    inverse = {}
+    for label, itsfirst in overlapcheck.items():
+      for symbol in itsfirst:
+        if symbol in inverse:
+          raise ValueError('rule %s is ambiguous; %s is in the'
+                           ' first sets of %s as well as %s' %
+                           (name, symbol, label, inverse[symbol]))
+        inverse[symbol] = label
+    self.first[name] = totalset
+
+  def parse(self):
+    dfas = {}
+    startsymbol = None
+    # MSTART: (NEWLINE | RULE)* ENDMARKER
+    while self.type != token.ENDMARKER:
+      while self.type == token.NEWLINE:
+        self.gettoken()
+      # RULE: NAME ':' RHS NEWLINE
+      name = self.expect(token.NAME)
+      self.expect(token.OP, ':')
+      a, z = self.parse_rhs()
+      self.expect(token.NEWLINE)
+      # self.dump_nfa(name, a, z)
+      dfa = self.make_dfa(a, z)
+      # self.dump_dfa(name, dfa)
+      self.simplify_dfa(dfa)
+      dfas[name] = dfa
+      # print name, oldlen, newlen
+      if startsymbol is None:
+        startsymbol = name
+    return dfas, startsymbol
+
+  def make_dfa(self, start, finish):
+    # To turn an NFA into a DFA, we define the states of the DFA
+    # to correspond to *sets* of states of the NFA.  Then do some
+    # state reduction.  Let's represent sets as dicts with 1 for
+    # values.
+    assert isinstance(start, NFAState)
+    assert isinstance(finish, NFAState)
+
+    def closure(state):
+      base = {}
+      addclosure(state, base)
+      return base
+
+    def addclosure(state, base):
+      assert isinstance(state, NFAState)
+      if state in base:
+        return
+      base[state] = 1
+      for label, next in state.arcs:
+        if label is None:
+          addclosure(next, base)
+
+    states = [DFAState(closure(start), finish)]
+    for state in states:  # NB states grows while we're iterating
+      arcs = {}
+      for nfastate in state.nfaset:
+        for label, next in nfastate.arcs:
+          if label is not None:
+            addclosure(next, arcs.setdefault(label, {}))
+      for label, nfaset in sorted(arcs.items()):
+        for st in states:
+          if st.nfaset == nfaset:
+            break
+        else:
+          st = DFAState(nfaset, finish)
+          states.append(st)
+        state.addarc(st, label)
+    return states  # List of DFAState instances; first one is start
+
+  def dump_nfa(self, name, start, finish):
+    print('Dump of NFA for', name)
+    todo = [start]
+    for i, state in enumerate(todo):
+      print('  State', i, state is finish and '(final)' or '')
+      for label, next in state.arcs:
+        if next in todo:
+          j = todo.index(next)
+        else:
+          j = len(todo)
+          todo.append(next)
+        if label is None:
+          print('    -> %d' % j)
+        else:
+          print('    %s -> %d' % (label, j))
+
+  def dump_dfa(self, name, dfa):
+    print('Dump of DFA for', name)
+    for i, state in enumerate(dfa):
+      print('  State', i, state.isfinal and '(final)' or '')
+      for label, next in sorted(state.arcs.items()):
+        print('    %s -> %d' % (label, dfa.index(next)))
+
+  def simplify_dfa(self, dfa):
+    # This is not theoretically optimal, but works well enough.
+    # Algorithm: repeatedly look for two states that have the same
+    # set of arcs (same labels pointing to the same nodes) and
+    # unify them, until things stop changing.
+
+    # dfa is a list of DFAState instances
+    changes = True
+    while changes:
+      changes = False
+      for i, state_i in enumerate(dfa):
+        for j in range(i + 1, len(dfa)):
+          state_j = dfa[j]
+          if state_i == state_j:
+            # print "  unify", i, j
+            del dfa[j]
+            for state in dfa:
+              state.unifystate(state_j, state_i)
+            changes = True
+            break
+
+  def parse_rhs(self):
+    # RHS: ALT ('|' ALT)*
+    a, z = self.parse_alt()
+    if self.value != '|':
+      return a, z
+    else:
+      aa = NFAState()
+      zz = NFAState()
+      aa.addarc(a)
+      z.addarc(zz)
+      while self.value == '|':
+        self.gettoken()
+        a, z = self.parse_alt()
+        aa.addarc(a)
+        z.addarc(zz)
+      return aa, zz
+
+  def parse_alt(self):
+    # ALT: ITEM+
+    a, b = self.parse_item()
+    while (self.value in ('(', '[') or self.type in (token.NAME, token.STRING)):
+      c, d = self.parse_item()
+      b.addarc(c)
+      b = d
+    return a, b
+
+  def parse_item(self):
+    # ITEM: '[' RHS ']' | ATOM ['+' | '*']
+    if self.value == '[':
+      self.gettoken()
+      a, z = self.parse_rhs()
+      self.expect(token.OP, ']')
+      a.addarc(z)
+      return a, z
+    else:
+      a, z = self.parse_atom()
+      value = self.value
+      if value not in ('+', '*'):
+        return a, z
+      self.gettoken()
+      z.addarc(a)
+      if value == '+':
+        return a, z
+      else:
+        return a, a
+
+  def parse_atom(self):
+    # ATOM: '(' RHS ')' | NAME | STRING
+    if self.value == '(':
+      self.gettoken()
+      a, z = self.parse_rhs()
+      self.expect(token.OP, ')')
+      return a, z
+    elif self.type in (token.NAME, token.STRING):
+      a = NFAState()
+      z = NFAState()
+      a.addarc(z, self.value)
+      self.gettoken()
+      return a, z
+    else:
+      self.raise_error('expected (...) or NAME or STRING, got %s/%s', self.type,
+                       self.value)
+
+  def expect(self, type, value=None):
+    if self.type != type or (value is not None and self.value != value):
+      self.raise_error('expected %s/%s, got %s/%s', type, value, self.type,
+                       self.value)
+    value = self.value
+    self.gettoken()
+    return value
+
+  def gettoken(self):
+    tup = next(self.generator)
+    while tup[0] in (tokenize.COMMENT, tokenize.NL):
+      tup = next(self.generator)
+    self.type, self.value, self.begin, self.end, self.line = tup
+    # print token.tok_name[self.type], repr(self.value)
+
+  def raise_error(self, msg, *args):
+    if args:
+      try:
+        msg = msg % args
+      except Exception:
+        msg = ' '.join([msg] + list(map(str, args)))
+    raise SyntaxError(msg, (self.filename, self.end[0], self.end[1], self.line))
+
+
+class NFAState(object):
+
+  def __init__(self):
+    self.arcs = []  # list of (label, NFAState) pairs
+
+  def addarc(self, next, label=None):
+    assert label is None or isinstance(label, str)
+    assert isinstance(next, NFAState)
+    self.arcs.append((label, next))
+
+
+class DFAState(object):
+
+  def __init__(self, nfaset, final):
+    assert isinstance(nfaset, dict)
+    assert isinstance(next(iter(nfaset)), NFAState)
+    assert isinstance(final, NFAState)
+    self.nfaset = nfaset
+    self.isfinal = final in nfaset
+    self.arcs = {}  # map from label to DFAState
+
+  def addarc(self, next, label):
+    assert isinstance(label, str)
+    assert label not in self.arcs
+    assert isinstance(next, DFAState)
+    self.arcs[label] = next
+
+  def unifystate(self, old, new):
+    for label, next in self.arcs.items():
+      if next is old:
+        self.arcs[label] = new
+
+  def __eq__(self, other):
+    # Equality test -- ignore the nfaset instance variable
+    assert isinstance(other, DFAState)
+    if self.isfinal != other.isfinal:
+      return False
+    # Can't just return self.arcs == other.arcs, because that
+    # would invoke this method recursively, with cycles...
+    if len(self.arcs) != len(other.arcs):
+      return False
+    for label, next in self.arcs.items():
+      if next is not other.arcs.get(label):
+        return False
+    return True
+
+  __hash__ = None  # For Py3 compatibility.
+
+
+def generate_grammar(filename_or_stream='Grammar.txt'):
+  # type:(str | StringIO) -> PgenGrammar
+  if isinstance(filename_or_stream, str):
+    p = ParserGenerator(filename_or_stream)
+  elif isinstance(filename_or_stream, StringIO):
+    p = ParserGenerator(stream=filename_or_stream)
+  else:
+    raise NotImplementedError('Type %s not implemented' %
+                              type(filename_or_stream))
+  return p.make_grammar()
diff --git a/third_party/yapf_third_party/_ylib2to3/pgen2/token.py b/third_party/yapf_third_party/_ylib2to3/pgen2/token.py
new file mode 100644
index 0000000..fbcd155
--- /dev/null
+++ b/third_party/yapf_third_party/_ylib2to3/pgen2/token.py
@@ -0,0 +1,88 @@
+#! /usr/bin/env python3
+"""Token constants (from "token.h")."""
+
+#  Taken from Python (r53757) and modified to include some tokens
+#   originally monkeypatched in by pgen2.tokenize
+
+# --start constants--
+ENDMARKER = 0
+NAME = 1
+NUMBER = 2
+STRING = 3
+NEWLINE = 4
+INDENT = 5
+DEDENT = 6
+LPAR = 7
+RPAR = 8
+LSQB = 9
+RSQB = 10
+COLON = 11
+COMMA = 12
+SEMI = 13
+PLUS = 14
+MINUS = 15
+STAR = 16
+SLASH = 17
+VBAR = 18
+AMPER = 19
+LESS = 20
+GREATER = 21
+EQUAL = 22
+DOT = 23
+PERCENT = 24
+BACKQUOTE = 25
+LBRACE = 26
+RBRACE = 27
+EQEQUAL = 28
+NOTEQUAL = 29
+LESSEQUAL = 30
+GREATEREQUAL = 31
+TILDE = 32
+CIRCUMFLEX = 33
+LEFTSHIFT = 34
+RIGHTSHIFT = 35
+DOUBLESTAR = 36
+PLUSEQUAL = 37
+MINEQUAL = 38
+STAREQUAL = 39
+SLASHEQUAL = 40
+PERCENTEQUAL = 41
+AMPEREQUAL = 42
+VBAREQUAL = 43
+CIRCUMFLEXEQUAL = 44
+LEFTSHIFTEQUAL = 45
+RIGHTSHIFTEQUAL = 46
+DOUBLESTAREQUAL = 47
+DOUBLESLASH = 48
+DOUBLESLASHEQUAL = 49
+AT = 50
+ATEQUAL = 51
+OP = 52
+COMMENT = 53
+NL = 54
+RARROW = 55
+AWAIT = 56
+ASYNC = 57
+ERRORTOKEN = 58
+COLONEQUAL = 59
+N_TOKENS = 60
+NT_OFFSET = 256
+# --end constants--
+
+tok_name = {
+    _value: _name
+    for _name, _value in globals().copy().items()
+    if isinstance(_value, int)
+}
+
+
+def ISTERMINAL(x):
+  return x < NT_OFFSET
+
+
+def ISNONTERMINAL(x):
+  return x >= NT_OFFSET
+
+
+def ISEOF(x):
+  return x == ENDMARKER
diff --git a/third_party/yapf_third_party/_ylib2to3/pgen2/tokenize.py b/third_party/yapf_third_party/_ylib2to3/pgen2/tokenize.py
new file mode 100644
index 0000000..dda8329
--- /dev/null
+++ b/third_party/yapf_third_party/_ylib2to3/pgen2/tokenize.py
@@ -0,0 +1,611 @@
+# Copyright (c) 2001, 2002, 2003, 2004, 2005, 2006 Python Software Foundation.
+# All rights reserved.
+"""Tokenization help for Python programs.
+
+generate_tokens(readline) is a generator that breaks a stream of
+text into Python tokens.  It accepts a readline-like method which is called
+repeatedly to get the next line of input (or "" for EOF).  It generates
+5-tuples with these members:
+
+    the token type (see token.py)
+    the token (a string)
+    the starting (row, column) indices of the token (a 2-tuple of ints)
+    the ending (row, column) indices of the token (a 2-tuple of ints)
+    the original line (string)
+
+It is designed to match the working of the Python tokenizer exactly, except
+that it produces COMMENT tokens for comments and gives type OP for all
+operators
+
+Older entry points
+    tokenize_loop(readline, tokeneater)
+    tokenize(readline, tokeneater=printtoken)
+are the same, except instead of generating tokens, tokeneater is a callback
+function to which the 5 fields described above are passed as 5 arguments,
+each time a new token is found."""
+
+__author__ = 'Ka-Ping Yee <ping@lfw.org>'
+__credits__ = \
+    'GvR, ESR, Tim Peters, Thomas Wouters, Fred Drake, Skip Montanaro'
+
+import re
+import string
+from codecs import BOM_UTF8
+from codecs import lookup
+
+from . import token
+from .token import ASYNC
+from .token import AWAIT
+from .token import COMMENT
+from .token import DEDENT
+from .token import ENDMARKER
+from .token import ERRORTOKEN
+from .token import INDENT
+from .token import NAME
+from .token import NEWLINE
+from .token import NL
+from .token import NUMBER
+from .token import OP
+from .token import STRING
+from .token import tok_name
+
+__all__ = [x for x in dir(token) if x[0] != '_'
+          ] + ['tokenize', 'generate_tokens', 'untokenize']
+del token
+
+try:
+  bytes
+except NameError:
+  # Support bytes type in Python <= 2.5, so 2to3 turns itself into
+  # valid Python 3 code.
+  bytes = str
+
+
+def group(*choices):
+  return '(' + '|'.join(choices) + ')'
+
+
+def any(*choices):
+  return group(*choices) + '*'
+
+
+def maybe(*choices):
+  return group(*choices) + '?'
+
+
+def _combinations(*l):  # noqa: E741
+  return set(
+      x + y for x in l for y in l + ('',) if x.casefold() != y.casefold())
+
+
+Whitespace = r'[ \f\t]*'
+Comment = r'#[^\r\n]*'
+Ignore = Whitespace + any(r'\\\r?\n' + Whitespace) + maybe(Comment)
+Name = r'\w+'
+
+Binnumber = r'0[bB]_?[01]+(?:_[01]+)*'
+Hexnumber = r'0[xX]_?[\da-fA-F]+(?:_[\da-fA-F]+)*[lL]?'
+Octnumber = r'0[oO]?_?[0-7]+(?:_[0-7]+)*[lL]?'
+Decnumber = group(r'[1-9]\d*(?:_\d+)*[lL]?', '0[lL]?')
+Intnumber = group(Binnumber, Hexnumber, Octnumber, Decnumber)
+Exponent = r'[eE][-+]?\d+(?:_\d+)*'
+Pointfloat = group(r'\d+(?:_\d+)*\.(?:\d+(?:_\d+)*)?',
+                   r'\.\d+(?:_\d+)*') + maybe(Exponent)
+Expfloat = r'\d+(?:_\d+)*' + Exponent
+Floatnumber = group(Pointfloat, Expfloat)
+Imagnumber = group(r'\d+(?:_\d+)*[jJ]', Floatnumber + r'[jJ]')
+Number = group(Imagnumber, Floatnumber, Intnumber)
+
+# Tail end of ' string.
+Single = r"[^'\\]*(?:\\.[^'\\]*)*'"
+# Tail end of " string.
+Double = r'[^"\\]*(?:\\.[^"\\]*)*"'
+# Tail end of ''' string.
+Single3 = r"[^'\\]*(?:(?:\\.|'(?!''))[^'\\]*)*'''"
+# Tail end of """ string.
+Double3 = r'[^"\\]*(?:(?:\\.|"(?!""))[^"\\]*)*"""'
+_litprefix = r'(?:[uUrRbBfF]|[rR][fFbB]|[fFbBuU][rR])?'
+Triple = group(_litprefix + "'''", _litprefix + '"""')
+# Single-line ' or " string.
+String = group(_litprefix + r"'[^\n'\\]*(?:\\.[^\n'\\]*)*'",
+               _litprefix + r'"[^\n"\\]*(?:\\.[^\n"\\]*)*"')
+
+# Because of leftmost-then-longest match semantics, be sure to put the
+# longest operators first (e.g., if = came before ==, == would get
+# recognized as two instances of =).
+Operator = group(r'\*\*=?', r'>>=?', r'<<=?', r'<>', r'!=', r'//=?', r'->',
+                 r'[+\-*/%&@|^=<>]=?', r'~')
+
+Bracket = '[][(){}]'
+Special = group(r'\r?\n', r':=', r'[:;.,`@]')
+Funny = group(Operator, Bracket, Special)
+
+PlainToken = group(Number, Funny, String, Name)
+Token = Ignore + PlainToken
+
+# First (or only) line of ' or " string.
+ContStr = group(
+    _litprefix + r"'[^\n'\\]*(?:\\.[^\n'\\]*)*" + group("'", r'\\\r?\n'),
+    _litprefix + r'"[^\n"\\]*(?:\\.[^\n"\\]*)*' + group('"', r'\\\r?\n'))
+PseudoExtras = group(r'\\\r?\n', Comment, Triple)
+PseudoToken = Whitespace + group(PseudoExtras, Number, Funny, ContStr, Name)
+
+tokenprog, pseudoprog, single3prog, double3prog = map(
+    re.compile, (Token, PseudoToken, Single3, Double3))
+
+_strprefixes = (
+    _combinations('r', 'R', 'f', 'F') | _combinations('r', 'R', 'b', 'B')
+    | {'u', 'U', 'ur', 'uR', 'Ur', 'UR'})
+
+endprogs = {
+    "'": re.compile(Single),
+    '"': re.compile(Double),
+    "'''": single3prog,
+    '"""': double3prog,
+    **{
+        f"{prefix}'''": single3prog for prefix in _strprefixes
+    },
+    **{
+        f'{prefix}"""': double3prog for prefix in _strprefixes
+    },
+    **{
+        prefix: None for prefix in _strprefixes
+    }
+}
+
+triple_quoted = ({"'''", '"""'} | {f"{prefix}'''" for prefix in _strprefixes}
+                 | {f'{prefix}"""' for prefix in _strprefixes})
+single_quoted = ({"'", '"'} | {f"{prefix}'" for prefix in _strprefixes}
+                 | {f'{prefix}"' for prefix in _strprefixes})
+
+tabsize = 8
+
+
+class TokenError(Exception):
+  pass
+
+
+class StopTokenizing(Exception):
+  pass
+
+
+def printtoken(type, token, xxx_todo_changeme, xxx_todo_changeme1,
+               line):  # for testing
+  (srow, scol) = xxx_todo_changeme
+  (erow, ecol) = xxx_todo_changeme1
+  print('%d,%d-%d,%d:\t%s\t%s' %
+        (srow, scol, erow, ecol, tok_name[type], repr(token)))
+
+
+def tokenize(readline, tokeneater=printtoken):
+  """
+    The tokenize() function accepts two parameters: one representing the
+    input stream, and one providing an output mechanism for tokenize().
+
+    The first parameter, readline, must be a callable object which provides
+    the same interface as the readline() method of built-in file objects.
+    Each call to the function should return one line of input as a string.
+
+    The second parameter, tokeneater, must also be a callable object. It is
+    called once for each token, with five arguments, corresponding to the
+    tuples generated by generate_tokens().
+    """
+  try:
+    tokenize_loop(readline, tokeneater)
+  except StopTokenizing:
+    pass
+
+
+# backwards compatible interface
+def tokenize_loop(readline, tokeneater):
+  for token_info in generate_tokens(readline):
+    tokeneater(*token_info)
+
+
+class Untokenizer:
+
+  def __init__(self):
+    self.tokens = []
+    self.prev_row = 1
+    self.prev_col = 0
+
+  def add_whitespace(self, start):
+    row, col = start
+    assert row <= self.prev_row
+    col_offset = col - self.prev_col
+    if col_offset:
+      self.tokens.append(' ' * col_offset)
+
+  def untokenize(self, iterable):
+    for t in iterable:
+      if len(t) == 2:
+        self.compat(t, iterable)
+        break
+      tok_type, token, start, end, line = t
+      self.add_whitespace(start)
+      self.tokens.append(token)
+      self.prev_row, self.prev_col = end
+      if tok_type in (NEWLINE, NL):
+        self.prev_row += 1
+        self.prev_col = 0
+    return ''.join(self.tokens)
+
+  def compat(self, token, iterable):
+    startline = False
+    indents = []
+    toks_append = self.tokens.append
+    toknum, tokval = token
+    if toknum in (NAME, NUMBER):
+      tokval += ' '
+    if toknum in (NEWLINE, NL):
+      startline = True
+    for tok in iterable:
+      toknum, tokval = tok[:2]
+
+      if toknum in (NAME, NUMBER, ASYNC, AWAIT):
+        tokval += ' '
+
+      if toknum == INDENT:
+        indents.append(tokval)
+        continue
+      elif toknum == DEDENT:
+        indents.pop()
+        continue
+      elif toknum in (NEWLINE, NL):
+        startline = True
+      elif startline and indents:
+        toks_append(indents[-1])
+        startline = False
+      toks_append(tokval)
+
+
+cookie_re = re.compile(r'^[ \t\f]*#.*?coding[:=][ \t]*([-\w.]+)', re.ASCII)
+blank_re = re.compile(br'^[ \t\f]*(?:[#\r\n]|$)', re.ASCII)
+
+
+def _get_normal_name(orig_enc):
+  """Imitates get_normal_name in tokenizer.c."""
+  # Only care about the first 12 characters.
+  enc = orig_enc[:12].lower().replace('_', '-')
+  if enc == 'utf-8' or enc.startswith('utf-8-'):
+    return 'utf-8'
+  if enc in ('latin-1', 'iso-8859-1', 'iso-latin-1') or \
+     enc.startswith(('latin-1-', 'iso-8859-1-', 'iso-latin-1-')):
+    return 'iso-8859-1'
+  return orig_enc
+
+
+def detect_encoding(readline):
+  """
+    The detect_encoding() function is used to detect the encoding that should
+    be used to decode a Python source file. It requires one argument, readline,
+    in the same way as the tokenize() generator.
+
+    It will call readline a maximum of twice, and return the encoding used
+    (as a string) and a list of any lines (left as bytes) it has read
+    in.
+
+    It detects the encoding from the presence of a utf-8 bom or an encoding
+    cookie as specified in pep-0263. If both a bom and a cookie are present, but
+    disagree, a SyntaxError will be raised. If the encoding cookie is an invalid
+    charset, raise a SyntaxError.  Note that if a utf-8 bom is found,
+    'utf-8-sig' is returned.
+
+    If no encoding is specified, then the default of 'utf-8' will be returned.
+    """
+  bom_found = False
+  encoding = None
+  default = 'utf-8'
+
+  def read_or_stop():
+    try:
+      return readline()
+    except StopIteration:
+      return bytes()
+
+  def find_cookie(line):
+    try:
+      line_string = line.decode('ascii')
+    except UnicodeDecodeError:
+      return None
+    match = cookie_re.match(line_string)
+    if not match:
+      return None
+    encoding = _get_normal_name(match.group(1))
+    try:
+      codec = lookup(encoding)
+    except LookupError:
+      # This behaviour mimics the Python interpreter
+      raise SyntaxError('unknown encoding: ' + encoding)
+
+    if bom_found:
+      if codec.name != 'utf-8':
+        # This behaviour mimics the Python interpreter
+        raise SyntaxError('encoding problem: utf-8')
+      encoding += '-sig'
+    return encoding
+
+  first = read_or_stop()
+  if first.startswith(BOM_UTF8):
+    bom_found = True
+    first = first[3:]
+    default = 'utf-8-sig'
+  if not first:
+    return default, []
+
+  encoding = find_cookie(first)
+  if encoding:
+    return encoding, [first]
+  if not blank_re.match(first):
+    return default, [first]
+
+  second = read_or_stop()
+  if not second:
+    return default, [first]
+
+  encoding = find_cookie(second)
+  if encoding:
+    return encoding, [first, second]
+
+  return default, [first, second]
+
+
+def untokenize(iterable):
+  """Transform tokens back into Python source code.
+
+    Each element returned by the iterable must be a token sequence
+    with at least two elements, a token number and token value.  If
+    only two tokens are passed, the resulting output is poor.
+
+    Round-trip invariant for full input:
+        Untokenized source will match input source exactly
+
+    Round-trip invariant for limited input:
+        # Output text will tokenize the back to the input
+        t1 = [tok[:2] for tok in generate_tokens(f.readline)]
+        newcode = untokenize(t1)
+        readline = iter(newcode.splitlines(1)).next
+        t2 = [tok[:2] for tokin generate_tokens(readline)]
+        assert t1 == t2
+    """
+  ut = Untokenizer()
+  return ut.untokenize(iterable)
+
+
+def generate_tokens(readline):
+  """
+    The generate_tokens() generator requires one argument, readline, which
+    must be a callable object which provides the same interface as the
+    readline() method of built-in file objects. Each call to the function
+    should return one line of input as a string.  Alternately, readline
+    can be a callable function terminating with StopIteration:
+        readline = open(myfile).next    # Example of alternate readline
+
+    The generator produces 5-tuples with these members: the token type; the
+    token string; a 2-tuple (srow, scol) of ints specifying the row and
+    column where the token begins in the source; a 2-tuple (erow, ecol) of
+    ints specifying the row and column where the token ends in the source;
+    and the line on which the token was found. The line passed is the
+    physical line.
+    """
+  strstart = ''
+  endprog = ''
+  lnum = parenlev = continued = 0
+  contstr, needcont = '', 0
+  contline = None
+  indents = [0]
+
+  # 'stashed' and 'async_*' are used for async/await parsing
+  stashed = None
+  async_def = False
+  async_def_indent = 0
+  async_def_nl = False
+
+  while 1:  # loop over lines in stream
+    try:
+      line = readline()
+    except StopIteration:
+      line = ''
+    lnum = lnum + 1
+    pos, max = 0, len(line)
+
+    if contstr:  # continued string
+      if not line:
+        raise TokenError('EOF in multi-line string', strstart)
+      endmatch = endprog.match(line)
+      if endmatch:
+        pos = end = endmatch.end(0)
+        yield (STRING, contstr + line[:end], strstart, (lnum, end),
+               contline + line)
+        contstr, needcont = '', 0
+        contline = None
+      elif needcont and line[-2:] != '\\\n' and line[-3:] != '\\\r\n':
+        yield (ERRORTOKEN, contstr + line, strstart, (lnum, len(line)),
+               contline)
+        contstr = ''
+        contline = None
+        continue
+      else:
+        contstr = contstr + line
+        contline = contline + line
+        continue
+
+    elif parenlev == 0 and not continued:  # new statement
+      if not line:
+        break
+      column = 0
+      while pos < max:  # measure leading whitespace
+        if line[pos] == ' ':
+          column = column + 1
+        elif line[pos] == '\t':
+          column = (column // tabsize + 1) * tabsize
+        elif line[pos] == '\f':
+          column = 0
+        else:
+          break
+        pos = pos + 1
+      if pos == max:
+        break
+
+      if stashed:
+        yield stashed
+        stashed = None
+
+      if line[pos] in '#\r\n':  # skip comments or blank lines
+        if line[pos] == '#':
+          comment_token = line[pos:].rstrip('\r\n')
+          nl_pos = pos + len(comment_token)
+          yield (COMMENT, comment_token, (lnum, pos),
+                 (lnum, pos + len(comment_token)), line)
+          yield (NL, line[nl_pos:], (lnum, nl_pos), (lnum, len(line)), line)
+        else:
+          yield ((NL, COMMENT)[line[pos] == '#'], line[pos:], (lnum, pos),
+                 (lnum, len(line)), line)
+        continue
+
+      if column > indents[-1]:  # count indents or dedents
+        indents.append(column)
+        yield (INDENT, line[:pos], (lnum, 0), (lnum, pos), line)
+      while column < indents[-1]:
+        if column not in indents:
+          raise IndentationError(
+              'unindent does not match any outer indentation level',
+              ('<tokenize>', lnum, pos, line))
+        indents = indents[:-1]
+
+        if async_def and async_def_indent >= indents[-1]:
+          async_def = False
+          async_def_nl = False
+          async_def_indent = 0
+
+        yield (DEDENT, '', (lnum, pos), (lnum, pos), line)
+
+      if async_def and async_def_nl and async_def_indent >= indents[-1]:
+        async_def = False
+        async_def_nl = False
+        async_def_indent = 0
+
+    else:  # continued statement
+      if not line:
+        raise TokenError('EOF in multi-line statement', (lnum, 0))
+      continued = 0
+
+    while pos < max:
+      pseudomatch = pseudoprog.match(line, pos)
+      if pseudomatch:  # scan for tokens
+        start, end = pseudomatch.span(1)
+        spos, epos, pos = (lnum, start), (lnum, end), end
+        token, initial = line[start:end], line[start]
+
+        if initial in string.digits or \
+           (initial == '.' and token != '.'):      # ordinary number
+          yield (NUMBER, token, spos, epos, line)
+        elif initial in '\r\n':
+          newline = NEWLINE
+          if parenlev > 0:
+            newline = NL
+          elif async_def:
+            async_def_nl = True
+          if stashed:
+            yield stashed
+            stashed = None
+          yield (newline, token, spos, epos, line)
+
+        elif initial == '#':
+          assert not token.endswith('\n')
+          if stashed:
+            yield stashed
+            stashed = None
+          yield (COMMENT, token, spos, epos, line)
+        elif token in triple_quoted:
+          endprog = endprogs[token]
+          endmatch = endprog.match(line, pos)
+          if endmatch:  # all on one line
+            pos = endmatch.end(0)
+            token = line[start:pos]
+            if stashed:
+              yield stashed
+              stashed = None
+            yield (STRING, token, spos, (lnum, pos), line)
+          else:
+            strstart = (lnum, start)  # multiple lines
+            contstr = line[start:]
+            contline = line
+            break
+        elif initial in single_quoted or \
+            token[:2] in single_quoted or \
+            token[:3] in single_quoted:
+          if token[-1] == '\n':  # continued string
+            strstart = (lnum, start)  # noqa: F841
+            endprog = (
+                endprogs[initial] or endprogs[token[1]] or endprogs[token[2]])
+            contstr, needcont = line[start:], 1
+            contline = line
+            break
+          else:  # ordinary string
+            if stashed:
+              yield stashed
+              stashed = None
+            yield (STRING, token, spos, epos, line)
+        elif initial.isidentifier():  # ordinary name
+          if token in ('async', 'await'):
+            if async_def:
+              yield (ASYNC if token == 'async' else AWAIT, token, spos, epos,
+                     line)
+              continue
+
+          tok = (NAME, token, spos, epos, line)
+          if token == 'async' and not stashed:
+            stashed = tok
+            continue
+
+          if token in ('def', 'for'):
+            if (stashed and stashed[0] == NAME and stashed[1] == 'async'):
+
+              if token == 'def':
+                async_def = True
+                async_def_indent = indents[-1]
+
+              yield (ASYNC, stashed[1], stashed[2], stashed[3], stashed[4])
+              stashed = None
+
+          if stashed:
+            yield stashed
+            stashed = None
+
+          yield tok
+        elif initial == '\\':  # continued stmt
+          # This yield is new; needed for better idempotency:
+          if stashed:
+            yield stashed
+            stashed = None
+          yield (NL, token, spos, (lnum, pos), line)
+          continued = 1
+        else:
+          if initial in '([{':
+            parenlev = parenlev + 1
+          elif initial in ')]}':
+            parenlev = parenlev - 1
+          if stashed:
+            yield stashed
+            stashed = None
+          yield (OP, token, spos, epos, line)
+      else:
+        yield (ERRORTOKEN, line[pos], (lnum, pos), (lnum, pos + 1), line)
+        pos = pos + 1
+
+  if stashed:
+    yield stashed
+    stashed = None
+
+  for indent in indents[1:]:  # pop remaining indent levels
+    yield (DEDENT, '', (lnum, 0), (lnum, 0), '')
+  yield (ENDMARKER, '', (lnum, 0), (lnum, 0), '')
+
+
+if __name__ == '__main__':  # testing
+  import sys
+  if len(sys.argv) > 1:
+    tokenize(open(sys.argv[1]).readline)
+  else:
+    tokenize(sys.stdin.readline)
diff --git a/third_party/yapf_third_party/_ylib2to3/pygram.py b/third_party/yapf_third_party/_ylib2to3/pygram.py
new file mode 100644
index 0000000..4267c36
--- /dev/null
+++ b/third_party/yapf_third_party/_ylib2to3/pygram.py
@@ -0,0 +1,40 @@
+# Copyright 2006 Google, Inc. All Rights Reserved.
+# Licensed to PSF under a Contributor Agreement.
+"""Export the Python grammar and symbols."""
+
+# Python imports
+import os
+
+# Local imports
+from .pgen2 import driver
+
+# The grammar file
+_GRAMMAR_FILE = os.path.join(os.path.dirname(__file__), 'Grammar.txt')
+_PATTERN_GRAMMAR_FILE = os.path.join(
+    os.path.dirname(__file__), 'PatternGrammar.txt')
+
+
+class Symbols(object):
+
+  def __init__(self, grammar):
+    """Initializer.
+
+        Creates an attribute for each grammar symbol (nonterminal),
+        whose value is the symbol's type (an int >= 256).
+        """
+    for name, symbol in grammar.symbol2number.items():
+      setattr(self, name, symbol)
+
+
+python_grammar = driver.load_grammar(_GRAMMAR_FILE)
+
+python_symbols = Symbols(python_grammar)
+
+python_grammar_no_print_statement = python_grammar.copy()
+del python_grammar_no_print_statement.keywords['print']
+
+python_grammar_no_print_and_exec_statement = python_grammar_no_print_statement.copy()  # yapf: disable # noqa: E501
+del python_grammar_no_print_and_exec_statement.keywords['exec']
+
+pattern_grammar = driver.load_grammar(_PATTERN_GRAMMAR_FILE)
+pattern_symbols = Symbols(pattern_grammar)
diff --git a/third_party/yapf_third_party/_ylib2to3/pytree.py b/third_party/yapf_third_party/_ylib2to3/pytree.py
new file mode 100644
index 0000000..ea9767b
--- /dev/null
+++ b/third_party/yapf_third_party/_ylib2to3/pytree.py
@@ -0,0 +1,861 @@
+# Copyright 2006 Google, Inc. All Rights Reserved.
+# Licensed to PSF under a Contributor Agreement.
+"""
+Python parse tree definitions.
+
+This is a very concrete parse tree; we need to keep every token and
+even the comments and whitespace between tokens.
+
+There's also a pattern matching implementation here.
+"""
+
+__author__ = 'Guido van Rossum <guido@python.org>'
+
+import sys
+from io import StringIO
+from typing import List
+from typing import Optional
+from typing import Text
+from typing import Tuple
+from typing import Union
+
+HUGE = 0x7FFFFFFF  # maximum repeat count, default max
+
+_type_reprs = {}
+
+
+def type_repr(type_num):
+  global _type_reprs
+  if not _type_reprs:
+    from .pygram import python_symbols
+
+    # printing tokens is possible but not as useful
+    # from .pgen2 import token // token.__dict__.items():
+    for name, val in python_symbols.__dict__.items():
+      if isinstance(val, int):
+        _type_reprs[val] = name
+  return _type_reprs.setdefault(type_num, type_num)
+
+
+NL = Union['Node', 'Leaf']
+Context = Tuple[Text, Tuple[int, int]]
+RawNode = Tuple[int, Optional[Text], Optional[Context], Optional[List[NL]]]
+
+
+class Base(object):
+  """
+    Abstract base class for Node and Leaf.
+
+    This provides some default functionality and boilerplate using the
+    template pattern.
+
+    A node may be a subnode of at most one parent.
+    """
+
+  # Default values for instance variables
+  type = None  # int: token number (< 256) or symbol number (>= 256)
+  parent = None  # Parent node pointer, or None
+  children = ()  # Tuple of subnodes
+  was_changed = False
+  was_checked = False
+
+  def __new__(cls, *args, **kwds):
+    """Constructor that prevents Base from being instantiated."""
+    assert cls is not Base, 'Cannot instantiate Base'
+    return object.__new__(cls)
+
+  def __eq__(self, other):
+    """
+        Compare two nodes for equality.
+
+        This calls the method _eq().
+        """
+    if self.__class__ is not other.__class__:
+      return NotImplemented
+    return self._eq(other)
+
+  __hash__ = None  # For Py3 compatibility.
+
+  def _eq(self, other):
+    """
+        Compare two nodes for equality.
+
+        This is called by __eq__ and __ne__.  It is only called if the two nodes
+        have the same type.  This must be implemented by the concrete subclass.
+        Nodes should be considered equal if they have the same structure,
+        ignoring the prefix string and other context information.
+        """
+    raise NotImplementedError
+
+  def clone(self):
+    """
+        Return a cloned (deep) copy of self.
+
+        This must be implemented by the concrete subclass.
+        """
+    raise NotImplementedError
+
+  def post_order(self):
+    """
+        Return a post-order iterator for the tree.
+
+        This must be implemented by the concrete subclass.
+        """
+    raise NotImplementedError
+
+  def pre_order(self):
+    """
+        Return a pre-order iterator for the tree.
+
+        This must be implemented by the concrete subclass.
+        """
+    raise NotImplementedError
+
+  def replace(self, new):
+    """Replace this node with a new one in the parent."""
+    assert self.parent is not None, str(self)
+    assert new is not None
+    if not isinstance(new, list):
+      new = [new]
+    l_children = []
+    found = False
+    for ch in self.parent.children:
+      if ch is self:
+        assert not found, (self.parent.children, self, new)
+        if new is not None:
+          l_children.extend(new)
+        found = True
+      else:
+        l_children.append(ch)
+    assert found, (self.children, self, new)
+    self.parent.changed()
+    self.parent.children = l_children
+    for x in new:
+      x.parent = self.parent
+    self.parent = None
+
+  def get_lineno(self):
+    """Return the line number which generated the invocant node."""
+    node = self
+    while not isinstance(node, Leaf):
+      if not node.children:
+        return
+      node = node.children[0]
+    return node.lineno
+
+  def changed(self):
+    if self.parent:
+      self.parent.changed()
+    self.was_changed = True
+
+  def remove(self):
+    """
+        Remove the node from the tree. Returns the position of the node in its
+        parent's children before it was removed.
+        """
+    if self.parent:
+      for i, node in enumerate(self.parent.children):
+        if node is self:
+          self.parent.changed()
+          del self.parent.children[i]
+          self.parent = None
+          return i
+
+  @property
+  def next_sibling(self):
+    """
+        The node immediately following the invocant in their parent's children
+        list. If the invocant does not have a next sibling, it is None
+        """
+    if self.parent is None:
+      return None
+
+    # Can't use index(); we need to test by identity
+    for i, child in enumerate(self.parent.children):
+      if child is self:
+        try:
+          return self.parent.children[i + 1]
+        except IndexError:
+          return None
+
+  @property
+  def prev_sibling(self):
+    """
+        The node immediately preceding the invocant in their parent's children
+        list. If the invocant does not have a previous sibling, it is None.
+        """
+    if self.parent is None:
+      return None
+
+    # Can't use index(); we need to test by identity
+    for i, child in enumerate(self.parent.children):
+      if child is self:
+        if i == 0:
+          return None
+        return self.parent.children[i - 1]
+
+  def leaves(self):
+    for child in self.children:
+      yield from child.leaves()
+
+  def depth(self):
+    if self.parent is None:
+      return 0
+    return 1 + self.parent.depth()
+
+  def get_suffix(self):
+    """
+        Return the string immediately following the invocant node. This is
+        effectively equivalent to node.next_sibling.prefix
+        """
+    next_sib = self.next_sibling
+    if next_sib is None:
+      return ''
+    return next_sib.prefix
+
+  if sys.version_info < (3, 0):
+
+    def __str__(self):
+      return str(self).encode('ascii')
+
+
+class Node(Base):
+  """Concrete implementation for interior nodes."""
+
+  def __init__(self,
+               type,
+               children,
+               context=None,
+               prefix=None,
+               fixers_applied=None):
+    """
+        Initializer.
+
+        Takes a type constant (a symbol number >= 256), a sequence of
+        child nodes, and an optional context keyword argument.
+
+        As a side effect, the parent pointers of the children are updated.
+        """
+    assert type >= 256, type
+    self.type = type
+    self.children = list(children)
+    for ch in self.children:
+      assert ch.parent is None, repr(ch)
+      ch.parent = self
+    if prefix is not None:
+      self.prefix = prefix
+    if fixers_applied:
+      self.fixers_applied = fixers_applied[:]
+    else:
+      self.fixers_applied = None
+
+  def __repr__(self):
+    """Return a canonical string representation."""
+    return '%s(%s, %r)' % (self.__class__.__name__, type_repr(
+        self.type), self.children)
+
+  def __unicode__(self):
+    """
+        Return a pretty string representation.
+
+        This reproduces the input source exactly.
+        """
+    return ''.join(map(str, self.children))
+
+  if sys.version_info > (3, 0):
+    __str__ = __unicode__
+
+  def _eq(self, other):
+    """Compare two nodes for equality."""
+    return (self.type, self.children) == (other.type, other.children)
+
+  def clone(self):
+    """Return a cloned (deep) copy of self."""
+    return Node(
+        self.type, [ch.clone() for ch in self.children],
+        fixers_applied=self.fixers_applied)
+
+  def post_order(self):
+    """Return a post-order iterator for the tree."""
+    for child in self.children:
+      yield from child.post_order()
+    yield self
+
+  def pre_order(self):
+    """Return a pre-order iterator for the tree."""
+    yield self
+    for child in self.children:
+      yield from child.pre_order()
+
+  @property
+  def prefix(self):
+    """
+        The whitespace and comments preceding this node in the input.
+        """
+    if not self.children:
+      return ''
+    return self.children[0].prefix
+
+  @prefix.setter
+  def prefix(self, prefix):
+    if self.children:
+      self.children[0].prefix = prefix
+
+  def set_child(self, i, child):
+    """
+        Equivalent to 'node.children[i] = child'. This method also sets the
+        child's parent attribute appropriately.
+        """
+    child.parent = self
+    self.children[i].parent = None
+    self.children[i] = child
+    self.changed()
+
+  def insert_child(self, i, child):
+    """
+        Equivalent to 'node.children.insert(i, child)'. This method also sets
+        the child's parent attribute appropriately.
+        """
+    child.parent = self
+    self.children.insert(i, child)
+    self.changed()
+
+  def append_child(self, child):
+    """
+        Equivalent to 'node.children.append(child)'. This method also sets the
+        child's parent attribute appropriately.
+        """
+    child.parent = self
+    self.children.append(child)
+    self.changed()
+
+
+class Leaf(Base):
+  """Concrete implementation for leaf nodes."""
+
+  # Default values for instance variables
+  _prefix = ''  # Whitespace and comments preceding this token in the input
+  lineno = 0  # Line where this token starts in the input
+  column = 0  # Column where this token tarts in the input
+
+  def __init__(self, type, value, context=None, prefix=None, fixers_applied=[]):
+    """
+        Initializer.
+
+        Takes a type constant (a token number < 256), a string value, and an
+        optional context keyword argument.
+        """
+    assert 0 <= type < 256, type
+    if context is not None:
+      self._prefix, (self.lineno, self.column) = context
+    self.type = type
+    self.value = value
+    if prefix is not None:
+      self._prefix = prefix
+    self.fixers_applied = fixers_applied[:]
+
+  def __repr__(self):
+    """Return a canonical string representation."""
+    return '%s(%r, %r)' % (self.__class__.__name__, self.type, self.value)
+
+  def __unicode__(self):
+    """
+        Return a pretty string representation.
+
+        This reproduces the input source exactly.
+        """
+    return self.prefix + str(self.value)
+
+  if sys.version_info > (3, 0):
+    __str__ = __unicode__
+
+  def _eq(self, other):
+    """Compare two nodes for equality."""
+    return (self.type, self.value) == (other.type, other.value)
+
+  def clone(self):
+    """Return a cloned (deep) copy of self."""
+    return Leaf(
+        self.type,
+        self.value, (self.prefix, (self.lineno, self.column)),
+        fixers_applied=self.fixers_applied)
+
+  def leaves(self):
+    yield self
+
+  def post_order(self):
+    """Return a post-order iterator for the tree."""
+    yield self
+
+  def pre_order(self):
+    """Return a pre-order iterator for the tree."""
+    yield self
+
+  @property
+  def prefix(self):
+    """
+        The whitespace and comments preceding this token in the input.
+        """
+    return self._prefix
+
+  @prefix.setter
+  def prefix(self, prefix):
+    self.changed()
+    self._prefix = prefix
+
+
+def convert(gr, raw_node):
+  """
+    Convert raw node information to a Node or Leaf instance.
+
+    This is passed to the parser driver which calls it whenever a reduction of a
+    grammar rule produces a new complete node, so that the tree is build
+    strictly bottom-up.
+    """
+  type, value, context, children = raw_node
+  if children or type in gr.number2symbol:
+    # If there's exactly one child, return that child instead of
+    # creating a new node.
+    if len(children) == 1:
+      return children[0]
+    return Node(type, children, context=context)
+  else:
+    return Leaf(type, value, context=context)
+
+
+class BasePattern(object):
+  """
+    A pattern is a tree matching pattern.
+
+    It looks for a specific node type (token or symbol), and
+    optionally for a specific content.
+
+    This is an abstract base class.  There are three concrete
+    subclasses:
+
+    - LeafPattern matches a single leaf node;
+    - NodePattern matches a single node (usually non-leaf);
+    - WildcardPattern matches a sequence of nodes of variable length.
+    """
+
+  # Defaults for instance variables
+  type = None  # Node type (token if < 256, symbol if >= 256)
+  content = None  # Optional content matching pattern
+  name = None  # Optional name used to store match in results dict
+
+  def __new__(cls, *args, **kwds):
+    """Constructor that prevents BasePattern from being instantiated."""
+    assert cls is not BasePattern, 'Cannot instantiate BasePattern'
+    return object.__new__(cls)
+
+  def __repr__(self):
+    args = [type_repr(self.type), self.content, self.name]
+    while args and args[-1] is None:
+      del args[-1]
+    return '%s(%s)' % (self.__class__.__name__, ', '.join(map(repr, args)))
+
+  def optimize(self):
+    """
+        A subclass can define this as a hook for optimizations.
+
+        Returns either self or another node with the same effect.
+        """
+    return self
+
+  def match(self, node, results=None):
+    """
+        Does this pattern exactly match a node?
+
+        Returns True if it matches, False if not.
+
+        If results is not None, it must be a dict which will be
+        updated with the nodes matching named subpatterns.
+
+        Default implementation for non-wildcard patterns.
+        """
+    if self.type is not None and node.type != self.type:
+      return False
+    if self.content is not None:
+      r = None
+      if results is not None:
+        r = {}
+      if not self._submatch(node, r):
+        return False
+      if r:
+        results.update(r)
+    if results is not None and self.name:
+      results[self.name] = node
+    return True
+
+  def match_seq(self, nodes, results=None):
+    """
+        Does this pattern exactly match a sequence of nodes?
+
+        Default implementation for non-wildcard patterns.
+        """
+    if len(nodes) != 1:
+      return False
+    return self.match(nodes[0], results)
+
+  def generate_matches(self, nodes):
+    """
+        Generator yielding all matches for this pattern.
+
+        Default implementation for non-wildcard patterns.
+        """
+    r = {}
+    if nodes and self.match(nodes[0], r):
+      yield 1, r
+
+
+class LeafPattern(BasePattern):
+
+  def __init__(self, type=None, content=None, name=None):
+    """
+        Initializer.  Takes optional type, content, and name.
+
+        The type, if given must be a token type (< 256).  If not given,
+        this matches any *leaf* node; the content may still be required.
+
+        The content, if given, must be a string.
+
+        If a name is given, the matching node is stored in the results
+        dict under that key.
+        """
+    if type is not None:
+      assert 0 <= type < 256, type
+    if content is not None:
+      assert isinstance(content, str), repr(content)
+    self.type = type
+    self.content = content
+    self.name = name
+
+  def match(self, node, results=None):
+    """Override match() to insist on a leaf node."""
+    if not isinstance(node, Leaf):
+      return False
+    return BasePattern.match(self, node, results)
+
+  def _submatch(self, node, results=None):
+    """
+        Match the pattern's content to the node's children.
+
+        This assumes the node type matches and self.content is not None.
+
+        Returns True if it matches, False if not.
+
+        If results is not None, it must be a dict which will be
+        updated with the nodes matching named subpatterns.
+
+        When returning False, the results dict may still be updated.
+        """
+    return self.content == node.value
+
+
+class NodePattern(BasePattern):
+
+  wildcards = False
+
+  def __init__(self, type=None, content=None, name=None):
+    """
+        Initializer.  Takes optional type, content, and name.
+
+        The type, if given, must be a symbol type (>= 256).  If the
+        type is None this matches *any* single node (leaf or not),
+        except if content is not None, in which it only matches
+        non-leaf nodes that also match the content pattern.
+
+        The content, if not None, must be a sequence of Patterns that
+        must match the node's children exactly.  If the content is
+        given, the type must not be None.
+
+        If a name is given, the matching node is stored in the results
+        dict under that key.
+        """
+    if type is not None:
+      assert type >= 256, type
+    if content is not None:
+      assert not isinstance(content, str), repr(content)
+      content = list(content)
+      for i, item in enumerate(content):
+        assert isinstance(item, BasePattern), (i, item)
+        if isinstance(item, WildcardPattern):
+          self.wildcards = True
+    self.type = type
+    self.content = content
+    self.name = name
+
+  def _submatch(self, node, results=None):
+    """
+        Match the pattern's content to the node's children.
+
+        This assumes the node type matches and self.content is not None.
+
+        Returns True if it matches, False if not.
+
+        If results is not None, it must be a dict which will be
+        updated with the nodes matching named subpatterns.
+
+        When returning False, the results dict may still be updated.
+        """
+    if self.wildcards:
+      for c, r in generate_matches(self.content, node.children):
+        if c == len(node.children):
+          if results is not None:
+            results.update(r)
+          return True
+      return False
+    if len(self.content) != len(node.children):
+      return False
+    for subpattern, child in zip(self.content, node.children):
+      if not subpattern.match(child, results):
+        return False
+    return True
+
+
+class WildcardPattern(BasePattern):
+  """
+    A wildcard pattern can match zero or more nodes.
+
+    This has all the flexibility needed to implement patterns like:
+
+    .*      .+      .?      .{m,n}
+    (a b c | d e | f)
+    (...)*  (...)+  (...)?  (...){m,n}
+
+    except it always uses non-greedy matching.
+    """
+
+  def __init__(self, content=None, min=0, max=HUGE, name=None):
+    """
+        Initializer.
+
+        Args:
+            content: optional sequence of subsequences of patterns;
+                     if absent, matches one node;
+                     if present, each subsequence is an alternative [*]
+            min: optional minimum number of times to match, default 0
+            max: optional maximum number of times to match, default HUGE
+            name: optional name assigned to this match
+
+        [*] Thus, if content is [[a, b, c], [d, e], [f, g, h]] this is
+            equivalent to (a b c | d e | f g h); if content is None,
+            this is equivalent to '.' in regular expression terms.
+            The min and max parameters work as follows:
+                min=0, max=maxint: .*
+                min=1, max=maxint: .+
+                min=0, max=1: .?
+                min=1, max=1: .
+            If content is not None, replace the dot with the parenthesized
+            list of alternatives, e.g. (a b c | d e | f g h)*
+        """
+    assert 0 <= min <= max <= HUGE, (min, max)
+    if content is not None:
+      content = tuple(map(tuple, content))  # Protect against alterations
+      # Check sanity of alternatives
+      assert len(content), repr(content)  # Can't have zero alternatives
+      for alt in content:
+        assert len(alt), repr(alt)  # Can have empty alternatives
+    self.content = content
+    self.min = min
+    self.max = max
+    self.name = name
+
+  def optimize(self):
+    """Optimize certain stacked wildcard patterns."""
+    subpattern = None
+    if (self.content is not None and len(self.content) == 1 and
+        len(self.content[0]) == 1):
+      subpattern = self.content[0][0]
+    if self.min == 1 and self.max == 1:
+      if self.content is None:
+        return NodePattern(name=self.name)
+      if subpattern is not None and self.name == subpattern.name:
+        return subpattern.optimize()
+    if (self.min <= 1 and isinstance(subpattern, WildcardPattern) and
+        subpattern.min <= 1 and self.name == subpattern.name):
+      return WildcardPattern(subpattern.content, self.min * subpattern.min,
+                             self.max * subpattern.max, subpattern.name)
+    return self
+
+  def match(self, node, results=None):
+    """Does this pattern exactly match a node?"""
+    return self.match_seq([node], results)
+
+  def match_seq(self, nodes, results=None):
+    """Does this pattern exactly match a sequence of nodes?"""
+    for c, r in self.generate_matches(nodes):
+      if c == len(nodes):
+        if results is not None:
+          results.update(r)
+          if self.name:
+            results[self.name] = list(nodes)
+        return True
+    return False
+
+  def generate_matches(self, nodes):
+    """
+        Generator yielding matches for a sequence of nodes.
+
+        Args:
+            nodes: sequence of nodes
+
+        Yields:
+            (count, results) tuples where:
+            count: the match comprises nodes[:count];
+            results: dict containing named submatches.
+        """
+    if self.content is None:
+      # Shortcut for special case (see __init__.__doc__)
+      for count in range(self.min, 1 + min(len(nodes), self.max)):
+        r = {}
+        if self.name:
+          r[self.name] = nodes[:count]
+        yield count, r
+    elif self.name == 'bare_name':
+      yield self._bare_name_matches(nodes)
+    else:
+      # The reason for this is that hitting the recursion limit usually
+      # results in some ugly messages about how RuntimeErrors are being
+      # ignored. We only have to do this on CPython, though, because other
+      # implementations don't have this nasty bug in the first place.
+      if hasattr(sys, 'getrefcount'):
+        save_stderr = sys.stderr
+        sys.stderr = StringIO()
+      try:
+        for count, r in self._recursive_matches(nodes, 0):
+          if self.name:
+            r[self.name] = nodes[:count]
+          yield count, r
+      except RuntimeError:
+        # We fall back to the iterative pattern matching scheme if the recursive
+        # scheme hits the recursion limit.
+        for count, r in self._iterative_matches(nodes):
+          if self.name:
+            r[self.name] = nodes[:count]
+          yield count, r
+      finally:
+        if hasattr(sys, 'getrefcount'):
+          sys.stderr = save_stderr
+
+  def _iterative_matches(self, nodes):
+    """Helper to iteratively yield the matches."""
+    nodelen = len(nodes)
+    if 0 >= self.min:
+      yield 0, {}
+
+    results = []
+    # generate matches that use just one alt from self.content
+    for alt in self.content:
+      for c, r in generate_matches(alt, nodes):
+        yield c, r
+        results.append((c, r))
+
+    # for each match, iterate down the nodes
+    while results:
+      new_results = []
+      for c0, r0 in results:
+        # stop if the entire set of nodes has been matched
+        if c0 < nodelen and c0 <= self.max:
+          for alt in self.content:
+            for c1, r1 in generate_matches(alt, nodes[c0:]):
+              if c1 > 0:
+                r = {}
+                r.update(r0)
+                r.update(r1)
+                yield c0 + c1, r
+                new_results.append((c0 + c1, r))
+      results = new_results
+
+  def _bare_name_matches(self, nodes):
+    """Special optimized matcher for bare_name."""
+    count = 0
+    r = {}
+    done = False
+    max = len(nodes)
+    while not done and count < max:
+      done = True
+      for leaf in self.content:
+        if leaf[0].match(nodes[count], r):
+          count += 1
+          done = False
+          break
+    r[self.name] = nodes[:count]
+    return count, r
+
+  def _recursive_matches(self, nodes, count):
+    """Helper to recursively yield the matches."""
+    assert self.content is not None
+    if count >= self.min:
+      yield 0, {}
+    if count < self.max:
+      for alt in self.content:
+        for c0, r0 in generate_matches(alt, nodes):
+          for c1, r1 in self._recursive_matches(nodes[c0:], count + 1):
+            r = {}
+            r.update(r0)
+            r.update(r1)
+            yield c0 + c1, r
+
+
+class NegatedPattern(BasePattern):
+
+  def __init__(self, content=None):
+    """
+        Initializer.
+
+        The argument is either a pattern or None.  If it is None, this
+        only matches an empty sequence (effectively '$' in regex
+        lingo).  If it is not None, this matches whenever the argument
+        pattern doesn't have any matches.
+        """
+    if content is not None:
+      assert isinstance(content, BasePattern), repr(content)
+    self.content = content
+
+  def match(self, node):
+    # We never match a node in its entirety
+    return False
+
+  def match_seq(self, nodes):
+    # We only match an empty sequence of nodes in its entirety
+    return len(nodes) == 0
+
+  def generate_matches(self, nodes):
+    if self.content is None:
+      # Return a match if there is an empty sequence
+      if len(nodes) == 0:
+        yield 0, {}
+    else:
+      # Return a match if the argument pattern has no matches
+      for c, r in self.content.generate_matches(nodes):
+        return
+      yield 0, {}
+
+
+def generate_matches(patterns, nodes):
+  """
+    Generator yielding matches for a sequence of patterns and nodes.
+
+    Args:
+        patterns: a sequence of patterns
+        nodes: a sequence of nodes
+
+    Yields:
+        (count, results) tuples where:
+        count: the entire sequence of patterns matches nodes[:count];
+        results: dict containing named submatches.
+        """
+  if not patterns:
+    yield 0, {}
+  else:
+    p, rest = patterns[0], patterns[1:]
+    for c0, r0 in p.generate_matches(nodes):
+      if not rest:
+        yield c0, r0
+      else:
+        for c1, r1 in generate_matches(rest, nodes[c0:]):
+          r = {}
+          r.update(r0)
+          r.update(r1)
+          yield c0 + c1, r
diff --git a/yapf/third_party/yapf_diff/LICENSE b/third_party/yapf_third_party/yapf_diff/LICENSE
similarity index 99%
rename from yapf/third_party/yapf_diff/LICENSE
rename to third_party/yapf_third_party/yapf_diff/LICENSE
index f9dc506..bd8b243 100644
--- a/yapf/third_party/yapf_diff/LICENSE
+++ b/third_party/yapf_third_party/yapf_diff/LICENSE
@@ -216,4 +216,3 @@ conflicts with the conditions of the GPLv2, you may retroactively and
 prospectively choose to deem waived or otherwise exclude such Section(s) of
 the License, but only in their entirety and only with respect to the Combined
 Software.
-
diff --git a/third_party/yapf_third_party/yapf_diff/__init__.py b/third_party/yapf_third_party/yapf_diff/__init__.py
new file mode 100644
index 0000000..e69de29
diff --git a/yapf/third_party/yapf_diff/yapf_diff.py b/third_party/yapf_third_party/yapf_diff/yapf_diff.py
similarity index 96%
rename from yapf/third_party/yapf_diff/yapf_diff.py
rename to third_party/yapf_third_party/yapf_diff/yapf_diff.py
index 810a6a2..a22abd9 100644
--- a/yapf/third_party/yapf_diff/yapf_diff.py
+++ b/third_party/yapf_third_party/yapf_diff/yapf_diff.py
@@ -24,18 +24,13 @@ to determine the source file to update. Users calling this script directly
 should be careful to ensure that the path in the diff is correct relative to the
 current working directory.
 """
-from __future__ import absolute_import, division, print_function
 
 import argparse
 import difflib
 import re
 import subprocess
 import sys
-
-if sys.version_info.major >= 3:
-  from io import StringIO
-else:
-  from io import BytesIO as StringIO
+from io import StringIO
 
 
 def main():
diff --git a/tox.ini b/tox.ini
index f42b884..5e5b11e 100644
--- a/tox.ini
+++ b/tox.ini
@@ -1,6 +1,19 @@
 [tox]
-envlist=py27,py34,py35,py36,py37,py38
+requires =
+    tox<4
+    tox-pyenv
+    tox-wheel
+envlist = py37,py38,py39,py310,py311,py312
+# tox-wheel alias for `wheel_pep517 = true`
+isolated_build = True
+distshare = ./dist
 
 [testenv]
-commands=
-    python setup.py test
+wheel = True
+wheel_build_env = bdist_wheel
+commands = python -m unittest discover -p '*_test.py' yapftests/
+
+[testenv:bdist_wheel]
+
+[testenv:sdist]
+wheel = False
diff --git a/yapf/__init__.py b/yapf/__init__.py
index 0c2fb95..cf4be93 100644
--- a/yapf/__init__.py
+++ b/yapf/__init__.py
@@ -19,26 +19,39 @@ i.e., lines which, if there were no column limit, we would place all tokens on
 that line. It then uses a priority queue to figure out what the best formatting
 is --- i.e., the formatting with the least penalty.
 
-It differs from tools like autopep8 and pep8ify in that it doesn't just look for
+It differs from tools like autopep8 in that it doesn't just look for
 violations of the style guide, but looks at the module as a whole, making
 formatting decisions based on what's the best format for each line.
 
 If no filenames are specified, YAPF reads the code from stdin.
 """
-from __future__ import print_function
 
 import argparse
+import codecs
+import io
 import logging
 import os
 import sys
 
+from yapf._version import __version__
 from yapf.yapflib import errors
 from yapf.yapflib import file_resources
-from yapf.yapflib import py3compat
 from yapf.yapflib import style
 from yapf.yapflib import yapf_api
 
-__version__ = '0.32.0'
+
+def _raw_input():
+  wrapper = io.TextIOWrapper(sys.stdin.buffer, encoding='utf-8')
+  return wrapper.buffer.raw.readall().decode('utf-8')
+
+
+def _removeBOM(source):
+  """Remove any Byte-order-Mark bytes from the beginning of a file."""
+  bom = codecs.BOM_UTF8
+  bom = bom.decode('utf-8')
+  if source.startswith(bom):
+    return source[len(bom):]
+  return source
 
 
 def main(argv):
@@ -77,14 +90,14 @@ def main(argv):
     while True:
       # Test that sys.stdin has the "closed" attribute. When using pytest, it
       # co-opts sys.stdin, which makes the "main_tests.py" fail. This is gross.
-      if hasattr(sys.stdin, "closed") and sys.stdin.closed:
+      if hasattr(sys.stdin, 'closed') and sys.stdin.closed:
         break
       try:
         # Use 'raw_input' instead of 'sys.stdin.read', because otherwise the
         # user will need to hit 'Ctrl-D' more than once if they're inputting
         # the program by hand. 'raw_input' throws an EOFError exception if
         # 'Ctrl-D' is pressed, which makes it easy to bail out of this loop.
-        original_source.append(py3compat.raw_input())
+        original_source.append(_raw_input())
       except EOFError:
         break
       except KeyboardInterrupt:
@@ -94,15 +107,14 @@ def main(argv):
       style_config = file_resources.GetDefaultStyleForDir(os.getcwd())
 
     source = [line.rstrip() for line in original_source]
-    source[0] = py3compat.removeBOM(source[0])
+    source[0] = _removeBOM(source[0])
 
     try:
       reformatted_source, _ = yapf_api.FormatCode(
-          py3compat.unicode('\n'.join(source) + '\n'),
+          str('\n'.join(source).replace('\r\n', '\n') + '\n'),
           filename='<stdin>',
           style_config=style_config,
-          lines=lines,
-          verify=args.verify)
+          lines=lines)
     except errors.YapfError:
       raise
     except Exception as e:
@@ -128,10 +140,10 @@ def main(argv):
       no_local_style=args.no_local_style,
       in_place=args.in_place,
       print_diff=args.diff,
-      verify=args.verify,
       parallel=args.parallel,
       quiet=args.quiet,
-      verbose=args.verbose)
+      verbose=args.verbose,
+      print_modified=args.print_modified)
   return 1 if changed and (args.diff or args.quiet) else 0
 
 
@@ -158,10 +170,10 @@ def FormatFiles(filenames,
                 no_local_style=False,
                 in_place=False,
                 print_diff=False,
-                verify=False,
                 parallel=False,
                 quiet=False,
-                verbose=False):
+                verbose=False,
+                print_modified=False):
   """Format a list of files.
 
   Arguments:
@@ -176,31 +188,32 @@ def FormatFiles(filenames,
     in_place: (bool) Modify the files in place.
     print_diff: (bool) Instead of returning the reformatted source, return a
       diff that turns the formatted source into reformatter source.
-    verify: (bool) True if reformatted code should be verified for syntax.
     parallel: (bool) True if should format multiple files in parallel.
     quiet: (bool) True if should output nothing.
     verbose: (bool) True if should print out filenames while processing.
+    print_modified: (bool) True if should print out filenames of modified files.
 
   Returns:
     True if the source code changed in any of the files being formatted.
   """
   changed = False
   if parallel:
-    import multiprocessing  # pylint: disable=g-import-not-at-top
     import concurrent.futures  # pylint: disable=g-import-not-at-top
+    import multiprocessing  # pylint: disable=g-import-not-at-top
     workers = min(multiprocessing.cpu_count(), len(filenames))
     with concurrent.futures.ProcessPoolExecutor(workers) as executor:
       future_formats = [
           executor.submit(_FormatFile, filename, lines, style_config,
-                          no_local_style, in_place, print_diff, verify, quiet,
-                          verbose) for filename in filenames
+                          no_local_style, in_place, print_diff, quiet, verbose,
+                          print_modified) for filename in filenames
       ]
       for future in concurrent.futures.as_completed(future_formats):
         changed |= future.result()
   else:
     for filename in filenames:
       changed |= _FormatFile(filename, lines, style_config, no_local_style,
-                             in_place, print_diff, verify, quiet, verbose)
+                             in_place, print_diff, quiet, verbose,
+                             print_modified)
   return changed
 
 
@@ -210,12 +223,12 @@ def _FormatFile(filename,
                 no_local_style=False,
                 in_place=False,
                 print_diff=False,
-                verify=False,
                 quiet=False,
-                verbose=False):
+                verbose=False,
+                print_modified=False):
   """Format an individual file."""
   if verbose and not quiet:
-    print('Reformatting %s' % filename)
+    print(f'Reformatting {filename}')
 
   if style_config is None and not no_local_style:
     style_config = file_resources.GetDefaultStyleForDir(
@@ -228,7 +241,6 @@ def _FormatFile(filename,
         style_config=style_config,
         lines=lines,
         print_diff=print_diff,
-        verify=verify,
         logger=logging.warning)
   except errors.YapfError:
     raise
@@ -238,6 +250,8 @@ def _FormatFile(filename,
   if not in_place and not quiet and reformatted_code:
     file_resources.WriteReformattedCode(filename, reformatted_code, encoding,
                                         in_place)
+  if print_modified and has_change and in_place and not quiet:
+    print(f'Formatted {filename}')
   return has_change
 
 
@@ -337,13 +351,16 @@ def _BuildParser():
       '--no-local-style',
       action='store_true',
       help="don't search for local style definition")
-  parser.add_argument('--verify', action='store_true', help=argparse.SUPPRESS)
   parser.add_argument(
       '-p',
       '--parallel',
       action='store_true',
-      help=('run yapf in parallel when formatting multiple files. Requires '
-            'concurrent.futures in Python 2.X'))
+      help=('run YAPF in parallel when formatting multiple files.'))
+  parser.add_argument(
+      '-m',
+      '--print-modified',
+      action='store_true',
+      help='print out file names of modified files')
   parser.add_argument(
       '-vv',
       '--verbose',
diff --git a/yapf/_version.py b/yapf/_version.py
new file mode 100644
index 0000000..1e79165
--- /dev/null
+++ b/yapf/_version.py
@@ -0,0 +1 @@
+__version__ = '0.43.0'
diff --git a/yapf/pyparser/__init__.py b/yapf/pyparser/__init__.py
new file mode 100644
index 0000000..1b6cc80
--- /dev/null
+++ b/yapf/pyparser/__init__.py
@@ -0,0 +1,13 @@
+# Copyright 2022 Google Inc. All Rights Reserved.
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
diff --git a/yapf/pyparser/pyparser.py b/yapf/pyparser/pyparser.py
new file mode 100644
index 0000000..a7b4e33
--- /dev/null
+++ b/yapf/pyparser/pyparser.py
@@ -0,0 +1,163 @@
+# Copyright 2022 Bill Wendling, All Rights Reserved.
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
+"""Simple Python Parser
+
+Parse Python code into a list of logical lines, represented by LogicalLine
+objects. This uses Python's tokenizer to generate the tokens. As such, YAPF must
+be run with the appropriate Python version---Python >=3.7 for Python 3.7 code,
+Python >=3.8 for Python 3.8 code, etc.
+
+This parser uses Python's native "tokenizer" module to generate a list of tokens
+for the source code. It then uses Python's native "ast" module to assign
+subtypes, calculate split penalties, etc.
+
+A "logical line" produced by Python's "tokenizer" module ends with a
+tokenize.NEWLINE, rather than a tokenize.NL, making it easy to separate them
+out. Comments all end with a tokentizer.NL, so we need to make sure we don't
+errantly pick up non-comment tokens when parsing comment blocks.
+
+  ParseCode(): parse the code producing a list of logical lines.
+"""
+
+# TODO: Call from yapf_api.FormatCode.
+
+import ast
+import codecs
+import os
+import token
+import tokenize
+from io import StringIO
+from tokenize import TokenInfo
+
+from yapf.pyparser import split_penalty_visitor
+from yapf.yapflib import format_token
+from yapf.yapflib import logical_line
+
+CONTINUATION = token.N_TOKENS
+
+
+def ParseCode(unformatted_source, filename='<unknown>'):
+  """Parse a string of Python code into logical lines.
+
+  This provides an alternative entry point to YAPF.
+
+  Arguments:
+    unformatted_source: (unicode) The code to format.
+    filename: (unicode) The name of the file being reformatted.
+
+  Returns:
+    A list of LogicalLines.
+
+  Raises:
+    An exception is raised if there's an error during AST parsing.
+  """
+  if not unformatted_source.endswith(os.linesep):
+    unformatted_source += os.linesep
+
+  try:
+    ast_tree = ast.parse(unformatted_source, filename)
+    ast.fix_missing_locations(ast_tree)
+    readline = StringIO(unformatted_source).readline
+    tokens = tokenize.generate_tokens(readline)
+  except Exception:
+    raise
+
+  logical_lines = _CreateLogicalLines(tokens)
+
+  # Process the logical lines.
+  split_penalty_visitor.SplitPenalty(logical_lines).visit(ast_tree)
+
+  return logical_lines
+
+
+def _CreateLogicalLines(tokens):
+  """Separate tokens into logical lines.
+
+  Arguments:
+    tokens: (list of tokenizer.TokenInfo) Tokens generated by tokenizer.
+
+  Returns:
+    A list of LogicalLines.
+  """
+  formatted_tokens = []
+
+  # Convert tokens into "TokenInfo" and add tokens for continuation markers.
+  prev_tok = None
+  for tok in tokens:
+    tok = TokenInfo(*tok)
+
+    if (prev_tok and prev_tok.line.rstrip().endswith('\\') and
+        prev_tok.start[0] < tok.start[0]):
+      ctok = TokenInfo(
+          type=CONTINUATION,
+          string='\\',
+          start=(prev_tok.start[0], prev_tok.start[1] + 1),
+          end=(prev_tok.end[0], prev_tok.end[0] + 2),
+          line=prev_tok.line)
+      ctok.lineno = ctok.start[0]
+      ctok.column = ctok.start[1]
+      ctok.value = '\\'
+      formatted_tokens.append(format_token.FormatToken(ctok, 'CONTINUATION'))
+
+    tok.lineno = tok.start[0]
+    tok.column = tok.start[1]
+    tok.value = tok.string
+    formatted_tokens.append(
+        format_token.FormatToken(tok, token.tok_name[tok.type]))
+    prev_tok = tok
+
+  # Generate logical lines.
+  logical_lines, cur_logical_line = [], []
+  depth = 0
+  for tok in formatted_tokens:
+    if tok.type == tokenize.ENDMARKER:
+      break
+
+    if tok.type == tokenize.NEWLINE:
+      # End of a logical line.
+      logical_lines.append(logical_line.LogicalLine(depth, cur_logical_line))
+      cur_logical_line = []
+    elif tok.type == tokenize.INDENT:
+      depth += 1
+    elif tok.type == tokenize.DEDENT:
+      depth -= 1
+    elif tok.type == tokenize.NL:
+      pass
+    else:
+      if (cur_logical_line and not tok.type == tokenize.COMMENT and
+          cur_logical_line[0].type == tokenize.COMMENT):
+        # We were parsing a comment block, but now we have real code to worry
+        # about. Store the comment and carry on.
+        logical_lines.append(logical_line.LogicalLine(depth, cur_logical_line))
+        cur_logical_line = []
+
+      cur_logical_line.append(tok)
+
+  # Link the FormatTokens in each line together to form a doubly linked list.
+  for line in logical_lines:
+    previous = line.first
+    bracket_stack = [previous] if previous.OpensScope() else []
+    for tok in line.tokens[1:]:
+      tok.previous_token = previous
+      previous.next_token = tok
+      previous = tok
+
+      # Set up the "matching_bracket" attribute.
+      if tok.OpensScope():
+        bracket_stack.append(tok)
+      elif tok.ClosesScope():
+        bracket_stack[-1].matching_bracket = tok
+        tok.matching_bracket = bracket_stack.pop()
+
+  return logical_lines
diff --git a/yapf/pyparser/pyparser_utils.py b/yapf/pyparser/pyparser_utils.py
new file mode 100644
index 0000000..dee2449
--- /dev/null
+++ b/yapf/pyparser/pyparser_utils.py
@@ -0,0 +1,103 @@
+# Copyright 2022 Bill Wendling, All Rights Reserved.
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
+"""PyParser-related utilities.
+
+This module collects various utilities related to the parse trees produced by
+the pyparser.
+
+  GetLogicalLine: produces a list of tokens from the logical lines within a
+    range.
+  GetTokensInSubRange: produces a sublist of tokens from a current token list
+    within a range.
+  GetTokenIndex: Get the index of a token.
+  GetNextTokenIndex: Get the index of the next token after a given position.
+  GetPrevTokenIndex: Get the index of the previous token before a given
+    position.
+  TokenStart: Convenience function to return the token's start as a tuple.
+  TokenEnd: Convenience function to return the token's end as a tuple.
+"""
+
+
+def GetLogicalLine(logical_lines, node):
+  """Get a list of tokens within the node's range from the logical lines."""
+  start = TokenStart(node)
+  end = TokenEnd(node)
+  tokens = []
+
+  for line in logical_lines:
+    if line.start > end:
+      break
+    if line.start <= start or line.end >= end:
+      tokens.extend(GetTokensInSubRange(line.tokens, node))
+
+  return tokens
+
+
+def GetTokensInSubRange(tokens, node):
+  """Get a subset of tokens representing the node."""
+  start = TokenStart(node)
+  end = TokenEnd(node)
+  tokens_in_range = []
+
+  for tok in tokens:
+    tok_range = (tok.lineno, tok.column)
+    if tok_range >= start and tok_range < end:
+      tokens_in_range.append(tok)
+
+  return tokens_in_range
+
+
+def GetTokenIndex(tokens, pos):
+  """Get the index of the token at pos."""
+  for index, token in enumerate(tokens):
+    if (token.lineno, token.column) == pos:
+      return index
+
+  return None
+
+
+def GetNextTokenIndex(tokens, pos):
+  """Get the index of the next token after pos."""
+  for index, token in enumerate(tokens):
+    if (token.lineno, token.column) >= pos:
+      return index
+
+  return None
+
+
+def GetPrevTokenIndex(tokens, pos):
+  """Get the index of the previous token before pos."""
+  for index, token in enumerate(tokens):
+    if index > 0 and (token.lineno, token.column) >= pos:
+      return index - 1
+
+  return None
+
+
+def TokenStart(node):
+  return (node.lineno, node.col_offset)
+
+
+def TokenEnd(node):
+  return (node.end_lineno, node.end_col_offset)
+
+
+#############################################################################
+# Code for debugging                                                        #
+#############################################################################
+
+
+def AstDump(node):
+  import ast
+  print(ast.dump(node, include_attributes=True, indent=4))
diff --git a/yapf/pyparser/pyparser_visitor.py.tmpl b/yapf/pyparser/pyparser_visitor.py.tmpl
new file mode 100644
index 0000000..0d8a75e
--- /dev/null
+++ b/yapf/pyparser/pyparser_visitor.py.tmpl
@@ -0,0 +1,646 @@
+# Copyright 2022 Bill Wendling, All Rights Reserved.
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
+"""AST visitor template.
+
+This is a template for a pyparser visitor. Example use:
+
+    import ast
+    from io import StringIO
+
+    from yapf.pyparser import pyparser_visitor
+
+    def parse_code(source, filename):
+        ast_tree = ast.parse(source, filename)
+        readline = StringIO(source).readline
+        tokens = tokenize.generate_tokens(readline)
+        logical_lines = _CreateLogicalLines(tokens)
+
+        pyparser_visitor.Visitor(logical_lines).visit(ast_tree)
+"""
+
+import ast
+
+
+# This is a skeleton of an AST visitor.
+class Visitor(ast.NodeVisitor):
+  """Compute split penalties between tokens."""
+
+  def __init__(self, logical_lines):
+    super(Visitor, self).__init__()
+    self.logical_lines = logical_lines
+
+  ############################################################################
+  # Statements                                                               #
+  ############################################################################
+
+  def visit_FunctionDef(self, node):
+    # FunctionDef(name=Name,
+    #             args=arguments(
+    #                 posonlyargs=[],
+    #                 args=[],
+    #                 vararg=[],
+    #                 kwonlyargs=[],
+    #                 kw_defaults=[],
+    #                 defaults=[]),
+    #             body=[...],
+    #             decorator_list=[Expr_1, Expr_2, ..., Expr_n],
+    #             keywords=[])
+    return self.generic_visit(node)
+
+  def visit_AsyncFunctionDef(self, node):
+    # AsyncFunctionDef(name=Name,
+    #                  args=arguments(
+    #                      posonlyargs=[],
+    #                      args=[],
+    #                      vararg=[],
+    #                      kwonlyargs=[],
+    #                      kw_defaults=[],
+    #                      defaults=[]),
+    #                  body=[...],
+    #                  decorator_list=[Expr_1, Expr_2, ..., Expr_n],
+    #                  keywords=[])
+    return self.generic_visit(node)
+
+  def visit_ClassDef(self, node):
+    # ClassDef(name=Name,
+    #          bases=[Expr_1, Expr_2, ..., Expr_n],
+    #          keywords=[],
+    #          body=[],
+    #          decorator_list=[Expr_1, Expr_2, ..., Expr_m])
+    return self.generic_visit(node)
+
+  def visit_Return(self, node):
+    # Return(value=Expr)
+    return self.generic_visit(node)
+
+  def visit_Delete(self, node):
+    # Delete(targets=[Expr_1, Expr_2, ..., Expr_n])
+    return self.generic_visit(node)
+
+  def visit_Assign(self, node):
+    # Assign(targets=[Expr_1, Expr_2, ..., Expr_n],
+    #        value=Expr)
+    return self.generic_visit(node)
+
+  def visit_AugAssign(self, node):
+    # AugAssign(target=Name,
+    #           op=Add(),
+    #           value=Expr)
+    return self.generic_visit(node)
+
+  def visit_AnnAssign(self, node):
+    # AnnAssign(target=Name,
+    #           annotation=TypeName,
+    #           value=Expr,
+    #           simple=number)
+    return self.generic_visit(node)
+
+  def visit_For(self, node):
+    # For(target=Expr,
+    #     iter=Expr,
+    #     body=[...],
+    #     orelse=[...])
+    return self.generic_visit(node)
+
+  def visit_AsyncFor(self, node):
+    # AsyncFor(target=Expr,
+    #          iter=Expr,
+    #          body=[...],
+    #          orelse=[...])
+    return self.generic_visit(node)
+
+  def visit_While(self, node):
+    # While(test=Expr,
+    #       body=[...],
+    #       orelse=[...])
+    return self.generic_visit(node)
+
+  def visit_If(self, node):
+    # If(test=Expr,
+    #    body=[...],
+    #    orelse=[...])
+    return self.generic_visit(node)
+
+  def visit_With(self, node):
+    # With(items=[withitem_1, withitem_2, ..., withitem_n],
+    #      body=[...])
+    return self.generic_visit(node)
+
+  def visit_AsyncWith(self, node):
+    # AsyncWith(items=[withitem_1, withitem_2, ..., withitem_n],
+    #           body=[...])
+    return self.generic_visit(node)
+
+  def visit_Match(self, node):
+    # Match(subject=Expr,
+    #       cases=[
+    #           match_case(
+    #               pattern=pattern,
+    #               guard=Expr,
+    #               body=[...]),
+    #             ...
+    #       ])
+    return self.generic_visit(node)
+
+  def visit_Raise(self, node):
+    # Raise(exc=Expr)
+    return self.generic_visit(node)
+
+  def visit_Try(self, node):
+    # Try(body=[...],
+    #     handlers=[ExceptHandler_1, ExceptHandler_2, ..., ExceptHandler_b],
+    #     orelse=[...],
+    #     finalbody=[...])
+    return self.generic_visit(node)
+
+  def visit_Assert(self, node):
+    # Assert(test=Expr)
+    return self.generic_visit(node)
+
+  def visit_Import(self, node):
+    # Import(names=[
+    #            alias(
+    #                name=Identifier,
+    #                asname=Identifier),
+    #              ...
+    #        ])
+    return self.generic_visit(node)
+
+  def visit_ImportFrom(self, node):
+    # ImportFrom(module=Identifier,
+    #            names=[
+    #                alias(
+    #                    name=Identifier,
+    #                    asname=Identifier),
+    #                  ...
+    #            ],
+    #            level=num
+    return self.generic_visit(node)
+
+  def visit_Global(self, node):
+    # Global(names=[Identifier_1, Identifier_2, ..., Identifier_n])
+    return self.generic_visit(node)
+
+  def visit_Nonlocal(self, node):
+    # Nonlocal(names=[Identifier_1, Identifier_2, ..., Identifier_n])
+    return self.generic_visit(node)
+
+  def visit_Expr(self, node):
+    # Expr(value=Expr)
+    return self.generic_visit(node)
+
+  def visit_Pass(self, node):
+    # Pass()
+    return self.generic_visit(node)
+
+  def visit_Break(self, node):
+    # Break()
+    return self.generic_visit(node)
+
+  def visit_Continue(self, node):
+    # Continue()
+    return self.generic_visit(node)
+
+  ############################################################################
+  # Expressions                                                              #
+  ############################################################################
+
+  def visit_BoolOp(self, node):
+    # BoolOp(op=And | Or,
+    #        values=[Expr_1, Expr_2, ..., Expr_n])
+    return self.generic_visit(node)
+
+  def visit_NamedExpr(self, node):
+    # NamedExpr(target=Name,
+    #           value=Expr)
+    return self.generic_visit(node)
+
+  def visit_BinOp(self, node):
+    # BinOp(left=LExpr
+    #       op=Add | Sub | Mult | MatMult | Div | Mod | Pow | LShift |
+    #          RShift | BitOr | BitXor | BitAnd | FloorDiv
+    #       right=RExpr)
+    return self.generic_visit(node)
+
+  def visit_UnaryOp(self, node):
+    # UnaryOp(op=Not | USub | UAdd | Invert,
+    #         operand=Expr)
+    return self.generic_visit(node)
+
+  def visit_Lambda(self, node):
+    # Lambda(args=arguments(
+    #            posonlyargs=[],
+    #            args=[
+    #                arg(arg='a'),
+    #                arg(arg='b')],
+    #            kwonlyargs=[],
+    #            kw_defaults=[],
+    #            defaults=[]),
+    #        body=Expr)
+    return self.generic_visit(node)
+
+  def visit_IfExp(self, node):
+    # IfExp(test=TestExpr,
+    #       body=BodyExpr,
+    #       orelse=OrElseExpr)
+    return self.generic_visit(node)
+
+  def visit_Dict(self, node):
+    # Dict(keys=[Expr_1, Expr_2, ..., Expr_n],
+    #      values=[Expr_1, Expr_2, ..., Expr_n])
+    return self.generic_visit(node)
+
+  def visit_Set(self, node):
+    # Set(elts=[Expr_1, Expr_2, ..., Expr_n])
+    return self.generic_visit(node)
+
+  def visit_ListComp(self, node):
+    # ListComp(elt=Expr,
+    #          generators=[
+    #              comprehension(
+    #                  target=Expr,
+    #                  iter=Expr,
+    #                  ifs=[Expr_1, Expr_2, ..., Expr_n],
+    #                  is_async=0),
+    #               ...
+    #          ])
+    return self.generic_visit(node)
+
+  def visit_SetComp(self, node):
+    # SetComp(elt=Expr,
+    #         generators=[
+    #             comprehension(
+    #                 target=Expr,
+    #                 iter=Expr,
+    #                 ifs=[Expr_1, Expr_2, ..., Expr_n],
+    #                 is_async=0),
+    #           ...
+    #         ])
+    return self.generic_visit(node)
+
+  def visit_DictComp(self, node):
+    # DictComp(key=KeyExpr,
+    #          value=ValExpr,
+    #          generators=[
+    #              comprehension(
+    #                  target=TargetExpr
+    #                  iter=IterExpr,
+    #                  ifs=[Expr_1, Expr_2, ..., Expr_n]),
+    #                  is_async=0)],
+    #           ...
+    #         ])
+    return self.generic_visit(node)
+
+  def visit_GeneratorExp(self, node):
+    # GeneratorExp(elt=Expr,
+    #              generators=[
+    #                  comprehension(
+    #                      target=Expr,
+    #                      iter=Expr,
+    #                      ifs=[Expr_1, Expr_2, ..., Expr_n],
+    #                      is_async=0),
+    #                ...
+    #              ])
+    return self.generic_visit(node)
+
+  def visit_Await(self, node):
+    # Await(value=Expr)
+    return self.generic_visit(node)
+
+  def visit_Yield(self, node):
+    # Yield(value=Expr)
+    return self.generic_visit(node)
+
+  def visit_YieldFrom(self, node):
+    # YieldFrom(value=Expr)
+    return self.generic_visit(node)
+
+  def visit_Compare(self, node):
+    # Compare(left=LExpr,
+    #         ops=[Op_1, Op_2, ..., Op_n],
+    #         comparators=[Expr_1, Expr_2, ..., Expr_n])
+    return self.generic_visit(node)
+
+  def visit_Call(self, node):
+    # Call(func=Expr,
+    #      args=[Expr_1, Expr_2, ..., Expr_n],
+    #      keywords=[
+    #          keyword(
+    #              arg='d',
+    #              value=Expr),
+    #            ...
+    #      ])
+    return self.generic_visit(node)
+
+  def visit_FormattedValue(self, node):
+    # FormattedValue(value=Expr,
+    #                conversion=-1,
+    #                format_spec=FSExpr)
+    return self.generic_visit(node)
+
+  def visit_JoinedStr(self, node):
+    # JoinedStr(values=[Expr_1, Expr_2, ..., Expr_n])
+    return self.generic_visit(node)
+
+  def visit_Constant(self, node):
+    # Constant(value=Expr)
+    return self.generic_visit(node)
+
+  def visit_Attribute(self, node):
+    # Attribute(value=Expr,
+    #           attr=Identifier)
+    return self.generic_visit(node)
+
+  def visit_Subscript(self, node):
+    # Subscript(value=VExpr,
+    #           slice=SExpr)
+    return self.generic_visit(node)
+
+  def visit_Starred(self, node):
+    # Starred(value=Expr)
+    return self.generic_visit(node)
+
+  def visit_Name(self, node):
+    # Name(id=Identifier)
+    return self.generic_visit(node)
+
+  def visit_List(self, node):
+    # List(elts=[Expr_1, Expr_2, ..., Expr_n])
+    return self.generic_visit(node)
+
+  def visit_Tuple(self, node):
+    # Tuple(elts=[Expr_1, Expr_2, ..., Expr_n])
+    return self.generic_visit(node)
+
+  def visit_Slice(self, node):
+    # Slice(lower=Expr,
+    #       upper=Expr,
+    #       step=Expr)
+    return self.generic_visit(node)
+
+  ############################################################################
+  # Expression Context                                                       #
+  ############################################################################
+
+  def visit_Load(self, node):
+    # Load()
+    return self.generic_visit(node)
+
+  def visit_Store(self, node):
+    # Store()
+    return self.generic_visit(node)
+
+  def visit_Del(self, node):
+    # Del()
+    return self.generic_visit(node)
+
+  ############################################################################
+  # Boolean Operators                                                        #
+  ############################################################################
+
+  def visit_And(self, node):
+    # And()
+    return self.generic_visit(node)
+
+  def visit_Or(self, node):
+    # Or()
+    return self.generic_visit(node)
+
+  ############################################################################
+  # Binary Operators                                                         #
+  ############################################################################
+
+  def visit_Add(self, node):
+    # Add()
+    return self.generic_visit(node)
+
+  def visit_Sub(self, node):
+    # Sub()
+    return self.generic_visit(node)
+
+  def visit_Mult(self, node):
+    # Mult()
+    return self.generic_visit(node)
+
+  def visit_MatMult(self, node):
+    # MatMult()
+    return self.generic_visit(node)
+
+  def visit_Div(self, node):
+    # Div()
+    return self.generic_visit(node)
+
+  def visit_Mod(self, node):
+    # Mod()
+    return self.generic_visit(node)
+
+  def visit_Pow(self, node):
+    # Pow()
+    return self.generic_visit(node)
+
+  def visit_LShift(self, node):
+    # LShift()
+    return self.generic_visit(node)
+
+  def visit_RShift(self, node):
+    # RShift()
+    return self.generic_visit(node)
+
+  def visit_BitOr(self, node):
+    # BitOr()
+    return self.generic_visit(node)
+
+  def visit_BitXor(self, node):
+    # BitXor()
+    return self.generic_visit(node)
+
+  def visit_BitAnd(self, node):
+    # BitAnd()
+    return self.generic_visit(node)
+
+  def visit_FloorDiv(self, node):
+    # FloorDiv()
+    return self.generic_visit(node)
+
+  ############################################################################
+  # Unary Operators                                                          #
+  ############################################################################
+
+  def visit_Invert(self, node):
+    # Invert()
+    return self.generic_visit(node)
+
+  def visit_Not(self, node):
+    # Not()
+    return self.generic_visit(node)
+
+  def visit_UAdd(self, node):
+    # UAdd()
+    return self.generic_visit(node)
+
+  def visit_USub(self, node):
+    # USub()
+    return self.generic_visit(node)
+
+  ############################################################################
+  # Comparison Operators                                                     #
+  ############################################################################
+
+  def visit_Eq(self, node):
+    # Eq()
+    return self.generic_visit(node)
+
+  def visit_NotEq(self, node):
+    # NotEq()
+    return self.generic_visit(node)
+
+  def visit_Lt(self, node):
+    # Lt()
+    return self.generic_visit(node)
+
+  def visit_LtE(self, node):
+    # LtE()
+    return self.generic_visit(node)
+
+  def visit_Gt(self, node):
+    # Gt()
+    return self.generic_visit(node)
+
+  def visit_GtE(self, node):
+    # GtE()
+    return self.generic_visit(node)
+
+  def visit_Is(self, node):
+    # Is()
+    return self.generic_visit(node)
+
+  def visit_IsNot(self, node):
+    # IsNot()
+    return self.generic_visit(node)
+
+  def visit_In(self, node):
+    # In()
+    return self.generic_visit(node)
+
+  def visit_NotIn(self, node):
+    # NotIn()
+    return self.generic_visit(node)
+
+  ############################################################################
+  # Exception Handler                                                        #
+  ############################################################################
+
+  def visit_ExceptionHandler(self, node):
+    # ExceptHandler(type=Expr,
+    #               name=Identifier,
+    #               body=[...])
+    return self.generic_visit(node)
+
+  ############################################################################
+  # Matching Patterns                                                        #
+  ############################################################################
+
+  def visit_MatchValue(self, node):
+    # MatchValue(value=Expr)
+    return self.generic_visit(node)
+
+  def visit_MatchSingleton(self, node):
+    # MatchSingleton(value=Constant)
+    return self.generic_visit(node)
+
+  def visit_MatchSequence(self, node):
+    # MatchSequence(patterns=[pattern_1, pattern_2, ..., pattern_n])
+    return self.generic_visit(node)
+
+  def visit_MatchMapping(self, node):
+    # MatchMapping(keys=[Expr_1, Expr_2, ..., Expr_n],
+    #              patterns=[pattern_1, pattern_2, ..., pattern_m],
+    #              rest=Identifier)
+    return self.generic_visit(node)
+
+  def visit_MatchClass(self, node):
+    # MatchClass(cls=Expr,
+    #            patterns=[pattern_1, pattern_2, ...],
+    #            kwd_attrs=[Identifier_1, Identifier_2, ...],
+    #            kwd_patterns=[pattern_1, pattern_2, ...])
+    return self.generic_visit(node)
+
+  def visit_MatchStar(self, node):
+    # MatchStar(name=Identifier)
+    return self.generic_visit(node)
+
+  def visit_MatchAs(self, node):
+    # MatchAs(pattern=pattern,
+    #         name=Identifier)
+    return self.generic_visit(node)
+
+  def visit_MatchOr(self, node):
+    # MatchOr(patterns=[pattern_1, pattern_2, ...])
+    return self.generic_visit(node)
+
+  ############################################################################
+  # Type Ignore                                                              #
+  ############################################################################
+
+  def visit_TypeIgnore(self, node):
+    # TypeIgnore(tag=string)
+    return self.generic_visit(node)
+
+  ############################################################################
+  # Miscellaneous                                                            #
+  ############################################################################
+
+  def visit_comprehension(self, node):
+    # comprehension(target=Expr,
+    #               iter=Expr,
+    #               ifs=[Expr_1, Expr_2, ..., Expr_n],
+    #               is_async=0)
+    return self.generic_visit(node)
+
+  def visit_arguments(self, node):
+    # arguments(posonlyargs=[],
+    #           args=[],
+    #           vararg=arg,
+    #           kwonlyargs=[],
+    #           kw_defaults=[],
+    #           kwarg=arg,
+    #           defaults=[]),
+    return self.generic_visit(node)
+
+  def visit_arg(self, node):
+    # arg(arg=Identifier,
+    #     annotation=Expr,
+    #     type_comment='')
+    return self.generic_visit(node)
+
+  def visit_keyword(self, node):
+    # keyword(arg=Identifier,
+    #         value=Expr)
+    return self.generic_visit(node)
+
+  def visit_alias(self, node):
+    # alias(name=Identifier,
+    #       asname=Identifier)
+    return self.generic_visit(node)
+
+  def visit_withitem(self, node):
+    # withitem(context_expr=Expr,
+    #          optional_vars=Expr)
+    return self.generic_visit(node)
+
+  def visit_match_case(self, node):
+    # match_case(pattern=pattern,
+    #            guard=Expr,
+    #            body=[...])
+    return self.generic_visit(node)
diff --git a/yapf/pyparser/split_penalty_visitor.py b/yapf/pyparser/split_penalty_visitor.py
new file mode 100644
index 0000000..8cd25c9
--- /dev/null
+++ b/yapf/pyparser/split_penalty_visitor.py
@@ -0,0 +1,913 @@
+# Copyright 2022 Bill Wendling, All Rights Reserved.
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
+import ast
+
+from yapf.pyparser import pyparser_utils as pyutils
+from yapf.yapflib import split_penalty
+from yapf.yapflib import style
+from yapf.yapflib import subtypes
+
+
+class SplitPenalty(ast.NodeVisitor):
+  """Compute split penalties between tokens."""
+
+  def __init__(self, logical_lines):
+    super(SplitPenalty, self).__init__()
+    self.logical_lines = logical_lines
+
+    # We never want to split before a colon or comma.
+    for logical_line in logical_lines:
+      for token in logical_line.tokens:
+        if token.value in frozenset({',', ':'}):
+          token.split_penalty = split_penalty.UNBREAKABLE
+
+  def _GetTokens(self, node):
+    return pyutils.GetLogicalLine(self.logical_lines, node)
+
+  ############################################################################
+  # Statements                                                               #
+  ############################################################################
+
+  def visit_FunctionDef(self, node):
+    # FunctionDef(name=Name,
+    #             args=arguments(
+    #                 posonlyargs=[],
+    #                 args=[],
+    #                 vararg=[],
+    #                 kwonlyargs=[],
+    #                 kw_defaults=[],
+    #                 defaults=[]),
+    #             body=[...],
+    #             decorator_list=[Call_1, Call_2, ..., Call_n],
+    #             keywords=[])
+    tokens = self._GetTokens(node)
+
+    for decorator in node.decorator_list:
+      # The decorator token list begins after the '@'. The body of the decorator
+      # is formatted like a normal "call."
+      decorator_range = self._GetTokens(decorator)
+      # Don't split after the '@'.
+      decorator_range[0].split_penalty = split_penalty.UNBREAKABLE
+
+    for token in tokens[1:]:
+      if token.value == '(':
+        break
+      _SetPenalty(token, split_penalty.UNBREAKABLE)
+
+    if node.returns:
+      start_index = pyutils.GetTokenIndex(tokens,
+                                          pyutils.TokenStart(node.returns))
+      _IncreasePenalty(tokens[start_index - 1:start_index + 1],
+                       split_penalty.VERY_STRONGLY_CONNECTED)
+      end_index = pyutils.GetTokenIndex(tokens, pyutils.TokenEnd(node.returns))
+      _IncreasePenalty(tokens[start_index + 1:end_index],
+                       split_penalty.STRONGLY_CONNECTED)
+
+    return self.generic_visit(node)
+
+  def visit_AsyncFunctionDef(self, node):
+    # AsyncFunctionDef(name=Name,
+    #                  args=arguments(
+    #                      posonlyargs=[],
+    #                      args=[],
+    #                      vararg=[],
+    #                      kwonlyargs=[],
+    #                      kw_defaults=[],
+    #                      defaults=[]),
+    #                  body=[...],
+    #                  decorator_list=[Expr_1, Expr_2, ..., Expr_n],
+    #                  keywords=[])
+    return self.visit_FunctionDef(node)
+
+  def visit_ClassDef(self, node):
+    # ClassDef(name=Name,
+    #          bases=[Expr_1, Expr_2, ..., Expr_n],
+    #          keywords=[],
+    #          body=[],
+    #          decorator_list=[Expr_1, Expr_2, ..., Expr_m])
+    for base in node.bases:
+      tokens = self._GetTokens(base)
+      _IncreasePenalty(tokens[1:], split_penalty.EXPR)
+
+    for decorator in node.decorator_list:
+      # Don't split after the '@'.
+      tokens = self._GetTokens(decorator)
+      tokens[0].split_penalty = split_penalty.UNBREAKABLE
+
+    return self.generic_visit(node)
+
+  def visit_Return(self, node):
+    # Return(value=Expr)
+    tokens = self._GetTokens(node)
+    _IncreasePenalty(tokens[1:], split_penalty.EXPR)
+
+    return self.generic_visit(node)
+
+  def visit_Delete(self, node):
+    # Delete(targets=[Expr_1, Expr_2, ..., Expr_n])
+    for target in node.targets:
+      tokens = self._GetTokens(target)
+      _IncreasePenalty(tokens[1:], split_penalty.EXPR)
+
+    return self.generic_visit(node)
+
+  def visit_Assign(self, node):
+    # Assign(targets=[Expr_1, Expr_2, ..., Expr_n],
+    #        value=Expr)
+    tokens = self._GetTokens(node)
+    _IncreasePenalty(tokens[1:], split_penalty.EXPR)
+
+    return self.generic_visit(node)
+
+  def visit_AugAssign(self, node):
+    # AugAssign(target=Name,
+    #           op=Add(),
+    #           value=Expr)
+    return self.generic_visit(node)
+
+  def visit_AnnAssign(self, node):
+    # AnnAssign(target=Expr,
+    #           annotation=TypeName,
+    #           value=Expr,
+    #           simple=number)
+    return self.generic_visit(node)
+
+  def visit_For(self, node):
+    # For(target=Expr,
+    #     iter=Expr,
+    #     body=[...],
+    #     orelse=[...])
+    return self.generic_visit(node)
+
+  def visit_AsyncFor(self, node):
+    # AsyncFor(target=Expr,
+    #          iter=Expr,
+    #          body=[...],
+    #          orelse=[...])
+    return self.generic_visit(node)
+
+  def visit_While(self, node):
+    # While(test=Expr,
+    #       body=[...],
+    #       orelse=[...])
+    return self.generic_visit(node)
+
+  def visit_If(self, node):
+    # If(test=Expr,
+    #    body=[...],
+    #    orelse=[...])
+    return self.generic_visit(node)
+
+  def visit_With(self, node):
+    # With(items=[withitem_1, withitem_2, ..., withitem_n],
+    #      body=[...])
+    return self.generic_visit(node)
+
+  def visit_AsyncWith(self, node):
+    # AsyncWith(items=[withitem_1, withitem_2, ..., withitem_n],
+    #           body=[...])
+    return self.generic_visit(node)
+
+  def visit_Match(self, node):
+    # Match(subject=Expr,
+    #       cases=[
+    #           match_case(
+    #               pattern=pattern,
+    #               guard=Expr,
+    #               body=[...]),
+    #             ...
+    #       ])
+    return self.generic_visit(node)
+
+  def visit_Raise(self, node):
+    # Raise(exc=Expr)
+    return self.generic_visit(node)
+
+  def visit_Try(self, node):
+    # Try(body=[...],
+    #     handlers=[ExceptHandler_1, ExceptHandler_2, ..., ExceptHandler_b],
+    #     orelse=[...],
+    #     finalbody=[...])
+    return self.generic_visit(node)
+
+  def visit_Assert(self, node):
+    # Assert(test=Expr)
+    return self.generic_visit(node)
+
+  def visit_Import(self, node):
+    # Import(names=[
+    #            alias(
+    #                name=Identifier,
+    #                asname=Identifier),
+    #              ...
+    #        ])
+    return self.generic_visit(node)
+
+  def visit_ImportFrom(self, node):
+    # ImportFrom(module=Identifier,
+    #            names=[
+    #                alias(
+    #                    name=Identifier,
+    #                    asname=Identifier),
+    #                  ...
+    #            ],
+    #            level=num
+    return self.generic_visit(node)
+
+  def visit_Global(self, node):
+    # Global(names=[Identifier_1, Identifier_2, ..., Identifier_n])
+    return self.generic_visit(node)
+
+  def visit_Nonlocal(self, node):
+    # Nonlocal(names=[Identifier_1, Identifier_2, ..., Identifier_n])
+    return self.generic_visit(node)
+
+  def visit_Expr(self, node):
+    # Expr(value=Expr)
+    return self.generic_visit(node)
+
+  def visit_Pass(self, node):
+    # Pass()
+    return self.generic_visit(node)
+
+  def visit_Break(self, node):
+    # Break()
+    return self.generic_visit(node)
+
+  def visit_Continue(self, node):
+    # Continue()
+    return self.generic_visit(node)
+
+  ############################################################################
+  # Expressions                                                              #
+  ############################################################################
+
+  def visit_BoolOp(self, node):
+    # BoolOp(op=And | Or,
+    #        values=[Expr_1, Expr_2, ..., Expr_n])
+    tokens = self._GetTokens(node)
+    _IncreasePenalty(tokens[1:], split_penalty.EXPR)
+
+    # Lower the split penalty to allow splitting before or after the logical
+    # operator.
+    split_before_operator = style.Get('SPLIT_BEFORE_LOGICAL_OPERATOR')
+    operator_indices = [
+        pyutils.GetNextTokenIndex(tokens, pyutils.TokenEnd(value))
+        for value in node.values[:-1]
+    ]
+    for operator_index in operator_indices:
+      if not split_before_operator:
+        operator_index += 1
+      _DecreasePenalty(tokens[operator_index], split_penalty.EXPR * 2)
+
+    return self.generic_visit(node)
+
+  def visit_NamedExpr(self, node):
+    # NamedExpr(target=Name,
+    #           value=Expr)
+    tokens = self._GetTokens(node)
+    _IncreasePenalty(tokens[1:], split_penalty.EXPR)
+
+    return self.generic_visit(node)
+
+  def visit_BinOp(self, node):
+    # BinOp(left=LExpr
+    #       op=Add | Sub | Mult | MatMult | Div | Mod | Pow | LShift |
+    #          RShift | BitOr | BitXor | BitAnd | FloorDiv
+    #       right=RExpr)
+    tokens = self._GetTokens(node)
+
+    _IncreasePenalty(tokens[1:], split_penalty.EXPR)
+
+    # Lower the split penalty to allow splitting before or after the arithmetic
+    # operator.
+    operator_index = pyutils.GetNextTokenIndex(tokens,
+                                               pyutils.TokenEnd(node.left))
+    if not style.Get('SPLIT_BEFORE_ARITHMETIC_OPERATOR'):
+      operator_index += 1
+
+    _DecreasePenalty(tokens[operator_index], split_penalty.EXPR * 2)
+
+    return self.generic_visit(node)
+
+  def visit_UnaryOp(self, node):
+    # UnaryOp(op=Not | USub | UAdd | Invert,
+    #         operand=Expr)
+    tokens = self._GetTokens(node)
+    _IncreasePenalty(tokens[1:], split_penalty.EXPR)
+    _IncreasePenalty(tokens[1], style.Get('SPLIT_PENALTY_AFTER_UNARY_OPERATOR'))
+
+    return self.generic_visit(node)
+
+  def visit_Lambda(self, node):
+    # Lambda(args=arguments(
+    #            posonlyargs=[arg(...), arg(...), ..., arg(...)],
+    #            args=[arg(...), arg(...), ..., arg(...)],
+    #            kwonlyargs=[arg(...), arg(...), ..., arg(...)],
+    #            kw_defaults=[arg(...), arg(...), ..., arg(...)],
+    #            defaults=[arg(...), arg(...), ..., arg(...)]),
+    #        body=Expr)
+    tokens = self._GetTokens(node)
+    _IncreasePenalty(tokens[1:], split_penalty.LAMBDA)
+
+    if style.Get('ALLOW_MULTILINE_LAMBDAS'):
+      _SetPenalty(self._GetTokens(node.body), split_penalty.MULTIPLINE_LAMBDA)
+
+    return self.generic_visit(node)
+
+  def visit_IfExp(self, node):
+    # IfExp(test=TestExpr,
+    #       body=BodyExpr,
+    #       orelse=OrElseExpr)
+    tokens = self._GetTokens(node)
+    _IncreasePenalty(tokens[1:], split_penalty.EXPR)
+
+    return self.generic_visit(node)
+
+  def visit_Dict(self, node):
+    # Dict(keys=[Expr_1, Expr_2, ..., Expr_n],
+    #      values=[Expr_1, Expr_2, ..., Expr_n])
+    tokens = self._GetTokens(node)
+
+    # The keys should be on a single line if at all possible.
+    for key in node.keys:
+      subrange = pyutils.GetTokensInSubRange(tokens, key)
+      _IncreasePenalty(subrange[1:], split_penalty.DICT_KEY_EXPR)
+
+    for value in node.values:
+      subrange = pyutils.GetTokensInSubRange(tokens, value)
+      _IncreasePenalty(subrange[1:], split_penalty.DICT_VALUE_EXPR)
+
+    return self.generic_visit(node)
+
+  def visit_Set(self, node):
+    # Set(elts=[Expr_1, Expr_2, ..., Expr_n])
+    tokens = self._GetTokens(node)
+    for element in node.elts:
+      subrange = pyutils.GetTokensInSubRange(tokens, element)
+      _IncreasePenalty(subrange[1:], split_penalty.EXPR)
+
+    return self.generic_visit(node)
+
+  def visit_ListComp(self, node):
+    # ListComp(elt=Expr,
+    #          generators=[
+    #              comprehension(
+    #                  target=Expr,
+    #                  iter=Expr,
+    #                  ifs=[Expr_1, Expr_2, ..., Expr_n],
+    #                  is_async=0),
+    #               ...
+    #          ])
+    tokens = self._GetTokens(node)
+    element = pyutils.GetTokensInSubRange(tokens, node.elt)
+    _IncreasePenalty(element[1:], split_penalty.EXPR)
+
+    for comp in node.generators:
+      subrange = pyutils.GetTokensInSubRange(tokens, comp.iter)
+      _IncreasePenalty(subrange[1:], split_penalty.EXPR)
+
+      for if_expr in comp.ifs:
+        subrange = pyutils.GetTokensInSubRange(tokens, if_expr)
+        _IncreasePenalty(subrange[1:], split_penalty.EXPR)
+
+    return self.generic_visit(node)
+
+  def visit_SetComp(self, node):
+    # SetComp(elt=Expr,
+    #         generators=[
+    #             comprehension(
+    #                 target=Expr,
+    #                 iter=Expr,
+    #                 ifs=[Expr_1, Expr_2, ..., Expr_n],
+    #                 is_async=0),
+    #           ...
+    #         ])
+    tokens = self._GetTokens(node)
+    element = pyutils.GetTokensInSubRange(tokens, node.elt)
+    _IncreasePenalty(element[1:], split_penalty.EXPR)
+
+    for comp in node.generators:
+      subrange = pyutils.GetTokensInSubRange(tokens, comp.iter)
+      _IncreasePenalty(subrange[1:], split_penalty.EXPR)
+
+      for if_expr in comp.ifs:
+        subrange = pyutils.GetTokensInSubRange(tokens, if_expr)
+        _IncreasePenalty(subrange[1:], split_penalty.EXPR)
+
+    return self.generic_visit(node)
+
+  def visit_DictComp(self, node):
+    # DictComp(key=KeyExpr,
+    #          value=ValExpr,
+    #          generators=[
+    #              comprehension(
+    #                  target=TargetExpr
+    #                  iter=IterExpr,
+    #                  ifs=[Expr_1, Expr_2, ..., Expr_n]),
+    #                  is_async=0)],
+    #           ...
+    #         ])
+    tokens = self._GetTokens(node)
+    key = pyutils.GetTokensInSubRange(tokens, node.key)
+    _IncreasePenalty(key[1:], split_penalty.EXPR)
+
+    value = pyutils.GetTokensInSubRange(tokens, node.value)
+    _IncreasePenalty(value[1:], split_penalty.EXPR)
+
+    for comp in node.generators:
+      subrange = pyutils.GetTokensInSubRange(tokens, comp.iter)
+      _IncreasePenalty(subrange[1:], split_penalty.EXPR)
+
+      for if_expr in comp.ifs:
+        subrange = pyutils.GetTokensInSubRange(tokens, if_expr)
+        _IncreasePenalty(subrange[1:], split_penalty.EXPR)
+
+    return self.generic_visit(node)
+
+  def visit_GeneratorExp(self, node):
+    # GeneratorExp(elt=Expr,
+    #              generators=[
+    #                  comprehension(
+    #                      target=Expr,
+    #                      iter=Expr,
+    #                      ifs=[Expr_1, Expr_2, ..., Expr_n],
+    #                      is_async=0),
+    #                ...
+    #              ])
+    tokens = self._GetTokens(node)
+    element = pyutils.GetTokensInSubRange(tokens, node.elt)
+    _IncreasePenalty(element[1:], split_penalty.EXPR)
+
+    for comp in node.generators:
+      subrange = pyutils.GetTokensInSubRange(tokens, comp.iter)
+      _IncreasePenalty(subrange[1:], split_penalty.EXPR)
+
+      for if_expr in comp.ifs:
+        subrange = pyutils.GetTokensInSubRange(tokens, if_expr)
+        _IncreasePenalty(subrange[1:], split_penalty.EXPR)
+
+    return self.generic_visit(node)
+
+  def visit_Await(self, node):
+    # Await(value=Expr)
+    tokens = self._GetTokens(node)
+    _IncreasePenalty(tokens[1:], split_penalty.EXPR)
+
+    return self.generic_visit(node)
+
+  def visit_Yield(self, node):
+    # Yield(value=Expr)
+    tokens = self._GetTokens(node)
+    _IncreasePenalty(tokens[1:], split_penalty.EXPR)
+
+    return self.generic_visit(node)
+
+  def visit_YieldFrom(self, node):
+    # YieldFrom(value=Expr)
+    tokens = self._GetTokens(node)
+    _IncreasePenalty(tokens[1:], split_penalty.EXPR)
+    tokens[2].split_penalty = split_penalty.UNBREAKABLE
+
+    return self.generic_visit(node)
+
+  def visit_Compare(self, node):
+    # Compare(left=LExpr,
+    #         ops=[Op_1, Op_2, ..., Op_n],
+    #         comparators=[Expr_1, Expr_2, ..., Expr_n])
+    tokens = self._GetTokens(node)
+    _IncreasePenalty(tokens[1:], split_penalty.EXPR)
+
+    operator_indices = [
+        pyutils.GetNextTokenIndex(tokens, pyutils.TokenEnd(node.left))
+    ] + [
+        pyutils.GetNextTokenIndex(tokens, pyutils.TokenEnd(comparator))
+        for comparator in node.comparators[:-1]
+    ]
+    split_before = style.Get('SPLIT_BEFORE_ARITHMETIC_OPERATOR')
+
+    for operator_index in operator_indices:
+      if not split_before:
+        operator_index += 1
+      _DecreasePenalty(tokens[operator_index], split_penalty.EXPR * 2)
+
+    return self.generic_visit(node)
+
+  def visit_Call(self, node):
+    # Call(func=Expr,
+    #      args=[Expr_1, Expr_2, ..., Expr_n],
+    #      keywords=[
+    #          keyword(
+    #              arg='d',
+    #              value=Expr),
+    #            ...
+    #      ])
+    tokens = self._GetTokens(node)
+
+    # Don't never split before the opening parenthesis.
+    paren_index = pyutils.GetNextTokenIndex(tokens, pyutils.TokenEnd(node.func))
+    _IncreasePenalty(tokens[paren_index], split_penalty.UNBREAKABLE)
+
+    for arg in node.args:
+      subrange = pyutils.GetTokensInSubRange(tokens, arg)
+      _IncreasePenalty(subrange[1:], split_penalty.EXPR)
+
+    return self.generic_visit(node)
+
+  def visit_FormattedValue(self, node):
+    # FormattedValue(value=Expr,
+    #                conversion=-1)
+    return node  # Ignore formatted values.
+
+  def visit_JoinedStr(self, node):
+    # JoinedStr(values=[Expr_1, Expr_2, ..., Expr_n])
+    return self.generic_visit(node)
+
+  def visit_Constant(self, node):
+    # Constant(value=Expr)
+    return self.generic_visit(node)
+
+  def visit_Attribute(self, node):
+    # Attribute(value=Expr,
+    #           attr=Identifier)
+    tokens = self._GetTokens(node)
+    split_before = style.Get('SPLIT_BEFORE_DOT')
+    dot_indices = pyutils.GetNextTokenIndex(tokens,
+                                            pyutils.TokenEnd(node.value))
+
+    if not split_before:
+      dot_indices += 1
+    _IncreasePenalty(tokens[dot_indices], split_penalty.VERY_STRONGLY_CONNECTED)
+
+    return self.generic_visit(node)
+
+  def visit_Subscript(self, node):
+    # Subscript(value=ValueExpr,
+    #           slice=SliceExpr)
+    tokens = self._GetTokens(node)
+
+    # Don't split before the opening bracket of a subscript.
+    bracket_index = pyutils.GetNextTokenIndex(tokens,
+                                              pyutils.TokenEnd(node.value))
+    _IncreasePenalty(tokens[bracket_index], split_penalty.UNBREAKABLE)
+
+    return self.generic_visit(node)
+
+  def visit_Starred(self, node):
+    # Starred(value=Expr)
+    return self.generic_visit(node)
+
+  def visit_Name(self, node):
+    # Name(id=Identifier)
+    tokens = self._GetTokens(node)
+    _IncreasePenalty(tokens[1:], split_penalty.UNBREAKABLE)
+
+    return self.generic_visit(node)
+
+  def visit_List(self, node):
+    # List(elts=[Expr_1, Expr_2, ..., Expr_n])
+    tokens = self._GetTokens(node)
+
+    for element in node.elts:
+      subrange = pyutils.GetTokensInSubRange(tokens, element)
+      _IncreasePenalty(subrange[1:], split_penalty.EXPR)
+      _DecreasePenalty(subrange[0], split_penalty.EXPR // 2)
+
+    return self.generic_visit(node)
+
+  def visit_Tuple(self, node):
+    # Tuple(elts=[Expr_1, Expr_2, ..., Expr_n])
+    tokens = self._GetTokens(node)
+
+    for element in node.elts:
+      subrange = pyutils.GetTokensInSubRange(tokens, element)
+      _IncreasePenalty(subrange[1:], split_penalty.EXPR)
+      _DecreasePenalty(subrange[0], split_penalty.EXPR // 2)
+
+    return self.generic_visit(node)
+
+  def visit_Slice(self, node):
+    # Slice(lower=Expr,
+    #       upper=Expr,
+    #       step=Expr)
+    tokens = self._GetTokens(node)
+
+    if hasattr(node, 'lower') and node.lower:
+      subrange = pyutils.GetTokensInSubRange(tokens, node.lower)
+      _IncreasePenalty(subrange, split_penalty.EXPR)
+      _DecreasePenalty(subrange[0], split_penalty.EXPR // 2)
+
+    if hasattr(node, 'upper') and node.upper:
+      colon_index = pyutils.GetPrevTokenIndex(tokens,
+                                              pyutils.TokenStart(node.upper))
+      _IncreasePenalty(tokens[colon_index], split_penalty.UNBREAKABLE)
+      subrange = pyutils.GetTokensInSubRange(tokens, node.upper)
+      _IncreasePenalty(subrange, split_penalty.EXPR)
+      _DecreasePenalty(subrange[0], split_penalty.EXPR // 2)
+
+    if hasattr(node, 'step') and node.step:
+      colon_index = pyutils.GetPrevTokenIndex(tokens,
+                                              pyutils.TokenStart(node.step))
+      _IncreasePenalty(tokens[colon_index], split_penalty.UNBREAKABLE)
+      subrange = pyutils.GetTokensInSubRange(tokens, node.step)
+      _IncreasePenalty(subrange, split_penalty.EXPR)
+      _DecreasePenalty(subrange[0], split_penalty.EXPR // 2)
+
+    return self.generic_visit(node)
+
+  ############################################################################
+  # Expression Context                                                       #
+  ############################################################################
+
+  def visit_Load(self, node):
+    # Load()
+    return self.generic_visit(node)
+
+  def visit_Store(self, node):
+    # Store()
+    return self.generic_visit(node)
+
+  def visit_Del(self, node):
+    # Del()
+    return self.generic_visit(node)
+
+  ############################################################################
+  # Boolean Operators                                                        #
+  ############################################################################
+
+  def visit_And(self, node):
+    # And()
+    return self.generic_visit(node)
+
+  def visit_Or(self, node):
+    # Or()
+    return self.generic_visit(node)
+
+  ############################################################################
+  # Binary Operators                                                         #
+  ############################################################################
+
+  def visit_Add(self, node):
+    # Add()
+    return self.generic_visit(node)
+
+  def visit_Sub(self, node):
+    # Sub()
+    return self.generic_visit(node)
+
+  def visit_Mult(self, node):
+    # Mult()
+    return self.generic_visit(node)
+
+  def visit_MatMult(self, node):
+    # MatMult()
+    return self.generic_visit(node)
+
+  def visit_Div(self, node):
+    # Div()
+    return self.generic_visit(node)
+
+  def visit_Mod(self, node):
+    # Mod()
+    return self.generic_visit(node)
+
+  def visit_Pow(self, node):
+    # Pow()
+    return self.generic_visit(node)
+
+  def visit_LShift(self, node):
+    # LShift()
+    return self.generic_visit(node)
+
+  def visit_RShift(self, node):
+    # RShift()
+    return self.generic_visit(node)
+
+  def visit_BitOr(self, node):
+    # BitOr()
+    return self.generic_visit(node)
+
+  def visit_BitXor(self, node):
+    # BitXor()
+    return self.generic_visit(node)
+
+  def visit_BitAnd(self, node):
+    # BitAnd()
+    return self.generic_visit(node)
+
+  def visit_FloorDiv(self, node):
+    # FloorDiv()
+    return self.generic_visit(node)
+
+  ############################################################################
+  # Unary Operators                                                          #
+  ############################################################################
+
+  def visit_Invert(self, node):
+    # Invert()
+    return self.generic_visit(node)
+
+  def visit_Not(self, node):
+    # Not()
+    return self.generic_visit(node)
+
+  def visit_UAdd(self, node):
+    # UAdd()
+    return self.generic_visit(node)
+
+  def visit_USub(self, node):
+    # USub()
+    return self.generic_visit(node)
+
+  ############################################################################
+  # Comparison Operators                                                     #
+  ############################################################################
+
+  def visit_Eq(self, node):
+    # Eq()
+    return self.generic_visit(node)
+
+  def visit_NotEq(self, node):
+    # NotEq()
+    return self.generic_visit(node)
+
+  def visit_Lt(self, node):
+    # Lt()
+    return self.generic_visit(node)
+
+  def visit_LtE(self, node):
+    # LtE()
+    return self.generic_visit(node)
+
+  def visit_Gt(self, node):
+    # Gt()
+    return self.generic_visit(node)
+
+  def visit_GtE(self, node):
+    # GtE()
+    return self.generic_visit(node)
+
+  def visit_Is(self, node):
+    # Is()
+    return self.generic_visit(node)
+
+  def visit_IsNot(self, node):
+    # IsNot()
+    return self.generic_visit(node)
+
+  def visit_In(self, node):
+    # In()
+    return self.generic_visit(node)
+
+  def visit_NotIn(self, node):
+    # NotIn()
+    return self.generic_visit(node)
+
+  ############################################################################
+  # Exception Handler                                                        #
+  ############################################################################
+
+  def visit_ExceptionHandler(self, node):
+    # ExceptHandler(type=Expr,
+    #               name=Identifier,
+    #               body=[...])
+    return self.generic_visit(node)
+
+  ############################################################################
+  # Matching Patterns                                                        #
+  ############################################################################
+
+  def visit_MatchValue(self, node):
+    # MatchValue(value=Expr)
+    return self.generic_visit(node)
+
+  def visit_MatchSingleton(self, node):
+    # MatchSingleton(value=Constant)
+    return self.generic_visit(node)
+
+  def visit_MatchSequence(self, node):
+    # MatchSequence(patterns=[pattern_1, pattern_2, ..., pattern_n])
+    return self.generic_visit(node)
+
+  def visit_MatchMapping(self, node):
+    # MatchMapping(keys=[Expr_1, Expr_2, ..., Expr_n],
+    #              patterns=[pattern_1, pattern_2, ..., pattern_m],
+    #              rest=Identifier)
+    return self.generic_visit(node)
+
+  def visit_MatchClass(self, node):
+    # MatchClass(cls=Expr,
+    #            patterns=[pattern_1, pattern_2, ...],
+    #            kwd_attrs=[Identifier_1, Identifier_2, ...],
+    #            kwd_patterns=[pattern_1, pattern_2, ...])
+    return self.generic_visit(node)
+
+  def visit_MatchStar(self, node):
+    # MatchStar(name=Identifier)
+    return self.generic_visit(node)
+
+  def visit_MatchAs(self, node):
+    # MatchAs(pattern=pattern,
+    #         name=Identifier)
+    return self.generic_visit(node)
+
+  def visit_MatchOr(self, node):
+    # MatchOr(patterns=[pattern_1, pattern_2, ...])
+    return self.generic_visit(node)
+
+  ############################################################################
+  # Type Ignore                                                              #
+  ############################################################################
+
+  def visit_TypeIgnore(self, node):
+    # TypeIgnore(tag=string)
+    return self.generic_visit(node)
+
+  ############################################################################
+  # Miscellaneous                                                            #
+  ############################################################################
+
+  def visit_comprehension(self, node):
+    # comprehension(target=Expr,
+    #               iter=Expr,
+    #               ifs=[Expr_1, Expr_2, ..., Expr_n],
+    #               is_async=0)
+    return self.generic_visit(node)
+
+  def visit_arguments(self, node):
+    # arguments(posonlyargs=[arg_1, arg_2, ..., arg_a],
+    #           args=[arg_1, arg_2, ..., arg_b],
+    #           vararg=arg,
+    #           kwonlyargs=[arg_1, arg_2, ..., arg_c],
+    #           kw_defaults=[arg_1, arg_2, ..., arg_d],
+    #           kwarg=arg,
+    #           defaults=[Expr_1, Expr_2, ..., Expr_n])
+    return self.generic_visit(node)
+
+  def visit_arg(self, node):
+    # arg(arg=Identifier,
+    #     annotation=Expr,
+    #     type_comment='')
+    tokens = self._GetTokens(node)
+
+    # Process any annotations.
+    if hasattr(node, 'annotation') and node.annotation:
+      annotation = node.annotation
+      subrange = pyutils.GetTokensInSubRange(tokens, annotation)
+      _IncreasePenalty(subrange, split_penalty.ANNOTATION)
+
+    return self.generic_visit(node)
+
+  def visit_keyword(self, node):
+    # keyword(arg=Identifier,
+    #         value=Expr)
+    return self.generic_visit(node)
+
+  def visit_alias(self, node):
+    # alias(name=Identifier,
+    #       asname=Identifier)
+    return self.generic_visit(node)
+
+  def visit_withitem(self, node):
+    # withitem(context_expr=Expr,
+    #          optional_vars=Expr)
+    return self.generic_visit(node)
+
+  def visit_match_case(self, node):
+    # match_case(pattern=pattern,
+    #            guard=Expr,
+    #            body=[...])
+    return self.generic_visit(node)
+
+
+def _IncreasePenalty(tokens, amt):
+  if not isinstance(tokens, list):
+    tokens = [tokens]
+  for token in tokens:
+    token.split_penalty += amt
+
+
+def _DecreasePenalty(tokens, amt):
+  if not isinstance(tokens, list):
+    tokens = [tokens]
+  for token in tokens:
+    token.split_penalty -= amt
+
+
+def _SetPenalty(tokens, amt):
+  if not isinstance(tokens, list):
+    tokens = [tokens]
+  for token in tokens:
+    token.split_penalty = amt
diff --git a/yapf/pytree/__init__.py b/yapf/pytree/__init__.py
new file mode 100644
index 0000000..8aa1c83
--- /dev/null
+++ b/yapf/pytree/__init__.py
@@ -0,0 +1,13 @@
+# Copyright 2021 Google Inc. All Rights Reserved.
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
diff --git a/yapf/yapflib/blank_line_calculator.py b/yapf/pytree/blank_line_calculator.py
similarity index 95%
rename from yapf/yapflib/blank_line_calculator.py
rename to yapf/pytree/blank_line_calculator.py
index 3d78646..32faaa2 100644
--- a/yapf/yapflib/blank_line_calculator.py
+++ b/yapf/pytree/blank_line_calculator.py
@@ -22,11 +22,10 @@ Annotations:
   newlines: The number of newlines required before the node.
 """
 
-from lib2to3.pgen2 import token as grammar_token
+from yapf_third_party._ylib2to3.pgen2 import token as grammar_token
 
-from yapf.yapflib import py3compat
-from yapf.yapflib import pytree_utils
-from yapf.yapflib import pytree_visitor
+from yapf.pytree import pytree_utils
+from yapf.pytree import pytree_visitor
 from yapf.yapflib import style
 
 _NO_BLANK_LINES = 1
@@ -175,5 +174,4 @@ def _StartsInZerothColumn(node):
 
 
 def _AsyncFunction(node):
-  return (py3compat.PY3 and node.prev_sibling and
-          node.prev_sibling.type == grammar_token.ASYNC)
+  return (node.prev_sibling and node.prev_sibling.type == grammar_token.ASYNC)
diff --git a/yapf/yapflib/comment_splicer.py b/yapf/pytree/comment_splicer.py
similarity index 98%
rename from yapf/yapflib/comment_splicer.py
rename to yapf/pytree/comment_splicer.py
index 535711b..a9180f3 100644
--- a/yapf/yapflib/comment_splicer.py
+++ b/yapf/pytree/comment_splicer.py
@@ -21,11 +21,11 @@ making them easier to process.
   SpliceComments(): the main function exported by this module.
 """
 
-from lib2to3 import pygram
-from lib2to3 import pytree
-from lib2to3.pgen2 import token
+from yapf_third_party._ylib2to3 import pygram
+from yapf_third_party._ylib2to3 import pytree
+from yapf_third_party._ylib2to3.pgen2 import token
 
-from yapf.yapflib import pytree_utils
+from yapf.pytree import pytree_utils
 
 
 def SpliceComments(tree):
diff --git a/yapf/yapflib/continuation_splicer.py b/yapf/pytree/continuation_splicer.py
similarity index 97%
rename from yapf/yapflib/continuation_splicer.py
rename to yapf/pytree/continuation_splicer.py
index b86188c..a8aef66 100644
--- a/yapf/yapflib/continuation_splicer.py
+++ b/yapf/pytree/continuation_splicer.py
@@ -19,7 +19,7 @@ Pull them out and make it into nodes of their own.
   SpliceContinuations(): the main function exported by this module.
 """
 
-from lib2to3 import pytree
+from yapf_third_party._ylib2to3 import pytree
 
 from yapf.yapflib import format_token
 
diff --git a/yapf/yapflib/pytree_unwrapper.py b/yapf/pytree/pytree_unwrapper.py
similarity index 88%
rename from yapf/yapflib/pytree_unwrapper.py
rename to yapf/pytree/pytree_unwrapper.py
index 1b05b0e..80e050f 100644
--- a/yapf/yapflib/pytree_unwrapper.py
+++ b/yapf/pytree/pytree_unwrapper.py
@@ -28,18 +28,21 @@ For most uses, the convenience function UnwrapPyTree should be sufficient.
 
 # The word "token" is overloaded within this module, so for clarity rename
 # the imported pgen2.token module.
-from lib2to3 import pytree
-from lib2to3.pgen2 import token as grammar_token
+from yapf_third_party._ylib2to3 import pytree
+from yapf_third_party._ylib2to3.pgen2 import token as grammar_token
 
+from yapf.pytree import pytree_utils
+from yapf.pytree import pytree_visitor
+from yapf.pytree import split_penalty
 from yapf.yapflib import format_token
 from yapf.yapflib import logical_line
 from yapf.yapflib import object_state
-from yapf.yapflib import pytree_utils
-from yapf.yapflib import pytree_visitor
-from yapf.yapflib import split_penalty
 from yapf.yapflib import style
 from yapf.yapflib import subtypes
 
+_OPENING_BRACKETS = frozenset({'(', '[', '{'})
+_CLOSING_BRACKETS = frozenset({')', ']', '}'})
+
 
 def UnwrapPyTree(tree):
   """Create and return a list of logical lines from the given pytree.
@@ -122,6 +125,8 @@ class PyTreeUnwrapper(pytree_visitor.PyTreeVisitor):
       'try_stmt',
       'expect_clause',
       'with_stmt',
+      'match_stmt',
+      'case_block',
       'funcdef',
       'classdef',
   })
@@ -141,11 +146,13 @@ class PyTreeUnwrapper(pytree_visitor.PyTreeVisitor):
     single_stmt_suite = (
         node.parent and pytree_utils.NodeName(node.parent) in self._STMT_TYPES)
     is_comment_stmt = pytree_utils.IsCommentStatement(node)
-    if single_stmt_suite and not is_comment_stmt:
+    is_inside_match = node.parent and pytree_utils.NodeName(
+        node.parent) == 'match_stmt'
+    if (single_stmt_suite and not is_comment_stmt) or is_inside_match:
       self._cur_depth += 1
     self._StartNewLine()
     self.DefaultNodeVisit(node)
-    if single_stmt_suite and not is_comment_stmt:
+    if (single_stmt_suite and not is_comment_stmt) or is_inside_match:
       self._cur_depth -= 1
 
   def _VisitCompoundStatement(self, node, substatement_names):
@@ -250,6 +257,20 @@ class PyTreeUnwrapper(pytree_visitor.PyTreeVisitor):
   def Visit_with_stmt(self, node):  # pylint: disable=invalid-name
     self._VisitCompoundStatement(node, self._WITH_STMT_ELEMS)
 
+  _MATCH_STMT_ELEMS = frozenset({'match', 'case'})
+
+  def Visit_match_stmt(self, node):  # pylint: disable=invalid-name
+    self._VisitCompoundStatement(node, self._MATCH_STMT_ELEMS)
+
+  # case_block refers to the grammar element name in Grammar.txt
+  _CASE_BLOCK_ELEMS = frozenset({'case'})
+
+  def Visit_case_block(self, node):
+    self._cur_depth += 1
+    self._StartNewLine()
+    self._VisitCompoundStatement(node, self._CASE_BLOCK_ELEMS)
+    self._cur_depth -= 1
+
   def Visit_suite(self, node):  # pylint: disable=invalid-name
     # A 'suite' starts a new indentation level in Python.
     self._cur_depth += 1
@@ -282,6 +303,10 @@ class PyTreeUnwrapper(pytree_visitor.PyTreeVisitor):
     _DetermineMustSplitAnnotation(node)
     self.DefaultNodeVisit(node)
 
+  def Visit_subscriptlist(self, node):  # pylint: disable=invalid-name
+    _DetermineMustSplitAnnotation(node)
+    self.DefaultNodeVisit(node)
+
   def DefaultLeafVisit(self, leaf):
     """Default visitor for tree leaves.
 
@@ -294,7 +319,8 @@ class PyTreeUnwrapper(pytree_visitor.PyTreeVisitor):
       self._StartNewLine()
     elif leaf.type != grammar_token.COMMENT or leaf.value.strip():
       # Add non-whitespace tokens and comments that aren't empty.
-      self._cur_logical_line.AppendNode(leaf)
+      self._cur_logical_line.AppendToken(
+          format_token.FormatToken(leaf, pytree_utils.NodeName(leaf)))
 
 
 _BRACKET_MATCH = {')': '(', '}': '{', ']': '['}
@@ -312,9 +338,9 @@ def _MatchBrackets(line):
   """
   bracket_stack = []
   for token in line.tokens:
-    if token.value in pytree_utils.OPENING_BRACKETS:
+    if token.value in _OPENING_BRACKETS:
       bracket_stack.append(token)
-    elif token.value in pytree_utils.CLOSING_BRACKETS:
+    elif token.value in _CLOSING_BRACKETS:
       bracket_stack[-1].matching_bracket = token
       token.matching_bracket = bracket_stack[-1]
       bracket_stack.pop()
@@ -373,24 +399,35 @@ def _AdjustSplitPenalty(line):
       pytree_utils.SetNodeAnnotation(token.node,
                                      pytree_utils.Annotation.SPLIT_PENALTY,
                                      split_penalty.UNBREAKABLE)
-    if token.value in pytree_utils.OPENING_BRACKETS:
+    if token.value in _OPENING_BRACKETS:
       bracket_level += 1
-    elif token.value in pytree_utils.CLOSING_BRACKETS:
+    elif token.value in _CLOSING_BRACKETS:
       bracket_level -= 1
 
 
 def _DetermineMustSplitAnnotation(node):
   """Enforce a split in the list if the list ends with a comma."""
-  if style.Get('DISABLE_ENDING_COMMA_HEURISTIC'):
-    return
-  if not _ContainsComments(node):
+
+  def SplitBecauseTrailingComma():
+    if style.Get('DISABLE_ENDING_COMMA_HEURISTIC'):
+      return False
     token = next(node.parent.leaves())
     if token.value == '(':
       if sum(1 for ch in node.children if ch.type == grammar_token.COMMA) < 2:
-        return
+        return False
     if (not isinstance(node.children[-1], pytree.Leaf) or
         node.children[-1].value != ','):
-      return
+      return False
+    return True
+
+  def SplitBecauseListContainsComment():
+    return (not style.Get('DISABLE_SPLIT_LIST_WITH_COMMENT') and
+            _ContainsComments(node))
+
+  if (not SplitBecauseTrailingComma() and
+      not SplitBecauseListContainsComment()):
+    return
+
   num_children = len(node.children)
   index = 0
   _SetMustSplitOnFirstLeaf(node.children[0])
diff --git a/yapf/yapflib/pytree_utils.py b/yapf/pytree/pytree_utils.py
similarity index 89%
rename from yapf/yapflib/pytree_utils.py
rename to yapf/pytree/pytree_utils.py
index 8762032..e7aa6f5 100644
--- a/yapf/yapflib/pytree_utils.py
+++ b/yapf/pytree/pytree_utils.py
@@ -27,11 +27,11 @@ the lib2to3 library.
 import ast
 import os
 
-from lib2to3 import pygram
-from lib2to3 import pytree
-from lib2to3.pgen2 import driver
-from lib2to3.pgen2 import parse
-from lib2to3.pgen2 import token
+from yapf_third_party._ylib2to3 import pygram
+from yapf_third_party._ylib2to3 import pytree
+from yapf_third_party._ylib2to3.pgen2 import driver
+from yapf_third_party._ylib2to3.pgen2 import parse
+from yapf_third_party._ylib2to3.pgen2 import token
 
 # TODO(eliben): We may want to get rid of this filtering at some point once we
 # have a better understanding of what information we need from the tree. Then,
@@ -39,9 +39,6 @@ from lib2to3.pgen2 import token
 # unwrapper.
 NONSEMANTIC_TOKENS = frozenset(['DEDENT', 'INDENT', 'NEWLINE', 'ENDMARKER'])
 
-OPENING_BRACKETS = frozenset({'(', '[', '{'})
-CLOSING_BRACKETS = frozenset({')', ']', '}'})
-
 
 class Annotation(object):
   """Annotation names associated with pytrees."""
@@ -87,11 +84,10 @@ def LastLeafNode(node):
 # context where a keyword is disallowed).
 # It forgets to do the same for 'exec' though. Luckily, Python is amenable to
 # monkey-patching.
-_GRAMMAR_FOR_PY3 = pygram.python_grammar_no_print_statement.copy()
-del _GRAMMAR_FOR_PY3.keywords['exec']
-
-_GRAMMAR_FOR_PY2 = pygram.python_grammar.copy()
-del _GRAMMAR_FOR_PY2.keywords['nonlocal']
+# Note that pygram.python_grammar_no_print_and_exec_statement with "_and_exec"
+# will require Python >=3.8.
+_PYTHON_GRAMMAR = pygram.python_grammar_no_print_statement.copy()
+del _PYTHON_GRAMMAR.keywords['exec']
 
 
 def ParseCodeToTree(code):
@@ -113,24 +109,12 @@ def ParseCodeToTree(code):
     code += os.linesep
 
   try:
-    # Try to parse using a Python 3 grammar, which is more permissive (print and
-    # exec are not keywords).
-    parser_driver = driver.Driver(_GRAMMAR_FOR_PY3, convert=pytree.convert)
+    parser_driver = driver.Driver(_PYTHON_GRAMMAR, convert=pytree.convert)
     tree = parser_driver.parse_string(code, debug=False)
   except parse.ParseError:
-    # Now try to parse using a Python 2 grammar; If this fails, then
-    # there's something else wrong with the code.
-    try:
-      parser_driver = driver.Driver(_GRAMMAR_FOR_PY2, convert=pytree.convert)
-      tree = parser_driver.parse_string(code, debug=False)
-    except parse.ParseError:
-      # Raise a syntax error if the code is invalid python syntax.
-      try:
-        ast.parse(code)
-      except SyntaxError as e:
-        raise e
-      else:
-        raise
+    # Raise a syntax error if the code is invalid python syntax.
+    ast.parse(code)
+    raise
   return _WrapEndMarker(tree)
 
 
diff --git a/yapf/yapflib/pytree_visitor.py b/yapf/pytree/pytree_visitor.py
similarity index 98%
rename from yapf/yapflib/pytree_visitor.py
rename to yapf/pytree/pytree_visitor.py
index a39331c..ec2cdb7 100644
--- a/yapf/yapflib/pytree_visitor.py
+++ b/yapf/pytree/pytree_visitor.py
@@ -26,9 +26,9 @@ a pytree into a stream.
 
 import sys
 
-from lib2to3 import pytree
+from yapf_third_party._ylib2to3 import pytree
 
-from yapf.yapflib import pytree_utils
+from yapf.pytree import pytree_utils
 
 
 class PyTreeVisitor(object):
diff --git a/yapf/pytree/split_penalty.py b/yapf/pytree/split_penalty.py
new file mode 100644
index 0000000..03b3638
--- /dev/null
+++ b/yapf/pytree/split_penalty.py
@@ -0,0 +1,632 @@
+# Copyright 2015 Google Inc. All Rights Reserved.
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
+"""Computation of split penalties before/between tokens."""
+
+import re
+
+from yapf_third_party._ylib2to3 import pytree
+from yapf_third_party._ylib2to3.pgen2 import token as grammar_token
+
+from yapf.pytree import pytree_utils
+from yapf.pytree import pytree_visitor
+from yapf.yapflib import style
+from yapf.yapflib import subtypes
+
+# TODO(morbo): Document the annotations in a centralized place. E.g., the
+# README file.
+UNBREAKABLE = 1000 * 1000
+NAMED_ASSIGN = 15000
+DOTTED_NAME = 4000
+VERY_STRONGLY_CONNECTED = 3500
+STRONGLY_CONNECTED = 3000
+CONNECTED = 500
+TOGETHER = 100
+
+OR_TEST = 1000
+AND_TEST = 1100
+NOT_TEST = 1200
+COMPARISON = 1300
+STAR_EXPR = 1300
+EXPR = 1400
+XOR_EXPR = 1500
+AND_EXPR = 1700
+SHIFT_EXPR = 1800
+ARITH_EXPR = 1900
+TERM = 2000
+FACTOR = 2100
+POWER = 2200
+ATOM = 2300
+ONE_ELEMENT_ARGUMENT = 500
+SUBSCRIPT = 6000
+
+
+def ComputeSplitPenalties(tree):
+  """Compute split penalties on tokens in the given parse tree.
+
+  Arguments:
+    tree: the top-level pytree node to annotate with penalties.
+  """
+  _SplitPenaltyAssigner().Visit(tree)
+
+
+class _SplitPenaltyAssigner(pytree_visitor.PyTreeVisitor):
+  """Assigns split penalties to tokens, based on parse tree structure.
+
+  Split penalties are attached as annotations to tokens.
+  """
+
+  def Visit(self, node):
+    if not hasattr(node, 'is_pseudo'):  # Ignore pseudo tokens.
+      super(_SplitPenaltyAssigner, self).Visit(node)
+
+  def Visit_import_as_names(self, node):  # pyline: disable=invalid-name
+    # import_as_names ::= import_as_name (',' import_as_name)* [',']
+    self.DefaultNodeVisit(node)
+    prev_child = None
+    for child in node.children:
+      if (prev_child and isinstance(prev_child, pytree.Leaf) and
+          prev_child.value == ','):
+        _SetSplitPenalty(child, style.Get('SPLIT_PENALTY_IMPORT_NAMES'))
+      prev_child = child
+
+  def Visit_classdef(self, node):  # pylint: disable=invalid-name
+    # classdef ::= 'class' NAME ['(' [arglist] ')'] ':' suite
+    #
+    # NAME
+    _SetUnbreakable(node.children[1])
+    if len(node.children) > 4:
+      # opening '('
+      _SetUnbreakable(node.children[2])
+    # ':'
+    _SetUnbreakable(node.children[-2])
+    self.DefaultNodeVisit(node)
+
+  def Visit_funcdef(self, node):  # pylint: disable=invalid-name
+    # funcdef ::= 'def' NAME parameters ['->' test] ':' suite
+    #
+    # Can't break before the function name and before the colon. The parameters
+    # are handled by child iteration.
+    colon_idx = 1
+    while pytree_utils.NodeName(node.children[colon_idx]) == 'simple_stmt':
+      colon_idx += 1
+    _SetUnbreakable(node.children[colon_idx])
+    arrow_idx = -1
+    while colon_idx < len(node.children):
+      if isinstance(node.children[colon_idx], pytree.Leaf):
+        if node.children[colon_idx].value == ':':
+          break
+        if node.children[colon_idx].value == '->':
+          arrow_idx = colon_idx
+      colon_idx += 1
+    _SetUnbreakable(node.children[colon_idx])
+    self.DefaultNodeVisit(node)
+    if arrow_idx > 0:
+      _SetSplitPenalty(
+          pytree_utils.LastLeafNode(node.children[arrow_idx - 1]), 0)
+      _SetUnbreakable(node.children[arrow_idx])
+      _SetStronglyConnected(node.children[arrow_idx + 1])
+
+  def Visit_lambdef(self, node):  # pylint: disable=invalid-name
+    # lambdef ::= 'lambda' [varargslist] ':' test
+    # Loop over the lambda up to and including the colon.
+    allow_multiline_lambdas = style.Get('ALLOW_MULTILINE_LAMBDAS')
+    if not allow_multiline_lambdas:
+      for child in node.children:
+        if child.type == grammar_token.COMMENT:
+          if re.search(r'pylint:.*disable=.*\bg-long-lambda', child.value):
+            allow_multiline_lambdas = True
+            break
+
+    if allow_multiline_lambdas:
+      _SetExpressionPenalty(node, STRONGLY_CONNECTED)
+    else:
+      _SetExpressionPenalty(node, VERY_STRONGLY_CONNECTED)
+
+  def Visit_parameters(self, node):  # pylint: disable=invalid-name
+    # parameters ::= '(' [typedargslist] ')'
+    self.DefaultNodeVisit(node)
+
+    # Can't break before the opening paren of a parameter list.
+    _SetUnbreakable(node.children[0])
+    if not (style.Get('INDENT_CLOSING_BRACKETS') or
+            style.Get('DEDENT_CLOSING_BRACKETS')):
+      _SetStronglyConnected(node.children[-1])
+
+  def Visit_arglist(self, node):  # pylint: disable=invalid-name
+    # arglist ::= argument (',' argument)* [',']
+    if node.children[0].type == grammar_token.STAR:
+      # Python 3 treats a star expression as a specific expression type.
+      # Process it in that method.
+      self.Visit_star_expr(node)
+      return
+
+    self.DefaultNodeVisit(node)
+
+    for index in range(1, len(node.children)):
+      child = node.children[index]
+      if isinstance(child, pytree.Leaf) and child.value == ',':
+        _SetUnbreakable(child)
+
+    for child in node.children:
+      if pytree_utils.NodeName(child) == 'atom':
+        _IncreasePenalty(child, CONNECTED)
+
+  def Visit_argument(self, node):  # pylint: disable=invalid-name
+    # argument ::= test [comp_for] | test '=' test  # Really [keyword '='] test
+    self.DefaultNodeVisit(node)
+
+    for index in range(1, len(node.children) - 1):
+      child = node.children[index]
+      if isinstance(child, pytree.Leaf) and child.value == '=':
+        _SetSplitPenalty(
+            pytree_utils.FirstLeafNode(node.children[index]), NAMED_ASSIGN)
+        _SetSplitPenalty(
+            pytree_utils.FirstLeafNode(node.children[index + 1]), NAMED_ASSIGN)
+
+  def Visit_tname(self, node):  # pylint: disable=invalid-name
+    # tname ::= NAME [':' test]
+    self.DefaultNodeVisit(node)
+
+    for index in range(1, len(node.children) - 1):
+      child = node.children[index]
+      if isinstance(child, pytree.Leaf) and child.value == ':':
+        _SetSplitPenalty(
+            pytree_utils.FirstLeafNode(node.children[index]), NAMED_ASSIGN)
+        _SetSplitPenalty(
+            pytree_utils.FirstLeafNode(node.children[index + 1]), NAMED_ASSIGN)
+
+  def Visit_dotted_name(self, node):  # pylint: disable=invalid-name
+    # dotted_name ::= NAME ('.' NAME)*
+    for child in node.children:
+      self.Visit(child)
+    start = 2 if hasattr(node.children[0], 'is_pseudo') else 1
+    for i in range(start, len(node.children)):
+      _SetUnbreakable(node.children[i])
+
+  def Visit_dictsetmaker(self, node):  # pylint: disable=invalid-name
+    # dictsetmaker ::= ( (test ':' test
+    #                      (comp_for | (',' test ':' test)* [','])) |
+    #                    (test (comp_for | (',' test)* [','])) )
+    for child in node.children:
+      self.Visit(child)
+      if child.type == grammar_token.COLON:
+        # This is a key to a dictionary. We don't want to split the key if at
+        # all possible.
+        _SetStronglyConnected(child)
+
+  def Visit_trailer(self, node):  # pylint: disable=invalid-name
+    # trailer ::= '(' [arglist] ')' | '[' subscriptlist ']' | '.' NAME
+    if node.children[0].value == '.':
+      before = style.Get('SPLIT_BEFORE_DOT')
+      _SetSplitPenalty(node.children[0],
+                       VERY_STRONGLY_CONNECTED if before else DOTTED_NAME)
+      _SetSplitPenalty(node.children[1],
+                       DOTTED_NAME if before else VERY_STRONGLY_CONNECTED)
+    elif len(node.children) == 2:
+      # Don't split an empty argument list if at all possible.
+      _SetSplitPenalty(node.children[1], VERY_STRONGLY_CONNECTED)
+    elif len(node.children) == 3:
+      name = pytree_utils.NodeName(node.children[1])
+      if name in {'argument', 'comparison'}:
+        # Don't split an argument list with one element if at all possible.
+        _SetStronglyConnected(node.children[1])
+        if (len(node.children[1].children) > 1 and
+            pytree_utils.NodeName(node.children[1].children[1]) == 'comp_for'):
+          # Don't penalize splitting before a comp_for expression.
+          _SetSplitPenalty(pytree_utils.FirstLeafNode(node.children[1]), 0)
+        else:
+          _SetSplitPenalty(
+              pytree_utils.FirstLeafNode(node.children[1]),
+              ONE_ELEMENT_ARGUMENT)
+      elif (node.children[0].type == grammar_token.LSQB and
+            len(node.children[1].children) > 2 and
+            (name.endswith('_test') or name.endswith('_expr'))):
+        _SetStronglyConnected(node.children[1].children[0])
+        _SetStronglyConnected(node.children[1].children[2])
+
+        # Still allow splitting around the operator.
+        split_before = ((name.endswith('_test') and
+                         style.Get('SPLIT_BEFORE_LOGICAL_OPERATOR')) or
+                        (name.endswith('_expr') and
+                         style.Get('SPLIT_BEFORE_BITWISE_OPERATOR')))
+        if split_before:
+          _SetSplitPenalty(
+              pytree_utils.LastLeafNode(node.children[1].children[1]), 0)
+        else:
+          _SetSplitPenalty(
+              pytree_utils.FirstLeafNode(node.children[1].children[2]), 0)
+
+        # Don't split the ending bracket of a subscript list.
+        _RecAnnotate(node.children[-1], pytree_utils.Annotation.SPLIT_PENALTY,
+                     VERY_STRONGLY_CONNECTED)
+      elif name not in {
+          'arglist', 'argument', 'term', 'or_test', 'and_test', 'comparison',
+          'atom', 'power'
+      }:
+        # Don't split an argument list with one element if at all possible.
+        stypes = pytree_utils.GetNodeAnnotation(
+            pytree_utils.FirstLeafNode(node), pytree_utils.Annotation.SUBTYPE)
+        if stypes and subtypes.SUBSCRIPT_BRACKET in stypes:
+          _IncreasePenalty(node, SUBSCRIPT)
+
+          # Bump up the split penalty for the first part of a subscript. We
+          # would rather not split there.
+          _IncreasePenalty(node.children[1], CONNECTED)
+        else:
+          _SetStronglyConnected(node.children[1], node.children[2])
+
+      if name == 'arglist':
+        _SetStronglyConnected(node.children[-1])
+
+    self.DefaultNodeVisit(node)
+
+  def Visit_power(self, node):  # pylint: disable=invalid-name,missing-docstring
+    # power ::= atom trailer* ['**' factor]
+    self.DefaultNodeVisit(node)
+
+    # When atom is followed by a trailer, we can not break between them.
+    # E.g. arr[idx] - no break allowed between 'arr' and '['.
+    if (len(node.children) > 1 and
+        pytree_utils.NodeName(node.children[1]) == 'trailer'):
+      # children[1] itself is a whole trailer: we don't want to
+      # mark all of it as unbreakable, only its first token: (, [ or .
+      first = pytree_utils.FirstLeafNode(node.children[1])
+      if first.value != '.':
+        _SetUnbreakable(node.children[1].children[0])
+
+      # A special case when there are more trailers in the sequence. Given:
+      #   atom tr1 tr2
+      # The last token of tr1 and the first token of tr2 comprise an unbreakable
+      # region. For example: foo.bar.baz(1)
+      # We can't put breaks between either of the '.', '(', or '[' and the names
+      # *preceding* them.
+      prev_trailer_idx = 1
+      while prev_trailer_idx < len(node.children) - 1:
+        cur_trailer_idx = prev_trailer_idx + 1
+        cur_trailer = node.children[cur_trailer_idx]
+        if pytree_utils.NodeName(cur_trailer) != 'trailer':
+          break
+
+        # Now we know we have two trailers one after the other
+        prev_trailer = node.children[prev_trailer_idx]
+        if prev_trailer.children[-1].value != ')':
+          # Set the previous node unbreakable if it's not a function call:
+          #   atom tr1() tr2
+          # It may be necessary (though undesirable) to split up a previous
+          # function call's parentheses to the next line.
+          _SetStronglyConnected(prev_trailer.children[-1])
+        _SetStronglyConnected(cur_trailer.children[0])
+        prev_trailer_idx = cur_trailer_idx
+
+    # We don't want to split before the last ')' of a function call. This also
+    # takes care of the special case of:
+    #   atom tr1 tr2 ... trn
+    # where the 'tr#' are trailers that may end in a ')'.
+    for trailer in node.children[1:]:
+      if pytree_utils.NodeName(trailer) != 'trailer':
+        break
+      if trailer.children[0].value in '([':
+        if len(trailer.children) > 2:
+          stypes = pytree_utils.GetNodeAnnotation(
+              trailer.children[0], pytree_utils.Annotation.SUBTYPE)
+          if stypes and subtypes.SUBSCRIPT_BRACKET in stypes:
+            _SetStronglyConnected(
+                pytree_utils.FirstLeafNode(trailer.children[1]))
+
+          last_child_node = pytree_utils.LastLeafNode(trailer)
+          if last_child_node.value.strip().startswith('#'):
+            last_child_node = last_child_node.prev_sibling
+          if not (style.Get('INDENT_CLOSING_BRACKETS') or
+                  style.Get('DEDENT_CLOSING_BRACKETS')):
+            last = pytree_utils.LastLeafNode(last_child_node.prev_sibling)
+            if last.value != ',':
+              if last_child_node.value == ']':
+                _SetUnbreakable(last_child_node)
+              else:
+                _SetSplitPenalty(last_child_node, VERY_STRONGLY_CONNECTED)
+        else:
+          # If the trailer's children are '()', then make it a strongly
+          # connected region.  It's sometimes necessary, though undesirable, to
+          # split the two.
+          _SetStronglyConnected(trailer.children[-1])
+
+  def Visit_subscriptlist(self, node):  # pylint: disable=invalid-name
+    # subscriptlist ::= subscript (',' subscript)* [',']
+    self.DefaultNodeVisit(node)
+    _SetSplitPenalty(pytree_utils.FirstLeafNode(node), 0)
+    prev_child = None
+    for child in node.children:
+      if prev_child and prev_child.type == grammar_token.COMMA:
+        _SetSplitPenalty(pytree_utils.FirstLeafNode(child), 0)
+      prev_child = child
+
+  def Visit_subscript(self, node):  # pylint: disable=invalid-name
+    # subscript ::= test | [test] ':' [test] [sliceop]
+    _SetStronglyConnected(*node.children)
+    self.DefaultNodeVisit(node)
+
+  def Visit_comp_for(self, node):  # pylint: disable=invalid-name
+    # comp_for ::= 'for' exprlist 'in' testlist_safe [comp_iter]
+    _SetSplitPenalty(pytree_utils.FirstLeafNode(node), 0)
+    _SetStronglyConnected(*node.children[1:])
+    self.DefaultNodeVisit(node)
+
+  def Visit_old_comp_for(self, node):  # pylint: disable=invalid-name
+    # Python 3.7
+    self.Visit_comp_for(node)
+
+  def Visit_comp_if(self, node):  # pylint: disable=invalid-name
+    # comp_if ::= 'if' old_test [comp_iter]
+    _SetSplitPenalty(node.children[0],
+                     style.Get('SPLIT_PENALTY_BEFORE_IF_EXPR'))
+    _SetStronglyConnected(*node.children[1:])
+    self.DefaultNodeVisit(node)
+
+  def Visit_old_comp_if(self, node):  # pylint: disable=invalid-name
+    # Python 3.7
+    self.Visit_comp_if(node)
+
+  def Visit_test(self, node):  # pylint: disable=invalid-name
+    # test ::= or_test ['if' or_test 'else' test] | lambdef
+    _IncreasePenalty(node, OR_TEST)
+    self.DefaultNodeVisit(node)
+
+  def Visit_or_test(self, node):  # pylint: disable=invalid-name
+    # or_test ::= and_test ('or' and_test)*
+    self.DefaultNodeVisit(node)
+    _IncreasePenalty(node, OR_TEST)
+    index = 1
+    while index + 1 < len(node.children):
+      if style.Get('SPLIT_BEFORE_LOGICAL_OPERATOR'):
+        _DecrementSplitPenalty(
+            pytree_utils.FirstLeafNode(node.children[index]), OR_TEST)
+      else:
+        _DecrementSplitPenalty(
+            pytree_utils.FirstLeafNode(node.children[index + 1]), OR_TEST)
+      index += 2
+
+  def Visit_and_test(self, node):  # pylint: disable=invalid-name
+    # and_test ::= not_test ('and' not_test)*
+    self.DefaultNodeVisit(node)
+    _IncreasePenalty(node, AND_TEST)
+    index = 1
+    while index + 1 < len(node.children):
+      if style.Get('SPLIT_BEFORE_LOGICAL_OPERATOR'):
+        _DecrementSplitPenalty(
+            pytree_utils.FirstLeafNode(node.children[index]), AND_TEST)
+      else:
+        _DecrementSplitPenalty(
+            pytree_utils.FirstLeafNode(node.children[index + 1]), AND_TEST)
+      index += 2
+
+  def Visit_not_test(self, node):  # pylint: disable=invalid-name
+    # not_test ::= 'not' not_test | comparison
+    self.DefaultNodeVisit(node)
+    _IncreasePenalty(node, NOT_TEST)
+
+  def Visit_comparison(self, node):  # pylint: disable=invalid-name
+    # comparison ::= expr (comp_op expr)*
+    self.DefaultNodeVisit(node)
+    if len(node.children) == 3 and _StronglyConnectedCompOp(node):
+      _IncreasePenalty(node.children[1], VERY_STRONGLY_CONNECTED)
+      _SetSplitPenalty(
+          pytree_utils.FirstLeafNode(node.children[2]), STRONGLY_CONNECTED)
+    else:
+      _IncreasePenalty(node, COMPARISON)
+
+  def Visit_star_expr(self, node):  # pylint: disable=invalid-name
+    # star_expr ::= '*' expr
+    self.DefaultNodeVisit(node)
+    _IncreasePenalty(node, STAR_EXPR)
+
+  def Visit_expr(self, node):  # pylint: disable=invalid-name
+    # expr ::= xor_expr ('|' xor_expr)*
+    self.DefaultNodeVisit(node)
+    _IncreasePenalty(node, EXPR)
+    _SetBitwiseOperandPenalty(node, '|')
+
+  def Visit_xor_expr(self, node):  # pylint: disable=invalid-name
+    # xor_expr ::= and_expr ('^' and_expr)*
+    self.DefaultNodeVisit(node)
+    _IncreasePenalty(node, XOR_EXPR)
+    _SetBitwiseOperandPenalty(node, '^')
+
+  def Visit_and_expr(self, node):  # pylint: disable=invalid-name
+    # and_expr ::= shift_expr ('&' shift_expr)*
+    self.DefaultNodeVisit(node)
+    _IncreasePenalty(node, AND_EXPR)
+    _SetBitwiseOperandPenalty(node, '&')
+
+  def Visit_shift_expr(self, node):  # pylint: disable=invalid-name
+    # shift_expr ::= arith_expr (('<<'|'>>') arith_expr)*
+    self.DefaultNodeVisit(node)
+    _IncreasePenalty(node, SHIFT_EXPR)
+
+  _ARITH_OPS = frozenset({'PLUS', 'MINUS'})
+
+  def Visit_arith_expr(self, node):  # pylint: disable=invalid-name
+    # arith_expr ::= term (('+'|'-') term)*
+    self.DefaultNodeVisit(node)
+    _IncreasePenalty(node, ARITH_EXPR)
+    _SetExpressionOperandPenalty(node, self._ARITH_OPS)
+
+  _TERM_OPS = frozenset({'STAR', 'AT', 'SLASH', 'PERCENT', 'DOUBLESLASH'})
+
+  def Visit_term(self, node):  # pylint: disable=invalid-name
+    # term ::= factor (('*'|'@'|'/'|'%'|'//') factor)*
+    self.DefaultNodeVisit(node)
+    _IncreasePenalty(node, TERM)
+    _SetExpressionOperandPenalty(node, self._TERM_OPS)
+
+  def Visit_factor(self, node):  # pyline: disable=invalid-name
+    # factor ::= ('+'|'-'|'~') factor | power
+    self.DefaultNodeVisit(node)
+    _IncreasePenalty(node, FACTOR)
+
+  def Visit_atom(self, node):  # pylint: disable=invalid-name
+    # atom ::= ('(' [yield_expr|testlist_gexp] ')'
+    #           '[' [listmaker] ']' |
+    #           '{' [dictsetmaker] '}')
+    self.DefaultNodeVisit(node)
+    if (node.children[0].value == '(' and
+        not hasattr(node.children[0], 'is_pseudo')):
+      if node.children[-1].value == ')':
+        if pytree_utils.NodeName(node.parent) == 'if_stmt':
+          _SetSplitPenalty(node.children[-1], STRONGLY_CONNECTED)
+        else:
+          if len(node.children) > 2:
+            _SetSplitPenalty(pytree_utils.FirstLeafNode(node.children[1]), EXPR)
+          _SetSplitPenalty(node.children[-1], ATOM)
+    elif node.children[0].value in '[{' and len(node.children) == 2:
+      # Keep empty containers together if we can.
+      _SetUnbreakable(node.children[-1])
+
+  def Visit_testlist_gexp(self, node):  # pylint: disable=invalid-name
+    self.DefaultNodeVisit(node)
+    prev_was_comma = False
+    for child in node.children:
+      if isinstance(child, pytree.Leaf) and child.value == ',':
+        _SetUnbreakable(child)
+        prev_was_comma = True
+      else:
+        if prev_was_comma:
+          _SetSplitPenalty(pytree_utils.FirstLeafNode(child), TOGETHER)
+        prev_was_comma = False
+
+
+def _SetUnbreakable(node):
+  """Set an UNBREAKABLE penalty annotation for the given node."""
+  _RecAnnotate(node, pytree_utils.Annotation.SPLIT_PENALTY, UNBREAKABLE)
+
+
+def _SetStronglyConnected(*nodes):
+  """Set a STRONGLY_CONNECTED penalty annotation for the given nodes."""
+  for node in nodes:
+    _RecAnnotate(node, pytree_utils.Annotation.SPLIT_PENALTY,
+                 STRONGLY_CONNECTED)
+
+
+def _SetExpressionPenalty(node, penalty):
+  """Set a penalty annotation on children nodes."""
+
+  def RecExpression(node, first_child_leaf):
+    if node is first_child_leaf:
+      return
+
+    if isinstance(node, pytree.Leaf):
+      if node.value in {'(', 'for', 'if'}:
+        return
+      penalty_annotation = pytree_utils.GetNodeAnnotation(
+          node, pytree_utils.Annotation.SPLIT_PENALTY, default=0)
+      if penalty_annotation < penalty:
+        _SetSplitPenalty(node, penalty)
+    else:
+      for child in node.children:
+        RecExpression(child, first_child_leaf)
+
+  RecExpression(node, pytree_utils.FirstLeafNode(node))
+
+
+def _SetBitwiseOperandPenalty(node, op):
+  for index in range(1, len(node.children) - 1):
+    child = node.children[index]
+    if isinstance(child, pytree.Leaf) and child.value == op:
+      if style.Get('SPLIT_BEFORE_BITWISE_OPERATOR'):
+        _SetSplitPenalty(child, style.Get('SPLIT_PENALTY_BITWISE_OPERATOR'))
+      else:
+        _SetSplitPenalty(
+            pytree_utils.FirstLeafNode(node.children[index + 1]),
+            style.Get('SPLIT_PENALTY_BITWISE_OPERATOR'))
+
+
+def _SetExpressionOperandPenalty(node, ops):
+  for index in range(1, len(node.children) - 1):
+    child = node.children[index]
+    if pytree_utils.NodeName(child) in ops:
+      if style.Get('SPLIT_BEFORE_ARITHMETIC_OPERATOR'):
+        _SetSplitPenalty(child, style.Get('SPLIT_PENALTY_ARITHMETIC_OPERATOR'))
+      else:
+        _SetSplitPenalty(
+            pytree_utils.FirstLeafNode(node.children[index + 1]),
+            style.Get('SPLIT_PENALTY_ARITHMETIC_OPERATOR'))
+
+
+def _IncreasePenalty(node, amt):
+  """Increase a penalty annotation on children nodes."""
+
+  def RecExpression(node, first_child_leaf):
+    if node is first_child_leaf:
+      return
+
+    if isinstance(node, pytree.Leaf):
+      if node.value in {'(', 'for'}:
+        return
+      penalty = pytree_utils.GetNodeAnnotation(
+          node, pytree_utils.Annotation.SPLIT_PENALTY, default=0)
+      _SetSplitPenalty(node, penalty + amt)
+    else:
+      for child in node.children:
+        RecExpression(child, first_child_leaf)
+
+  RecExpression(node, pytree_utils.FirstLeafNode(node))
+
+
+def _RecAnnotate(tree, annotate_name, annotate_value):
+  """Recursively set the given annotation on all leafs of the subtree.
+
+  Takes care to only increase the penalty. If the node already has a higher
+  or equal penalty associated with it, this is a no-op.
+
+  Args:
+    tree: subtree to annotate
+    annotate_name: name of the annotation to set
+    annotate_value: value of the annotation to set
+  """
+  for child in tree.children:
+    _RecAnnotate(child, annotate_name, annotate_value)
+  if isinstance(tree, pytree.Leaf):
+    cur_annotate = pytree_utils.GetNodeAnnotation(
+        tree, annotate_name, default=0)
+    if cur_annotate < annotate_value:
+      pytree_utils.SetNodeAnnotation(tree, annotate_name, annotate_value)
+
+
+_COMP_OPS = frozenset({'==', '!=', '<=', '<', '>', '>=', '<>', 'in', 'is'})
+
+
+def _StronglyConnectedCompOp(op):
+  if (len(op.children[1].children) == 2 and
+      pytree_utils.NodeName(op.children[1]) == 'comp_op'):
+    if (pytree_utils.FirstLeafNode(op.children[1]).value == 'not' and
+        pytree_utils.LastLeafNode(op.children[1]).value == 'in'):
+      return True
+    if (pytree_utils.FirstLeafNode(op.children[1]).value == 'is' and
+        pytree_utils.LastLeafNode(op.children[1]).value == 'not'):
+      return True
+  if (isinstance(op.children[1], pytree.Leaf) and
+      op.children[1].value in _COMP_OPS):
+    return True
+  return False
+
+
+def _DecrementSplitPenalty(node, amt):
+  penalty = pytree_utils.GetNodeAnnotation(
+      node, pytree_utils.Annotation.SPLIT_PENALTY, default=amt)
+  penalty = penalty - amt if amt < penalty else 0
+  _SetSplitPenalty(node, penalty)
+
+
+def _SetSplitPenalty(node, penalty):
+  pytree_utils.SetNodeAnnotation(node, pytree_utils.Annotation.SPLIT_PENALTY,
+                                 penalty)
diff --git a/yapf/yapflib/subtype_assigner.py b/yapf/pytree/subtype_assigner.py
similarity index 94%
rename from yapf/yapflib/subtype_assigner.py
rename to yapf/pytree/subtype_assigner.py
index 7b45586..e3b3277 100644
--- a/yapf/yapflib/subtype_assigner.py
+++ b/yapf/pytree/subtype_assigner.py
@@ -24,13 +24,12 @@ Annotations:
       subtypes.
 """
 
-from lib2to3 import pytree
-from lib2to3.pgen2 import token as grammar_token
-from lib2to3.pygram import python_symbols as syms
+from yapf_third_party._ylib2to3 import pytree
+from yapf_third_party._ylib2to3.pgen2 import token as grammar_token
+from yapf_third_party._ylib2to3.pygram import python_symbols as syms
 
-from yapf.yapflib import format_token
-from yapf.yapflib import pytree_utils
-from yapf.yapflib import pytree_visitor
+from yapf.pytree import pytree_utils
+from yapf.pytree import pytree_visitor
 from yapf.yapflib import style
 from yapf.yapflib import subtypes
 
@@ -67,20 +66,26 @@ class _SubtypeAssigner(pytree_visitor.PyTreeVisitor):
     for child in node.children:
       self.Visit(child)
 
-    comp_for = False
     dict_maker = False
 
+    def markAsDictSetGenerator(node):
+      _AppendFirstLeafTokenSubtype(node, subtypes.DICT_SET_GENERATOR)
+      for child in node.children:
+        if pytree_utils.NodeName(child) == 'comp_for':
+          markAsDictSetGenerator(child)
+
     for child in node.children:
       if pytree_utils.NodeName(child) == 'comp_for':
-        comp_for = True
-        _AppendFirstLeafTokenSubtype(child, subtypes.DICT_SET_GENERATOR)
+        markAsDictSetGenerator(child)
       elif child.type in (grammar_token.COLON, grammar_token.DOUBLESTAR):
         dict_maker = True
 
-    if not comp_for and dict_maker:
+    if dict_maker:
       last_was_colon = False
       unpacking = False
       for child in node.children:
+        if pytree_utils.NodeName(child) == 'comp_for':
+          break
         if child.type == grammar_token.DOUBLESTAR:
           _AppendFirstLeafTokenSubtype(child, subtypes.KWARGS_STAR_STAR)
         if last_was_colon:
@@ -217,6 +222,11 @@ class _SubtypeAssigner(pytree_visitor.PyTreeVisitor):
       if isinstance(child, pytree.Leaf) and child.value == '**':
         _AppendTokenSubtype(child, subtypes.BINARY_OPERATOR)
 
+  def Visit_lambdef(self, node):  # pylint: disable=invalid-name
+    # trailer: '(' [arglist] ')' | '[' subscriptlist ']' | '.' NAME
+    _AppendSubtypeRec(node, subtypes.LAMBDEF)
+    self.DefaultNodeVisit(node)
+
   def Visit_trailer(self, node):  # pylint: disable=invalid-name
     for child in node.children:
       self.Visit(child)
@@ -336,7 +346,10 @@ class _SubtypeAssigner(pytree_visitor.PyTreeVisitor):
     attr = pytree_utils.GetNodeAnnotation(node.parent,
                                           pytree_utils.Annotation.SUBTYPE)
     if not attr or subtypes.COMP_FOR not in attr:
-      _AppendSubtypeRec(node.parent.children[0], subtypes.COMP_EXPR)
+      sibling = node.prev_sibling
+      while sibling:
+        _AppendSubtypeRec(sibling, subtypes.COMP_EXPR)
+        sibling = sibling.prev_sibling
     self.DefaultNodeVisit(node)
 
   def Visit_old_comp_for(self, node):  # pylint: disable=invalid-name
@@ -450,7 +463,7 @@ def _InsertPseudoParentheses(node):
 
   lparen = pytree.Leaf(
       grammar_token.LPAR,
-      u'(',
+      '(',
       context=('', (first.get_lineno(), first.column - 1)))
   last_lineno = last.get_lineno()
   if last.type == grammar_token.STRING and '\n' in last.value:
@@ -461,7 +474,7 @@ def _InsertPseudoParentheses(node):
   else:
     last_column = last.column + len(last.value) + 1
   rparen = pytree.Leaf(
-      grammar_token.RPAR, u')', context=('', (last_lineno, last_column)))
+      grammar_token.RPAR, ')', context=('', (last_lineno, last_column)))
 
   lparen.is_pseudo = True
   rparen.is_pseudo = True
diff --git a/yapf/yapflib/errors.py b/yapf/yapflib/errors.py
index 99e88d9..3a01023 100644
--- a/yapf/yapflib/errors.py
+++ b/yapf/yapflib/errors.py
@@ -13,7 +13,7 @@
 # limitations under the License.
 """YAPF error objects."""
 
-from lib2to3.pgen2 import tokenize
+from yapf_third_party._ylib2to3.pgen2 import tokenize
 
 
 def FormatErrorMsg(e):
diff --git a/yapf/yapflib/file_resources.py b/yapf/yapflib/file_resources.py
index 972f483..87b6d86 100644
--- a/yapf/yapflib/file_resources.py
+++ b/yapf/yapflib/file_resources.py
@@ -17,16 +17,22 @@ This module provides functions for interfacing with files: opening, writing, and
 querying.
 """
 
+import codecs
 import fnmatch
 import os
 import re
-
-from lib2to3.pgen2 import tokenize
+import sys
+from configparser import ConfigParser
+from tokenize import detect_encoding
 
 from yapf.yapflib import errors
-from yapf.yapflib import py3compat
 from yapf.yapflib import style
 
+if sys.version_info >= (3, 11):
+  import tomllib
+else:
+  import tomli as tomllib
+
 CR = '\r'
 LF = '\n'
 CRLF = '\r\n'
@@ -50,15 +56,10 @@ def _GetExcludePatternsFromYapfIgnore(filename):
 def _GetExcludePatternsFromPyprojectToml(filename):
   """Get a list of file patterns to ignore from pyproject.toml."""
   ignore_patterns = []
-  try:
-    import toml
-  except ImportError:
-    raise errors.YapfError(
-        "toml package is needed for using pyproject.toml as a "
-        "configuration file")
 
   if os.path.isfile(filename) and os.access(filename, os.R_OK):
-    pyproject_toml = toml.load(filename)
+    with open(filename, 'rb') as fd:
+      pyproject_toml = tomllib.load(fd)
     ignore_patterns = pyproject_toml.get('tool',
                                          {}).get('yapfignore',
                                                  {}).get('ignore_patterns', [])
@@ -121,7 +122,7 @@ def GetDefaultStyleForDir(dirname, default_style=style.DEFAULT_STYLE):
       pass  # It's okay if it's not there.
     else:
       with fd:
-        config = py3compat.ConfigParser()
+        config = ConfigParser()
         config.read_file(fd)
         if config.has_section('yapf'):
           return config_file
@@ -129,19 +130,12 @@ def GetDefaultStyleForDir(dirname, default_style=style.DEFAULT_STYLE):
     # See if we have a pyproject.toml file with a '[tool.yapf]'  section.
     config_file = os.path.join(dirname, style.PYPROJECT_TOML)
     try:
-      fd = open(config_file)
+      fd = open(config_file, 'rb')
     except IOError:
       pass  # It's okay if it's not there.
     else:
       with fd:
-        try:
-          import toml
-        except ImportError:
-          raise errors.YapfError(
-              "toml package is needed for using pyproject.toml as a "
-              "configuration file")
-
-        pyproject_toml = toml.load(config_file)
+        pyproject_toml = tomllib.load(fd)
         style_dict = pyproject_toml.get('tool', {}).get('yapf', None)
         if style_dict is not None:
           return config_file
@@ -179,11 +173,10 @@ def WriteReformattedCode(filename,
     in_place: (bool) If True, then write the reformatted code to the file.
   """
   if in_place:
-    with py3compat.open_with_encoding(
-        filename, mode='w', encoding=encoding, newline='') as fd:
+    with codecs.open(filename, mode='w', encoding=encoding) as fd:
       fd.write(reformatted_code)
   else:
-    py3compat.EncodeAndWriteToStdout(reformatted_code)
+    sys.stdout.buffer.write(reformatted_code.encode('utf-8'))
 
 
 def LineEnding(lines):
@@ -196,14 +189,14 @@ def LineEnding(lines):
       endings[CR] += 1
     elif line.endswith(LF):
       endings[LF] += 1
-  return (sorted(endings, key=endings.get, reverse=True) or [LF])[0]
+  return sorted((LF, CRLF, CR), key=endings.get, reverse=True)[0]
 
 
 def _FindPythonFiles(filenames, recursive, exclude):
   """Find all Python files."""
   if exclude and any(e.startswith('./') for e in exclude):
     raise errors.YapfError("path in '--exclude' should not start with ./")
-  exclude = exclude and [e.rstrip("/" + os.path.sep) for e in exclude]
+  exclude = exclude and [e.rstrip('/' + os.path.sep) for e in exclude]
 
   python_files = []
   for filename in filenames:
@@ -259,16 +252,15 @@ def IsIgnored(path, exclude):
 
 def IsPythonFile(filename):
   """Return True if filename is a Python file."""
-  if os.path.splitext(filename)[1] == '.py':
+  if os.path.splitext(filename)[1] in frozenset({'.py', '.pyi'}):
     return True
 
   try:
     with open(filename, 'rb') as fd:
-      encoding = tokenize.detect_encoding(fd.readline)[0]
+      encoding = detect_encoding(fd.readline)[0]
 
     # Check for correctness of encoding.
-    with py3compat.open_with_encoding(
-        filename, mode='r', encoding=encoding) as fd:
+    with codecs.open(filename, mode='r', encoding=encoding) as fd:
       fd.read()
   except UnicodeDecodeError:
     encoding = 'latin-1'
@@ -279,8 +271,7 @@ def IsPythonFile(filename):
     return False
 
   try:
-    with py3compat.open_with_encoding(
-        filename, mode='r', encoding=encoding) as fd:
+    with codecs.open(filename, mode='r', encoding=encoding) as fd:
       first_line = fd.readline(256)
   except IOError:
     return False
@@ -291,4 +282,4 @@ def IsPythonFile(filename):
 def FileEncoding(filename):
   """Return the file's encoding."""
   with open(filename, 'rb') as fd:
-    return tokenize.detect_encoding(fd.readline)[0]
+    return detect_encoding(fd.readline)[0]
diff --git a/yapf/yapflib/format_decision_state.py b/yapf/yapflib/format_decision_state.py
index 74d0861..06f3455 100644
--- a/yapf/yapflib/format_decision_state.py
+++ b/yapf/yapflib/format_decision_state.py
@@ -14,7 +14,7 @@
 """Implements a format decision state object that manages whitespace decisions.
 
 Each token is processed one at a time, at which point its whitespace formatting
-decisions are made. A graph of potential whitespace formattings is created,
+decisions are made. A graph of potential whitespace formatting is created,
 where each node in the graph is a format decision state object. The heuristic
 tries formatting the token with and without a newline before it to determine
 which one has the least penalty. Therefore, the format decision state object for
@@ -26,10 +26,10 @@ through the code to commit the whitespace formatting.
   FormatDecisionState: main class exported by this module.
 """
 
-from yapf.yapflib import format_token
+from yapf.pytree import split_penalty
+from yapf.pytree.pytree_utils import NodeName
 from yapf.yapflib import logical_line
 from yapf.yapflib import object_state
-from yapf.yapflib import split_penalty
 from yapf.yapflib import style
 from yapf.yapflib import subtypes
 
@@ -180,10 +180,23 @@ class FormatDecisionState(object):
       return False
 
     if style.Get('SPLIT_ALL_COMMA_SEPARATED_VALUES') and previous.value == ',':
+      if (subtypes.COMP_FOR in current.subtypes or
+          subtypes.LAMBDEF in current.subtypes):
+        return False
+
+      return True
+
+    if (style.Get('FORCE_MULTILINE_DICT') and
+        subtypes.DICTIONARY_KEY in current.subtypes and not current.is_comment):
       return True
 
     if (style.Get('SPLIT_ALL_TOP_LEVEL_COMMA_SEPARATED_VALUES') and
         previous.value == ','):
+
+      if (subtypes.COMP_FOR in current.subtypes or
+          subtypes.LAMBDEF in current.subtypes):
+        return False
+
       # Avoid breaking in a container that fits in the current line if possible
       opening = _GetOpeningBracket(current)
 
@@ -206,7 +219,9 @@ class FormatDecisionState(object):
         (current.value in '}]' and style.Get('SPLIT_BEFORE_CLOSING_BRACKET') or
          current.value in '}])' and style.Get('INDENT_CLOSING_BRACKETS'))):
       # Split before the closing bracket if we can.
-      if subtypes.SUBSCRIPT_BRACKET not in current.subtypes:
+      if (subtypes.SUBSCRIPT_BRACKET not in current.subtypes or
+          (previous.value == ',' and
+           not style.Get('DISABLE_ENDING_COMMA_HEURISTIC'))):
         return current.node_split_penalty != split_penalty.UNBREAKABLE
 
     if (current.value == ')' and previous.value == ',' and
@@ -367,6 +382,16 @@ class FormatDecisionState(object):
 
     ###########################################################################
     # Argument List Splitting
+
+    if style.Get('SPLIT_ARGUMENTS_WHEN_COMMA_TERMINATED'):
+      # Split before arguments in a function call or definition if the
+      # arguments are terminated by a comma.
+      opening = _GetOpeningBracket(current)
+      if opening and opening.previous_token and opening.previous_token.is_name:
+        if previous.value in '(,':
+          if opening.matching_bracket.previous_token.value == ',':
+            return True
+
     if (style.Get('SPLIT_BEFORE_NAMED_ASSIGNS') and not current.is_comment and
         subtypes.DEFAULT_OR_NAMED_ASSIGN_ARG_LIST in current.subtypes):
       if (previous.value not in {'=', ':', '*', '**'} and
@@ -403,15 +428,6 @@ class FormatDecisionState(object):
         self._ArgumentListHasDictionaryEntry(current)):
       return True
 
-    if style.Get('SPLIT_ARGUMENTS_WHEN_COMMA_TERMINATED'):
-      # Split before arguments in a function call or definition if the
-      # arguments are terminated by a comma.
-      opening = _GetOpeningBracket(current)
-      if opening and opening.previous_token and opening.previous_token.is_name:
-        if previous.value in '(,':
-          if opening.matching_bracket.previous_token.value == ',':
-            return True
-
     if ((current.is_name or current.value in {'*', '**'}) and
         previous.value == ','):
       # If we have a function call within an argument list and it won't fit on
@@ -1032,6 +1048,8 @@ class FormatDecisionState(object):
     current = opening.next_token.next_token
 
     while current and current != closing:
+      if subtypes.DICT_SET_GENERATOR in current.subtypes:
+        break
       if subtypes.DICTIONARY_KEY in current.subtypes:
         prev = PreviousNonCommentToken(current)
         if prev.value == ',':
@@ -1093,14 +1111,27 @@ class FormatDecisionState(object):
             self.stack[-1].indent) <= self.column_limit
 
 
-_COMPOUND_STMTS = frozenset(
-    {'for', 'while', 'if', 'elif', 'with', 'except', 'def', 'class'})
+_COMPOUND_STMTS = frozenset({
+    'for',
+    'while',
+    'if',
+    'elif',
+    'with',
+    'except',
+    'def',
+    'class',
+})
 
 
 def _IsCompoundStatement(token):
-  if token.value == 'async':
+  value = token.value
+  if value == 'async':
     token = token.next_token
-  return token.value in _COMPOUND_STMTS
+  if token.value in _COMPOUND_STMTS:
+    return True
+  parent_name = NodeName(token.node.parent)
+  return value == 'match' and parent_name == 'match_stmt' or \
+    value == 'case' and parent_name == 'case_stmt'
 
 
 def _IsFunctionDef(token):
diff --git a/yapf/yapflib/format_token.py b/yapf/yapflib/format_token.py
index 487f3a9..141c265 100644
--- a/yapf/yapflib/format_token.py
+++ b/yapf/yapflib/format_token.py
@@ -11,23 +11,24 @@
 # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 # See the License for the specific language governing permissions and
 # limitations under the License.
-"""Pytree nodes with extra formatting information.
-
-This is a thin wrapper around a pytree.Leaf node.
-"""
+"""Enhanced token information for formatting."""
 
 import keyword
 import re
+from functools import lru_cache
 
-from lib2to3.pgen2 import token
+from yapf_third_party._ylib2to3.pgen2 import token
+from yapf_third_party._ylib2to3.pytree import type_repr
 
-from yapf.yapflib import py3compat
-from yapf.yapflib import pytree_utils
+from yapf.pytree import pytree_utils
 from yapf.yapflib import style
 from yapf.yapflib import subtypes
 
 CONTINUATION = token.N_TOKENS
 
+_OPENING_BRACKETS = frozenset({'(', '[', '{'})
+_CLOSING_BRACKETS = frozenset({')', ']', '}'})
+
 
 def _TabbedContinuationAlignPadding(spaces, align_style, tab_width):
   """Build padding string for continuation alignment in tabbed indentation.
@@ -48,13 +49,13 @@ def _TabbedContinuationAlignPadding(spaces, align_style, tab_width):
 
 
 class FormatToken(object):
-  """A wrapper around pytree Leaf nodes.
+  """Enhanced token information for formatting.
 
   This represents the token plus additional information useful for reformatting
   the code.
 
   Attributes:
-    node: The PyTree node this token represents.
+    node: The original token node.
     next_token: The token in the logical line after this token or None if this
       is the last token in the logical line.
     previous_token: The token in the logical line before this token or None if
@@ -83,13 +84,23 @@ class FormatToken(object):
     newlines: The number of newlines needed before this token.
   """
 
-  def __init__(self, node):
+  def __init__(self, node, name):
     """Constructor.
 
     Arguments:
       node: (pytree.Leaf) The node that's being wrapped.
+      name: (string) The name of the node.
     """
     self.node = node
+    self.name = name
+    self.type = node.type
+    self.column = node.column
+    self.lineno = node.lineno
+    self.value = node.value
+
+    if self.is_continuation:
+      self.value = node.value.rstrip()
+
     self.next_token = None
     self.previous_token = None
     self.matching_bracket = None
@@ -104,20 +115,11 @@ class FormatToken(object):
         node, pytree_utils.Annotation.MUST_SPLIT, default=False)
     self.newlines = pytree_utils.GetNodeAnnotation(
         node, pytree_utils.Annotation.NEWLINES)
-
-    self.type = node.type
-    self.column = node.column
-    self.lineno = node.lineno
-    self.name = pytree_utils.NodeName(node)
-
     self.spaces_required_before = 0
+
     if self.is_comment:
       self.spaces_required_before = style.Get('SPACES_BEFORE_COMMENT')
 
-    self.value = node.value
-    if self.is_continuation:
-      self.value = node.value.rstrip()
-
     stypes = pytree_utils.GetNodeAnnotation(node,
                                             pytree_utils.Annotation.SUBTYPE)
     self.subtypes = {subtypes.NONE} if not stypes else stypes
@@ -195,7 +197,7 @@ class FormatToken(object):
       return
 
     cur_column = self.column
-    prev_column = previous.node.column
+    prev_column = previous.column
     prev_len = len(previous.value)
 
     if previous.is_pseudo and previous.value == ')':
@@ -210,10 +212,10 @@ class FormatToken(object):
     self.spaces_required_before = cur_column - (prev_column + prev_len)
 
   def OpensScope(self):
-    return self.value in pytree_utils.OPENING_BRACKETS
+    return self.value in _OPENING_BRACKETS
 
   def ClosesScope(self):
-    return self.value in pytree_utils.CLOSING_BRACKETS
+    return self.value in _CLOSING_BRACKETS
 
   def AddSubtype(self, subtype):
     self.subtypes.add(subtype)
@@ -238,7 +240,7 @@ class FormatToken(object):
     return subtypes.BINARY_OPERATOR in self.subtypes
 
   @property
-  @py3compat.lru_cache()
+  @lru_cache()
   def is_arithmetic_op(self):
     """Token is an arithmetic operator."""
     return self.value in frozenset({
@@ -276,9 +278,13 @@ class FormatToken(object):
     return self.type == CONTINUATION
 
   @property
-  @py3compat.lru_cache()
+  @lru_cache()
   def is_keyword(self):
-    return keyword.iskeyword(self.value)
+    return keyword.iskeyword(
+        self.value) or (self.value == 'match' and
+                        type_repr(self.node.parent.type) == 'match_stmt') or (
+                            self.value == 'case' and
+                            type_repr(self.node.parent.type) == 'case_block')
 
   @property
   def is_name(self):
diff --git a/yapf/yapflib/identify_container.py b/yapf/yapflib/identify_container.py
index 888dbbb..43ba4b9 100644
--- a/yapf/yapflib/identify_container.py
+++ b/yapf/yapflib/identify_container.py
@@ -19,10 +19,10 @@ to the opening bracket and vice-versa.
   IdentifyContainers(): the main function exported by this module.
 """
 
-from lib2to3.pgen2 import token as grammar_token
+from yapf_third_party._ylib2to3.pgen2 import token as grammar_token
 
-from yapf.yapflib import pytree_utils
-from yapf.yapflib import pytree_visitor
+from yapf.pytree import pytree_utils
+from yapf.pytree import pytree_visitor
 
 
 def IdentifyContainers(tree):
diff --git a/yapf/yapflib/logical_line.py b/yapf/yapflib/logical_line.py
index 5723440..4433276 100644
--- a/yapf/yapflib/logical_line.py
+++ b/yapf/yapflib/logical_line.py
@@ -19,15 +19,14 @@ line if there were no line length restrictions. It's then used by the parser to
 perform the wrapping required to comply with the style guide.
 """
 
+from yapf_third_party._ylib2to3.fixer_util import syms as python_symbols
+
+from yapf.pytree import pytree_utils
+from yapf.pytree import split_penalty
 from yapf.yapflib import format_token
-from yapf.yapflib import py3compat
-from yapf.yapflib import pytree_utils
-from yapf.yapflib import split_penalty
 from yapf.yapflib import style
 from yapf.yapflib import subtypes
 
-from lib2to3.fixer_util import syms as python_symbols
-
 
 class LogicalLine(object):
   """Represents a single logical line in the output.
@@ -135,16 +134,6 @@ class LogicalLine(object):
       self.last.next_token = token
     self._tokens.append(token)
 
-  def AppendNode(self, node):
-    """Convenience method to append a pytree node directly.
-
-    Wraps the node with a FormatToken.
-
-    Arguments:
-      node: the node to append
-    """
-    self.AppendToken(format_token.FormatToken(node))
-
   @property
   def first(self):
     """Returns the first non-whitespace token."""
@@ -169,7 +158,7 @@ class LogicalLine(object):
     have spaces around them, for example).
 
     Arguments:
-      indent_per_depth: how much spaces to indend per depth level.
+      indent_per_depth: how much spaces to indent per depth level.
 
     Returns:
       A string representing the line as code.
@@ -312,9 +301,9 @@ def _SpaceRequiredBetween(left, right, is_line_disabled):
     return True
   if style.Get('SPACE_INSIDE_BRACKETS'):
     # Supersede the "no space before a colon or comma" check.
-    if lval in pytree_utils.OPENING_BRACKETS and rval == ':':
+    if left.OpensScope() and rval == ':':
       return True
-    if rval in pytree_utils.CLOSING_BRACKETS and lval == ':':
+    if right.ClosesScope() and lval == ':':
       return True
   if (style.Get('SPACES_AROUND_SUBSCRIPT_COLON') and
       (_IsSubscriptColonAndValuePair(left, right) or
@@ -365,7 +354,7 @@ def _SpaceRequiredBetween(left, right, is_line_disabled):
       # A string followed by something other than a subscript, closing bracket,
       # dot, or a binary op should have a space after it.
       return True
-    if rval in pytree_utils.CLOSING_BRACKETS:
+    if right.ClosesScope():
       # A string followed by closing brackets should have a space after it
       # depending on SPACE_INSIDE_BRACKETS.  A string followed by opening
       # brackets, however, should not.
@@ -449,28 +438,26 @@ def _SpaceRequiredBetween(left, right, is_line_disabled):
         (rval == ')' and
          _IsDictListTupleDelimiterTok(right, is_opening=False)))):
       return True
-  if (lval in pytree_utils.OPENING_BRACKETS and
-      rval in pytree_utils.OPENING_BRACKETS):
+  if left.OpensScope() and right.OpensScope():
     # Nested objects' opening brackets shouldn't be separated, unless enabled
     # by SPACE_INSIDE_BRACKETS.
     return style.Get('SPACE_INSIDE_BRACKETS')
-  if (lval in pytree_utils.CLOSING_BRACKETS and
-      rval in pytree_utils.CLOSING_BRACKETS):
+  if left.ClosesScope() and right.ClosesScope():
     # Nested objects' closing brackets shouldn't be separated, unless enabled
     # by SPACE_INSIDE_BRACKETS.
     return style.Get('SPACE_INSIDE_BRACKETS')
-  if lval in pytree_utils.CLOSING_BRACKETS and rval in '([':
+  if left.ClosesScope() and rval in '([':
     # A call, set, dictionary, or subscript that has a call or subscript after
     # it shouldn't have a space between them.
     return False
-  if lval in pytree_utils.OPENING_BRACKETS and _IsIdNumberStringToken(right):
+  if left.OpensScope() and _IsIdNumberStringToken(right):
     # Don't separate the opening bracket from the first item, unless enabled
     # by SPACE_INSIDE_BRACKETS.
     return style.Get('SPACE_INSIDE_BRACKETS')
   if left.is_name and rval in '([':
     # Don't separate a call or array access from the name.
     return False
-  if rval in pytree_utils.CLOSING_BRACKETS:
+  if right.ClosesScope():
     # Don't separate the closing bracket from the last item, unless enabled
     # by SPACE_INSIDE_BRACKETS.
     # FIXME(morbo): This might be too permissive.
@@ -478,13 +465,12 @@ def _SpaceRequiredBetween(left, right, is_line_disabled):
   if lval == 'print' and rval == '(':
     # Special support for the 'print' function.
     return False
-  if lval in pytree_utils.OPENING_BRACKETS and _IsUnaryOperator(right):
+  if left.OpensScope() and _IsUnaryOperator(right):
     # Don't separate a unary operator from the opening bracket, unless enabled
     # by SPACE_INSIDE_BRACKETS.
     return style.Get('SPACE_INSIDE_BRACKETS')
-  if (lval in pytree_utils.OPENING_BRACKETS and
-      (subtypes.VARARGS_STAR in right.subtypes or
-       subtypes.KWARGS_STAR_STAR in right.subtypes)):
+  if (left.OpensScope() and (subtypes.VARARGS_STAR in right.subtypes or
+                             subtypes.KWARGS_STAR_STAR in right.subtypes)):
     # Don't separate a '*' or '**' from the opening bracket, unless enabled
     # by SPACE_INSIDE_BRACKETS.
     return style.Get('SPACE_INSIDE_BRACKETS')
@@ -518,13 +504,12 @@ def _CanBreakBefore(prev_token, cur_token):
   """Return True if a line break may occur before the current token."""
   pval = prev_token.value
   cval = cur_token.value
-  if py3compat.PY3:
-    if pval == 'yield' and cval == 'from':
-      # Don't break before a yield argument.
-      return False
-    if pval in {'async', 'await'} and cval in {'def', 'with', 'for'}:
-      # Don't break after sync keywords.
-      return False
+  if pval == 'yield' and cval == 'from':
+    # Don't break before a yield argument.
+    return False
+  if pval in {'async', 'await'} and cval in {'def', 'with', 'for'}:
+    # Don't break after sync keywords.
+    return False
   if cur_token.split_penalty >= split_penalty.UNBREAKABLE:
     return False
   if pval == '@':
diff --git a/yapf/yapflib/object_state.py b/yapf/yapflib/object_state.py
index 07925ef..cb8c51b 100644
--- a/yapf/yapflib/object_state.py
+++ b/yapf/yapflib/object_state.py
@@ -18,12 +18,8 @@ requirements on how they're formatted. These state objects keep track of these
 requirements.
 """
 
-from __future__ import absolute_import
-from __future__ import division
-from __future__ import print_function
+from functools import lru_cache
 
-from yapf.yapflib import format_token
-from yapf.yapflib import py3compat
 from yapf.yapflib import style
 from yapf.yapflib import subtypes
 
@@ -121,26 +117,26 @@ class ParameterListState(object):
     return self.closing_bracket.next_token.value == '->'
 
   @property
-  @py3compat.lru_cache()
+  @lru_cache()
   def has_default_values(self):
     return any(param.has_default_value for param in self.parameters)
 
   @property
-  @py3compat.lru_cache()
+  @lru_cache()
   def ends_in_comma(self):
     if not self.parameters:
       return False
     return self.parameters[-1].last_token.next_token.value == ','
 
   @property
-  @py3compat.lru_cache()
+  @lru_cache()
   def last_token(self):
     token = self.opening_bracket.matching_bracket
     while not token.is_comment and token.next_token:
       token = token.next_token
     return token
 
-  @py3compat.lru_cache()
+  @lru_cache()
   def LastParamFitsOnLine(self, indent):
     """Return true if the last parameter fits on a single line."""
     if not self.has_typed_return:
@@ -152,7 +148,7 @@ class ParameterListState(object):
     total_length -= last_param.total_length - len(last_param.value)
     return total_length + indent <= style.Get('COLUMN_LIMIT')
 
-  @py3compat.lru_cache()
+  @lru_cache()
   def SplitBeforeClosingBracket(self, indent):
     """Return true if there's a split before the closing bracket."""
     if style.Get('DEDENT_CLOSING_BRACKETS'):
@@ -206,7 +202,7 @@ class Parameter(object):
     self.last_token = last_token
 
   @property
-  @py3compat.lru_cache()
+  @lru_cache()
   def has_default_value(self):
     """Returns true if the parameter has a default value."""
     tok = self.first_token
diff --git a/yapf/yapflib/py3compat.py b/yapf/yapflib/py3compat.py
deleted file mode 100644
index 8f15476..0000000
--- a/yapf/yapflib/py3compat.py
+++ /dev/null
@@ -1,131 +0,0 @@
-# Copyright 2015 Google Inc. All Rights Reserved.
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#     http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-"""Utilities for Python2 / Python3 compatibility."""
-
-import codecs
-import io
-import os
-import sys
-
-PY3 = sys.version_info[0] >= 3
-PY36 = sys.version_info[0] >= 3 and sys.version_info[1] >= 6
-PY37 = sys.version_info[0] >= 3 and sys.version_info[1] >= 7
-PY38 = sys.version_info[0] >= 3 and sys.version_info[1] >= 8
-
-if PY3:
-  StringIO = io.StringIO
-  BytesIO = io.BytesIO
-
-  import codecs  # noqa: F811
-
-  def open_with_encoding(filename, mode, encoding, newline=''):  # pylint: disable=unused-argument # noqa
-    return codecs.open(filename, mode=mode, encoding=encoding)
-
-  import functools
-  lru_cache = functools.lru_cache
-
-  range = range
-  ifilter = filter
-
-  def raw_input():
-    wrapper = io.TextIOWrapper(sys.stdin.buffer, encoding='utf-8')
-    return wrapper.buffer.raw.readall().decode('utf-8')
-
-  import configparser
-
-  # Mappings from strings to booleans (such as '1' to True, 'false' to False,
-  # etc.)
-  CONFIGPARSER_BOOLEAN_STATES = configparser.ConfigParser.BOOLEAN_STATES
-else:
-  import __builtin__
-  import cStringIO
-  StringIO = BytesIO = cStringIO.StringIO
-
-  open_with_encoding = io.open
-
-  # Python 2.7 doesn't have a native LRU cache, so do nothing.
-  def lru_cache(maxsize=128, typed=False):
-
-    def fake_wrapper(user_function):
-      return user_function
-
-    return fake_wrapper
-
-  range = xrange  # noqa: F821
-
-  from itertools import ifilter
-  raw_input = raw_input
-
-  import ConfigParser as configparser
-  CONFIGPARSER_BOOLEAN_STATES = configparser.ConfigParser._boolean_states  # pylint: disable=protected-access # noqa
-
-
-def EncodeAndWriteToStdout(s, encoding='utf-8'):
-  """Encode the given string and emit to stdout.
-
-  The string may contain non-ascii characters. This is a problem when stdout is
-  redirected, because then Python doesn't know the encoding and we may get a
-  UnicodeEncodeError.
-
-  Arguments:
-    s: (string) The string to encode.
-    encoding: (string) The encoding of the string.
-  """
-  if PY3:
-    sys.stdout.buffer.write(s.encode(encoding))
-  elif sys.platform == 'win32':
-    # On python 2 and Windows universal newline transformation will be in
-    # effect on stdout. Python 2 will not let us avoid the easily because
-    # it happens based on whether the file handle is opened in O_BINARY or
-    # O_TEXT state. However we can tell Windows itself to change the current
-    # mode, and python 2 will follow suit. However we must take care to change
-    # the mode on the actual external stdout not just the current sys.stdout
-    # which may have been monkey-patched inside the python environment.
-    import msvcrt  # pylint: disable=g-import-not-at-top
-    if sys.__stdout__ is sys.stdout:
-      msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
-    sys.stdout.write(s.encode(encoding))
-  else:
-    sys.stdout.write(s.encode(encoding))
-
-
-if PY3:
-  basestring = str
-  unicode = str  # pylint: disable=redefined-builtin,invalid-name
-else:
-  basestring = basestring
-
-  def unicode(s):  # pylint: disable=invalid-name
-    """Force conversion of s to unicode."""
-    return __builtin__.unicode(s, 'utf-8')
-
-
-# In Python 3.2+, readfp is deprecated in favor of read_file, which doesn't
-# exist in Python 2 yet. To avoid deprecation warnings, subclass ConfigParser to
-# fix this - now read_file works across all Python versions we care about.
-class ConfigParser(configparser.ConfigParser):
-  if not PY3:
-
-    def read_file(self, fp, source=None):
-      self.readfp(fp, filename=source)
-
-
-def removeBOM(source):
-  """Remove any Byte-order-Mark bytes from the beginning of a file."""
-  bom = codecs.BOM_UTF8
-  if PY3:
-    bom = bom.decode('utf-8')
-  if source.startswith(bom):
-    return source[len(bom):]
-  return source
diff --git a/yapf/yapflib/reformatter.py b/yapf/yapflib/reformatter.py
index b6e6a13..ff09525 100644
--- a/yapf/yapflib/reformatter.py
+++ b/yapf/yapflib/reformatter.py
@@ -19,28 +19,25 @@ can be merged together are. The best formatting is returned as a string.
   Reformat(): the main function exported by this module.
 """
 
-from __future__ import unicode_literals
 import collections
 import heapq
 import re
 
-from lib2to3 import pytree
-from lib2to3.pgen2 import token
+from yapf_third_party._ylib2to3 import pytree
+from yapf_third_party._ylib2to3.pgen2 import token
 
+from yapf.pytree import pytree_utils
 from yapf.yapflib import format_decision_state
 from yapf.yapflib import format_token
 from yapf.yapflib import line_joiner
-from yapf.yapflib import pytree_utils
 from yapf.yapflib import style
-from yapf.yapflib import verifier
 
 
-def Reformat(llines, verify=False, lines=None):
+def Reformat(llines, lines=None):
   """Reformat the logical lines.
 
   Arguments:
     llines: (list of logical_line.LogicalLine) Lines we want to format.
-    verify: (bool) True if reformatted code should be verified for syntax.
     lines: (set of int) The lines which can be modified or None if there is no
       line range restriction.
 
@@ -61,9 +58,9 @@ def Reformat(llines, verify=False, lines=None):
 
     if not lline.disable:
       if lline.first.is_comment:
-        lline.first.node.value = lline.first.node.value.rstrip()
+        lline.first.value = lline.first.value.rstrip()
       elif lline.last.is_comment:
-        lline.last.node.value = lline.last.node.value.rstrip()
+        lline.last.value = lline.last.value.rstrip()
       if prev_line and prev_line.disable:
         # Keep the vertical spacing between a disabled and enabled formatting
         # region.
@@ -102,7 +99,7 @@ def Reformat(llines, verify=False, lines=None):
     prev_line = lline
 
   _AlignTrailingComments(final_lines)
-  return _FormatFinalLines(final_lines, verify)
+  return _FormatFinalLines(final_lines)
 
 
 def _RetainHorizontalSpacing(line):
@@ -248,8 +245,13 @@ def _CanPlaceOnSingleLine(line):
   Returns:
     True if the line can or should be added to a single line. False otherwise.
   """
-  token_names = [x.name for x in line.tokens]
-  if (style.Get('FORCE_MULTILINE_DICT') and 'LBRACE' in token_names):
+  token_types = [x.type for x in line.tokens]
+  if (style.Get('SPLIT_ARGUMENTS_WHEN_COMMA_TERMINATED') and
+      any(token_types[token_index - 1] == token.COMMA
+          for token_index, token_type in enumerate(token_types[1:], start=1)
+          if token_type == token.RPAR)):
+    return False
+  if (style.Get('FORCE_MULTILINE_DICT') and token.LBRACE in token_types):
     return False
   indent_amt = style.Get('INDENT_WIDTH') * line.depth
   last = line.last
@@ -393,7 +395,7 @@ def _AlignTrailingComments(final_lines):
       final_lines_index += 1
 
 
-def _FormatFinalLines(final_lines, verify):
+def _FormatFinalLines(final_lines):
   """Compose the final output from the finalized lines."""
   formatted_code = []
   for line in final_lines:
@@ -409,8 +411,6 @@ def _FormatFinalLines(final_lines, verify):
           formatted_line.append(' ')
 
     formatted_code.append(''.join(formatted_line))
-    if verify:
-      verifier.VerifyCode(formatted_code[-1])
 
   return ''.join(formatted_code) + '\n'
 
@@ -738,7 +738,8 @@ def _SingleOrMergedLines(lines):
         if line.last.value != ':':
           leaf = pytree.Leaf(
               type=token.SEMI, value=';', context=('', (line.lineno, column)))
-          line.AppendToken(format_token.FormatToken(leaf))
+          line.AppendToken(
+              format_token.FormatToken(leaf, pytree_utils.NodeName(leaf)))
         for tok in lines[index].tokens:
           line.AppendToken(tok)
         index += 1
diff --git a/yapf/yapflib/split_penalty.py b/yapf/yapflib/split_penalty.py
index 643ae24..79b68ed 100644
--- a/yapf/yapflib/split_penalty.py
+++ b/yapf/yapflib/split_penalty.py
@@ -1,4 +1,4 @@
-# Copyright 2015 Google Inc. All Rights Reserved.
+# Copyright 2022 Bill Wendling, All Rights Reserved.
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
 # you may not use this file except in compliance with the License.
@@ -11,621 +11,29 @@
 # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 # See the License for the specific language governing permissions and
 # limitations under the License.
-"""Computation of split penalties before/between tokens."""
 
-import re
-
-from lib2to3 import pytree
-from lib2to3.pgen2 import token as grammar_token
-
-from yapf.yapflib import format_token
-from yapf.yapflib import py3compat
-from yapf.yapflib import pytree_utils
-from yapf.yapflib import pytree_visitor
 from yapf.yapflib import style
-from yapf.yapflib import subtypes
-
-# TODO(morbo): Document the annotations in a centralized place. E.g., the
-# README file.
-UNBREAKABLE = 1000 * 1000
-NAMED_ASSIGN = 15000
-DOTTED_NAME = 4000
-VERY_STRONGLY_CONNECTED = 3500
-STRONGLY_CONNECTED = 3000
-CONNECTED = 500
-TOGETHER = 100
-
-OR_TEST = 1000
-AND_TEST = 1100
-NOT_TEST = 1200
-COMPARISON = 1300
-STAR_EXPR = 1300
-EXPR = 1400
-XOR_EXPR = 1500
-AND_EXPR = 1700
-SHIFT_EXPR = 1800
-ARITH_EXPR = 1900
-TERM = 2000
-FACTOR = 2100
-POWER = 2200
-ATOM = 2300
-ONE_ELEMENT_ARGUMENT = 500
-SUBSCRIPT = 6000
-
-
-def ComputeSplitPenalties(tree):
-  """Compute split penalties on tokens in the given parse tree.
-
-  Arguments:
-    tree: the top-level pytree node to annotate with penalties.
-  """
-  _SplitPenaltyAssigner().Visit(tree)
-
-
-class _SplitPenaltyAssigner(pytree_visitor.PyTreeVisitor):
-  """Assigns split penalties to tokens, based on parse tree structure.
-
-  Split penalties are attached as annotations to tokens.
-  """
-
-  def Visit(self, node):
-    if not hasattr(node, 'is_pseudo'):  # Ignore pseudo tokens.
-      super(_SplitPenaltyAssigner, self).Visit(node)
-
-  def Visit_import_as_names(self, node):  # pyline: disable=invalid-name
-    # import_as_names ::= import_as_name (',' import_as_name)* [',']
-    self.DefaultNodeVisit(node)
-    prev_child = None
-    for child in node.children:
-      if (prev_child and isinstance(prev_child, pytree.Leaf) and
-          prev_child.value == ','):
-        _SetSplitPenalty(child, style.Get('SPLIT_PENALTY_IMPORT_NAMES'))
-      prev_child = child
-
-  def Visit_classdef(self, node):  # pylint: disable=invalid-name
-    # classdef ::= 'class' NAME ['(' [arglist] ')'] ':' suite
-    #
-    # NAME
-    _SetUnbreakable(node.children[1])
-    if len(node.children) > 4:
-      # opening '('
-      _SetUnbreakable(node.children[2])
-    # ':'
-    _SetUnbreakable(node.children[-2])
-    self.DefaultNodeVisit(node)
-
-  def Visit_funcdef(self, node):  # pylint: disable=invalid-name
-    # funcdef ::= 'def' NAME parameters ['->' test] ':' suite
-    #
-    # Can't break before the function name and before the colon. The parameters
-    # are handled by child iteration.
-    colon_idx = 1
-    while pytree_utils.NodeName(node.children[colon_idx]) == 'simple_stmt':
-      colon_idx += 1
-    _SetUnbreakable(node.children[colon_idx])
-    arrow_idx = -1
-    while colon_idx < len(node.children):
-      if isinstance(node.children[colon_idx], pytree.Leaf):
-        if node.children[colon_idx].value == ':':
-          break
-        if node.children[colon_idx].value == '->':
-          arrow_idx = colon_idx
-      colon_idx += 1
-    _SetUnbreakable(node.children[colon_idx])
-    self.DefaultNodeVisit(node)
-    if arrow_idx > 0:
-      _SetSplitPenalty(
-          pytree_utils.LastLeafNode(node.children[arrow_idx - 1]), 0)
-      _SetUnbreakable(node.children[arrow_idx])
-      _SetStronglyConnected(node.children[arrow_idx + 1])
-
-  def Visit_lambdef(self, node):  # pylint: disable=invalid-name
-    # lambdef ::= 'lambda' [varargslist] ':' test
-    # Loop over the lambda up to and including the colon.
-    allow_multiline_lambdas = style.Get('ALLOW_MULTILINE_LAMBDAS')
-    if not allow_multiline_lambdas:
-      for child in node.children:
-        if child.type == grammar_token.COMMENT:
-          if re.search(r'pylint:.*disable=.*\bg-long-lambda', child.value):
-            allow_multiline_lambdas = True
-            break
-
-    if allow_multiline_lambdas:
-      _SetExpressionPenalty(node, STRONGLY_CONNECTED)
-    else:
-      _SetExpressionPenalty(node, VERY_STRONGLY_CONNECTED)
-
-  def Visit_parameters(self, node):  # pylint: disable=invalid-name
-    # parameters ::= '(' [typedargslist] ')'
-    self.DefaultNodeVisit(node)
-
-    # Can't break before the opening paren of a parameter list.
-    _SetUnbreakable(node.children[0])
-    if not (style.Get('INDENT_CLOSING_BRACKETS') or
-            style.Get('DEDENT_CLOSING_BRACKETS')):
-      _SetStronglyConnected(node.children[-1])
-
-  def Visit_arglist(self, node):  # pylint: disable=invalid-name
-    # arglist ::= argument (',' argument)* [',']
-    if node.children[0].type == grammar_token.STAR:
-      # Python 3 treats a star expression as a specific expression type.
-      # Process it in that method.
-      self.Visit_star_expr(node)
-      return
-
-    self.DefaultNodeVisit(node)
-
-    for index in py3compat.range(1, len(node.children)):
-      child = node.children[index]
-      if isinstance(child, pytree.Leaf) and child.value == ',':
-        _SetUnbreakable(child)
-
-    for child in node.children:
-      if pytree_utils.NodeName(child) == 'atom':
-        _IncreasePenalty(child, CONNECTED)
-
-  def Visit_argument(self, node):  # pylint: disable=invalid-name
-    # argument ::= test [comp_for] | test '=' test  # Really [keyword '='] test
-    self.DefaultNodeVisit(node)
-
-    for index in py3compat.range(1, len(node.children) - 1):
-      child = node.children[index]
-      if isinstance(child, pytree.Leaf) and child.value == '=':
-        _SetSplitPenalty(
-            pytree_utils.FirstLeafNode(node.children[index]), NAMED_ASSIGN)
-        _SetSplitPenalty(
-            pytree_utils.FirstLeafNode(node.children[index + 1]), NAMED_ASSIGN)
-
-  def Visit_tname(self, node):  # pylint: disable=invalid-name
-    # tname ::= NAME [':' test]
-    self.DefaultNodeVisit(node)
-
-    for index in py3compat.range(1, len(node.children) - 1):
-      child = node.children[index]
-      if isinstance(child, pytree.Leaf) and child.value == ':':
-        _SetSplitPenalty(
-            pytree_utils.FirstLeafNode(node.children[index]), NAMED_ASSIGN)
-        _SetSplitPenalty(
-            pytree_utils.FirstLeafNode(node.children[index + 1]), NAMED_ASSIGN)
-
-  def Visit_dotted_name(self, node):  # pylint: disable=invalid-name
-    # dotted_name ::= NAME ('.' NAME)*
-    for child in node.children:
-      self.Visit(child)
-    start = 2 if hasattr(node.children[0], 'is_pseudo') else 1
-    for i in py3compat.range(start, len(node.children)):
-      _SetUnbreakable(node.children[i])
-
-  def Visit_dictsetmaker(self, node):  # pylint: disable=invalid-name
-    # dictsetmaker ::= ( (test ':' test
-    #                      (comp_for | (',' test ':' test)* [','])) |
-    #                    (test (comp_for | (',' test)* [','])) )
-    for child in node.children:
-      self.Visit(child)
-      if child.type == grammar_token.COLON:
-        # This is a key to a dictionary. We don't want to split the key if at
-        # all possible.
-        _SetStronglyConnected(child)
-
-  def Visit_trailer(self, node):  # pylint: disable=invalid-name
-    # trailer ::= '(' [arglist] ')' | '[' subscriptlist ']' | '.' NAME
-    if node.children[0].value == '.':
-      before = style.Get('SPLIT_BEFORE_DOT')
-      _SetSplitPenalty(node.children[0],
-                       VERY_STRONGLY_CONNECTED if before else DOTTED_NAME)
-      _SetSplitPenalty(node.children[1],
-                       DOTTED_NAME if before else VERY_STRONGLY_CONNECTED)
-    elif len(node.children) == 2:
-      # Don't split an empty argument list if at all possible.
-      _SetSplitPenalty(node.children[1], VERY_STRONGLY_CONNECTED)
-    elif len(node.children) == 3:
-      name = pytree_utils.NodeName(node.children[1])
-      if name in {'argument', 'comparison'}:
-        # Don't split an argument list with one element if at all possible.
-        _SetStronglyConnected(node.children[1])
-        if (len(node.children[1].children) > 1 and
-            pytree_utils.NodeName(node.children[1].children[1]) == 'comp_for'):
-          # Don't penalize splitting before a comp_for expression.
-          _SetSplitPenalty(pytree_utils.FirstLeafNode(node.children[1]), 0)
-        else:
-          _SetSplitPenalty(
-              pytree_utils.FirstLeafNode(node.children[1]),
-              ONE_ELEMENT_ARGUMENT)
-      elif (node.children[0].type == grammar_token.LSQB and
-            len(node.children[1].children) > 2 and
-            (name.endswith('_test') or name.endswith('_expr'))):
-        _SetStronglyConnected(node.children[1].children[0])
-        _SetStronglyConnected(node.children[1].children[2])
-
-        # Still allow splitting around the operator.
-        split_before = ((name.endswith('_test') and
-                         style.Get('SPLIT_BEFORE_LOGICAL_OPERATOR')) or
-                        (name.endswith('_expr') and
-                         style.Get('SPLIT_BEFORE_BITWISE_OPERATOR')))
-        if split_before:
-          _SetSplitPenalty(
-              pytree_utils.LastLeafNode(node.children[1].children[1]), 0)
-        else:
-          _SetSplitPenalty(
-              pytree_utils.FirstLeafNode(node.children[1].children[2]), 0)
-
-        # Don't split the ending bracket of a subscript list.
-        _RecAnnotate(node.children[-1], pytree_utils.Annotation.SPLIT_PENALTY,
-                     VERY_STRONGLY_CONNECTED)
-      elif name not in {
-          'arglist', 'argument', 'term', 'or_test', 'and_test', 'comparison',
-          'atom', 'power'
-      }:
-        # Don't split an argument list with one element if at all possible.
-        stypes = pytree_utils.GetNodeAnnotation(
-            pytree_utils.FirstLeafNode(node), pytree_utils.Annotation.SUBTYPE)
-        if stypes and subtypes.SUBSCRIPT_BRACKET in stypes:
-          _IncreasePenalty(node, SUBSCRIPT)
-
-          # Bump up the split penalty for the first part of a subscript. We
-          # would rather not split there.
-          _IncreasePenalty(node.children[1], CONNECTED)
-        else:
-          _SetStronglyConnected(node.children[1], node.children[2])
-
-      if name == 'arglist':
-        _SetStronglyConnected(node.children[-1])
-
-    self.DefaultNodeVisit(node)
-
-  def Visit_power(self, node):  # pylint: disable=invalid-name,missing-docstring
-    # power ::= atom trailer* ['**' factor]
-    self.DefaultNodeVisit(node)
-
-    # When atom is followed by a trailer, we can not break between them.
-    # E.g. arr[idx] - no break allowed between 'arr' and '['.
-    if (len(node.children) > 1 and
-        pytree_utils.NodeName(node.children[1]) == 'trailer'):
-      # children[1] itself is a whole trailer: we don't want to
-      # mark all of it as unbreakable, only its first token: (, [ or .
-      first = pytree_utils.FirstLeafNode(node.children[1])
-      if first.value != '.':
-        _SetUnbreakable(node.children[1].children[0])
-
-      # A special case when there are more trailers in the sequence. Given:
-      #   atom tr1 tr2
-      # The last token of tr1 and the first token of tr2 comprise an unbreakable
-      # region. For example: foo.bar.baz(1)
-      # We can't put breaks between either of the '.', '(', or '[' and the names
-      # *preceding* them.
-      prev_trailer_idx = 1
-      while prev_trailer_idx < len(node.children) - 1:
-        cur_trailer_idx = prev_trailer_idx + 1
-        cur_trailer = node.children[cur_trailer_idx]
-        if pytree_utils.NodeName(cur_trailer) != 'trailer':
-          break
-
-        # Now we know we have two trailers one after the other
-        prev_trailer = node.children[prev_trailer_idx]
-        if prev_trailer.children[-1].value != ')':
-          # Set the previous node unbreakable if it's not a function call:
-          #   atom tr1() tr2
-          # It may be necessary (though undesirable) to split up a previous
-          # function call's parentheses to the next line.
-          _SetStronglyConnected(prev_trailer.children[-1])
-        _SetStronglyConnected(cur_trailer.children[0])
-        prev_trailer_idx = cur_trailer_idx
-
-    # We don't want to split before the last ')' of a function call. This also
-    # takes care of the special case of:
-    #   atom tr1 tr2 ... trn
-    # where the 'tr#' are trailers that may end in a ')'.
-    for trailer in node.children[1:]:
-      if pytree_utils.NodeName(trailer) != 'trailer':
-        break
-      if trailer.children[0].value in '([':
-        if len(trailer.children) > 2:
-          stypes = pytree_utils.GetNodeAnnotation(
-              trailer.children[0], pytree_utils.Annotation.SUBTYPE)
-          if stypes and subtypes.SUBSCRIPT_BRACKET in stypes:
-            _SetStronglyConnected(
-                pytree_utils.FirstLeafNode(trailer.children[1]))
-
-          last_child_node = pytree_utils.LastLeafNode(trailer)
-          if last_child_node.value.strip().startswith('#'):
-            last_child_node = last_child_node.prev_sibling
-          if not (style.Get('INDENT_CLOSING_BRACKETS') or
-                  style.Get('DEDENT_CLOSING_BRACKETS')):
-            last = pytree_utils.LastLeafNode(last_child_node.prev_sibling)
-            if last.value != ',':
-              if last_child_node.value == ']':
-                _SetUnbreakable(last_child_node)
-              else:
-                _SetSplitPenalty(last_child_node, VERY_STRONGLY_CONNECTED)
-        else:
-          # If the trailer's children are '()', then make it a strongly
-          # connected region.  It's sometimes necessary, though undesirable, to
-          # split the two.
-          _SetStronglyConnected(trailer.children[-1])
-
-  def Visit_subscriptlist(self, node):  # pylint: disable=invalid-name
-    # subscriptlist ::= subscript (',' subscript)* [',']
-    self.DefaultNodeVisit(node)
-    _SetSplitPenalty(pytree_utils.FirstLeafNode(node), 0)
-    prev_child = None
-    for child in node.children:
-      if prev_child and prev_child.type == grammar_token.COMMA:
-        _SetSplitPenalty(pytree_utils.FirstLeafNode(child), 0)
-      prev_child = child
-
-  def Visit_subscript(self, node):  # pylint: disable=invalid-name
-    # subscript ::= test | [test] ':' [test] [sliceop]
-    _SetStronglyConnected(*node.children)
-    self.DefaultNodeVisit(node)
-
-  def Visit_comp_for(self, node):  # pylint: disable=invalid-name
-    # comp_for ::= 'for' exprlist 'in' testlist_safe [comp_iter]
-    _SetSplitPenalty(pytree_utils.FirstLeafNode(node), 0)
-    _SetStronglyConnected(*node.children[1:])
-    self.DefaultNodeVisit(node)
-
-  def Visit_old_comp_for(self, node):  # pylint: disable=invalid-name
-    # Python 3.7
-    self.Visit_comp_for(node)
-
-  def Visit_comp_if(self, node):  # pylint: disable=invalid-name
-    # comp_if ::= 'if' old_test [comp_iter]
-    _SetSplitPenalty(node.children[0],
-                     style.Get('SPLIT_PENALTY_BEFORE_IF_EXPR'))
-    _SetStronglyConnected(*node.children[1:])
-    self.DefaultNodeVisit(node)
-
-  def Visit_old_comp_if(self, node):  # pylint: disable=invalid-name
-    # Python 3.7
-    self.Visit_comp_if(node)
-
-  def Visit_test(self, node):  # pylint: disable=invalid-name
-    # test ::= or_test ['if' or_test 'else' test] | lambdef
-    _IncreasePenalty(node, OR_TEST)
-    self.DefaultNodeVisit(node)
-
-  def Visit_or_test(self, node):  # pylint: disable=invalid-name
-    # or_test ::= and_test ('or' and_test)*
-    self.DefaultNodeVisit(node)
-    _IncreasePenalty(node, OR_TEST)
-    index = 1
-    while index + 1 < len(node.children):
-      if style.Get('SPLIT_BEFORE_LOGICAL_OPERATOR'):
-        _DecrementSplitPenalty(
-            pytree_utils.FirstLeafNode(node.children[index]), OR_TEST)
-      else:
-        _DecrementSplitPenalty(
-            pytree_utils.FirstLeafNode(node.children[index + 1]), OR_TEST)
-      index += 2
-
-  def Visit_and_test(self, node):  # pylint: disable=invalid-name
-    # and_test ::= not_test ('and' not_test)*
-    self.DefaultNodeVisit(node)
-    _IncreasePenalty(node, AND_TEST)
-    index = 1
-    while index + 1 < len(node.children):
-      if style.Get('SPLIT_BEFORE_LOGICAL_OPERATOR'):
-        _DecrementSplitPenalty(
-            pytree_utils.FirstLeafNode(node.children[index]), AND_TEST)
-      else:
-        _DecrementSplitPenalty(
-            pytree_utils.FirstLeafNode(node.children[index + 1]), AND_TEST)
-      index += 2
-
-  def Visit_not_test(self, node):  # pylint: disable=invalid-name
-    # not_test ::= 'not' not_test | comparison
-    self.DefaultNodeVisit(node)
-    _IncreasePenalty(node, NOT_TEST)
-
-  def Visit_comparison(self, node):  # pylint: disable=invalid-name
-    # comparison ::= expr (comp_op expr)*
-    self.DefaultNodeVisit(node)
-    if len(node.children) == 3 and _StronglyConnectedCompOp(node):
-      _IncreasePenalty(node.children[1], VERY_STRONGLY_CONNECTED)
-      _SetSplitPenalty(
-          pytree_utils.FirstLeafNode(node.children[2]), STRONGLY_CONNECTED)
-    else:
-      _IncreasePenalty(node, COMPARISON)
-
-  def Visit_star_expr(self, node):  # pylint: disable=invalid-name
-    # star_expr ::= '*' expr
-    self.DefaultNodeVisit(node)
-    _IncreasePenalty(node, STAR_EXPR)
-
-  def Visit_expr(self, node):  # pylint: disable=invalid-name
-    # expr ::= xor_expr ('|' xor_expr)*
-    self.DefaultNodeVisit(node)
-    _IncreasePenalty(node, EXPR)
-    _SetBitwiseOperandPenalty(node, '|')
-
-  def Visit_xor_expr(self, node):  # pylint: disable=invalid-name
-    # xor_expr ::= and_expr ('^' and_expr)*
-    self.DefaultNodeVisit(node)
-    _IncreasePenalty(node, XOR_EXPR)
-    _SetBitwiseOperandPenalty(node, '^')
-
-  def Visit_and_expr(self, node):  # pylint: disable=invalid-name
-    # and_expr ::= shift_expr ('&' shift_expr)*
-    self.DefaultNodeVisit(node)
-    _IncreasePenalty(node, AND_EXPR)
-    _SetBitwiseOperandPenalty(node, '&')
-
-  def Visit_shift_expr(self, node):  # pylint: disable=invalid-name
-    # shift_expr ::= arith_expr (('<<'|'>>') arith_expr)*
-    self.DefaultNodeVisit(node)
-    _IncreasePenalty(node, SHIFT_EXPR)
-
-  _ARITH_OPS = frozenset({'PLUS', 'MINUS'})
-
-  def Visit_arith_expr(self, node):  # pylint: disable=invalid-name
-    # arith_expr ::= term (('+'|'-') term)*
-    self.DefaultNodeVisit(node)
-    _IncreasePenalty(node, ARITH_EXPR)
-    _SetExpressionOperandPenalty(node, self._ARITH_OPS)
-
-  _TERM_OPS = frozenset({'STAR', 'AT', 'SLASH', 'PERCENT', 'DOUBLESLASH'})
-
-  def Visit_term(self, node):  # pylint: disable=invalid-name
-    # term ::= factor (('*'|'@'|'/'|'%'|'//') factor)*
-    self.DefaultNodeVisit(node)
-    _IncreasePenalty(node, TERM)
-    _SetExpressionOperandPenalty(node, self._TERM_OPS)
-
-  def Visit_factor(self, node):  # pyline: disable=invalid-name
-    # factor ::= ('+'|'-'|'~') factor | power
-    self.DefaultNodeVisit(node)
-    _IncreasePenalty(node, FACTOR)
-
-  def Visit_atom(self, node):  # pylint: disable=invalid-name
-    # atom ::= ('(' [yield_expr|testlist_gexp] ')'
-    #           '[' [listmaker] ']' |
-    #           '{' [dictsetmaker] '}')
-    self.DefaultNodeVisit(node)
-    if (node.children[0].value == '(' and
-        not hasattr(node.children[0], 'is_pseudo')):
-      if node.children[-1].value == ')':
-        if pytree_utils.NodeName(node.parent) == 'if_stmt':
-          _SetSplitPenalty(node.children[-1], STRONGLY_CONNECTED)
-        else:
-          if len(node.children) > 2:
-            _SetSplitPenalty(pytree_utils.FirstLeafNode(node.children[1]), EXPR)
-          _SetSplitPenalty(node.children[-1], ATOM)
-    elif node.children[0].value in '[{' and len(node.children) == 2:
-      # Keep empty containers together if we can.
-      _SetUnbreakable(node.children[-1])
-
-  def Visit_testlist_gexp(self, node):  # pylint: disable=invalid-name
-    self.DefaultNodeVisit(node)
-    prev_was_comma = False
-    for child in node.children:
-      if isinstance(child, pytree.Leaf) and child.value == ',':
-        _SetUnbreakable(child)
-        prev_was_comma = True
-      else:
-        if prev_was_comma:
-          _SetSplitPenalty(pytree_utils.FirstLeafNode(child), TOGETHER)
-        prev_was_comma = False
-
-
-def _SetUnbreakable(node):
-  """Set an UNBREAKABLE penalty annotation for the given node."""
-  _RecAnnotate(node, pytree_utils.Annotation.SPLIT_PENALTY, UNBREAKABLE)
-
-
-def _SetStronglyConnected(*nodes):
-  """Set a STRONGLY_CONNECTED penalty annotation for the given nodes."""
-  for node in nodes:
-    _RecAnnotate(node, pytree_utils.Annotation.SPLIT_PENALTY,
-                 STRONGLY_CONNECTED)
-
-
-def _SetExpressionPenalty(node, penalty):
-  """Set a penalty annotation on children nodes."""
-
-  def RecExpression(node, first_child_leaf):
-    if node is first_child_leaf:
-      return
-
-    if isinstance(node, pytree.Leaf):
-      if node.value in {'(', 'for', 'if'}:
-        return
-      penalty_annotation = pytree_utils.GetNodeAnnotation(
-          node, pytree_utils.Annotation.SPLIT_PENALTY, default=0)
-      if penalty_annotation < penalty:
-        _SetSplitPenalty(node, penalty)
-    else:
-      for child in node.children:
-        RecExpression(child, first_child_leaf)
-
-  RecExpression(node, pytree_utils.FirstLeafNode(node))
-
-
-def _SetBitwiseOperandPenalty(node, op):
-  for index in py3compat.range(1, len(node.children) - 1):
-    child = node.children[index]
-    if isinstance(child, pytree.Leaf) and child.value == op:
-      if style.Get('SPLIT_BEFORE_BITWISE_OPERATOR'):
-        _SetSplitPenalty(child, style.Get('SPLIT_PENALTY_BITWISE_OPERATOR'))
-      else:
-        _SetSplitPenalty(
-            pytree_utils.FirstLeafNode(node.children[index + 1]),
-            style.Get('SPLIT_PENALTY_BITWISE_OPERATOR'))
-
-
-def _SetExpressionOperandPenalty(node, ops):
-  for index in py3compat.range(1, len(node.children) - 1):
-    child = node.children[index]
-    if pytree_utils.NodeName(child) in ops:
-      if style.Get('SPLIT_BEFORE_ARITHMETIC_OPERATOR'):
-        _SetSplitPenalty(child, style.Get('SPLIT_PENALTY_ARITHMETIC_OPERATOR'))
-      else:
-        _SetSplitPenalty(
-            pytree_utils.FirstLeafNode(node.children[index + 1]),
-            style.Get('SPLIT_PENALTY_ARITHMETIC_OPERATOR'))
-
-
-def _IncreasePenalty(node, amt):
-  """Increase a penalty annotation on children nodes."""
-
-  def RecExpression(node, first_child_leaf):
-    if node is first_child_leaf:
-      return
-
-    if isinstance(node, pytree.Leaf):
-      if node.value in {'(', 'for'}:
-        return
-      penalty = pytree_utils.GetNodeAnnotation(
-          node, pytree_utils.Annotation.SPLIT_PENALTY, default=0)
-      _SetSplitPenalty(node, penalty + amt)
-    else:
-      for child in node.children:
-        RecExpression(child, first_child_leaf)
-
-  RecExpression(node, pytree_utils.FirstLeafNode(node))
-
-
-def _RecAnnotate(tree, annotate_name, annotate_value):
-  """Recursively set the given annotation on all leafs of the subtree.
-
-  Takes care to only increase the penalty. If the node already has a higher
-  or equal penalty associated with it, this is a no-op.
-
-  Args:
-    tree: subtree to annotate
-    annotate_name: name of the annotation to set
-    annotate_value: value of the annotation to set
-  """
-  for child in tree.children:
-    _RecAnnotate(child, annotate_name, annotate_value)
-  if isinstance(tree, pytree.Leaf):
-    cur_annotate = pytree_utils.GetNodeAnnotation(
-        tree, annotate_name, default=0)
-    if cur_annotate < annotate_value:
-      pytree_utils.SetNodeAnnotation(tree, annotate_name, annotate_value)
-
-
-def _StronglyConnectedCompOp(op):
-  if (len(op.children[1].children) == 2 and
-      pytree_utils.NodeName(op.children[1]) == 'comp_op'):
-    if (pytree_utils.FirstLeafNode(op.children[1]).value == 'not' and
-        pytree_utils.LastLeafNode(op.children[1]).value == 'in'):
-      return True
-    if (pytree_utils.FirstLeafNode(op.children[1]).value == 'is' and
-        pytree_utils.LastLeafNode(op.children[1]).value == 'not'):
-      return True
-  if (isinstance(op.children[1], pytree.Leaf) and
-      op.children[1].value in {'==', 'in'}):
-    return True
-  return False
-
-
-def _DecrementSplitPenalty(node, amt):
-  penalty = pytree_utils.GetNodeAnnotation(
-      node, pytree_utils.Annotation.SPLIT_PENALTY, default=amt)
-  penalty = penalty - amt if amt < penalty else 0
-  _SetSplitPenalty(node, penalty)
-
 
-def _SetSplitPenalty(node, penalty):
-  pytree_utils.SetNodeAnnotation(node, pytree_utils.Annotation.SPLIT_PENALTY,
-                                 penalty)
+# Generic split penalties
+UNBREAKABLE = 1000**5
+VERY_STRONGLY_CONNECTED = 5000
+STRONGLY_CONNECTED = 2500
+
+#############################################################################
+# Grammar-specific penalties - should be <= 1000                            #
+#############################################################################
+
+# Lambdas shouldn't be split unless absolutely necessary or if
+# ALLOW_MULTILINE_LAMBDAS is True.
+LAMBDA = 1000
+MULTILINE_LAMBDA = 500
+
+ANNOTATION = 100
+ARGUMENT = 25
+
+# TODO: Assign real values.
+RETURN_TYPE = 1
+DOTTED_NAME = 40
+EXPR = 10
+DICT_KEY_EXPR = 20
+DICT_VALUE_EXPR = 11
diff --git a/yapf/yapflib/style.py b/yapf/yapflib/style.py
index 233a64e..7642c01 100644
--- a/yapf/yapflib/style.py
+++ b/yapf/yapflib/style.py
@@ -15,10 +15,16 @@
 
 import os
 import re
+import sys
 import textwrap
+from configparser import ConfigParser
 
 from yapf.yapflib import errors
-from yapf.yapflib import py3compat
+
+if sys.version_info >= (3, 11):
+  import tomllib
+else:
+  import tomli as tomllib
 
 
 class StyleConfigError(errors.YapfError):
@@ -52,10 +58,10 @@ def SetGlobalStyle(style):
 
 
 _STYLE_HELP = dict(
+    # BASED_ON_STYLE='Which predefined style this style is based on',
     ALIGN_CLOSING_BRACKET_WITH_VISUAL_INDENT=textwrap.dedent("""\
-      Align closing bracket with visual indentation."""),
-    ALLOW_MULTILINE_LAMBDAS=textwrap.dedent("""\
-      Allow lambdas to be formatted on more than one line."""),
+      Align closing bracket with visual indentation.
+    """),
     ALLOW_MULTILINE_DICTIONARY_KEYS=textwrap.dedent("""\
       Allow dictionary keys to exist on multiple lines. For example:
 
@@ -63,12 +69,17 @@ _STYLE_HELP = dict(
             ('this is the first element of a tuple',
              'this is the second element of a tuple'):
                  value,
-        }"""),
+        }
+    """),
+    ALLOW_MULTILINE_LAMBDAS=textwrap.dedent("""\
+      Allow lambdas to be formatted on more than one line.
+    """),
     ALLOW_SPLIT_BEFORE_DEFAULT_OR_NAMED_ASSIGNS=textwrap.dedent("""\
       Allow splitting before a default / named assignment in an argument list.
-      """),
+    """),
     ALLOW_SPLIT_BEFORE_DICT_VALUE=textwrap.dedent("""\
-      Allow splits before the dictionary value."""),
+      Allow splits before the dictionary value.
+    """),
     ARITHMETIC_PRECEDENCE_INDICATION=textwrap.dedent("""\
       Let spacing indicate operator precedence. For example:
 
@@ -88,7 +99,13 @@ _STYLE_HELP = dict(
         e = 1*2 - 3
         f = 1 + 2 + 3 + 4
 
-      """),
+    """),
+    BLANK_LINE_BEFORE_CLASS_DOCSTRING=textwrap.dedent("""\
+      Insert a blank line before a class-level docstring.
+    """),
+    BLANK_LINE_BEFORE_MODULE_DOCSTRING=textwrap.dedent("""\
+      Insert a blank line before a module docstring.
+    """),
     BLANK_LINE_BEFORE_NESTED_CLASS_OR_DEF=textwrap.dedent("""\
       Insert a blank line before a 'def' or 'class' immediately nested
       within another 'def' or 'class'. For example:
@@ -96,17 +113,16 @@ _STYLE_HELP = dict(
         class Foo:
                            # <------ this blank line
           def method():
-            ..."""),
-    BLANK_LINE_BEFORE_CLASS_DOCSTRING=textwrap.dedent("""\
-      Insert a blank line before a class-level docstring."""),
-    BLANK_LINE_BEFORE_MODULE_DOCSTRING=textwrap.dedent("""\
-      Insert a blank line before a module docstring."""),
+            pass
+    """),
     BLANK_LINES_AROUND_TOP_LEVEL_DEFINITION=textwrap.dedent("""\
       Number of blank lines surrounding top-level function and class
-      definitions."""),
+      definitions.
+    """),
     BLANK_LINES_BETWEEN_TOP_LEVEL_IMPORTS_AND_VARIABLES=textwrap.dedent("""\
       Number of blank lines between top-level imports and variable
-      definitions."""),
+      definitions.
+    """),
     COALESCE_BRACKETS=textwrap.dedent("""\
       Do not split consecutive brackets. Only relevant when
       dedent_closing_brackets is set. For example:
@@ -123,9 +139,11 @@ _STYLE_HELP = dict(
          call_func_that_takes_a_dict({
              'key1': 'value1',
              'key2': 'value2',
-         })"""),
+         })
+    """),
     COLUMN_LIMIT=textwrap.dedent("""\
-      The column limit."""),
+      The column limit.
+    """),
     CONTINUATION_ALIGN_STYLE=textwrap.dedent("""\
       The style for continuation alignment. Possible values are:
 
@@ -135,9 +153,11 @@ _STYLE_HELP = dict(
         CONTINUATION_INDENT_WIDTH spaces) for continuation alignment.
       - VALIGN-RIGHT: Vertically align continuation lines to multiple of
         INDENT_WIDTH columns. Slightly right (one tab or a few spaces) if
-        cannot vertically align continuation lines with indent characters."""),
+        cannot vertically align continuation lines with indent characters.
+    """),
     CONTINUATION_INDENT_WIDTH=textwrap.dedent("""\
-      Indent width used for line continuations."""),
+      Indent width used for line continuations.
+    """),
     DEDENT_CLOSING_BRACKETS=textwrap.dedent("""\
       Put closing brackets on a separate line, dedented, if the bracketed
       expression can't fit in a single line. Applies to all kinds of brackets,
@@ -155,27 +175,42 @@ _STYLE_HELP = dict(
             start_ts=now()-timedelta(days=3),
             end_ts=now(),
         )        # <--- this bracket is dedented and on a separate line
-      """),
+    """),
     DISABLE_ENDING_COMMA_HEURISTIC=textwrap.dedent("""\
       Disable the heuristic which places each list element on a separate line
-      if the list is comma-terminated."""),
+      if the list is comma-terminated.
+
+      Note: The behavior of this flag changed in v0.40.3.  Before, if this flag
+      was true, we would split lists that contained a trailing comma or a
+      comment.  Now, we have a separate flag, `DISABLE_SPLIT_LIT_WITH_COMMENT`,
+      that controls splitting when a list contains a comment.  To get the old
+      behavior, set both flags to true.  More information in CHANGELOG.md.
+    """),
+    DISABLE_SPLIT_LIST_WITH_COMMENT=textwrap.dedent("""
+      Don't put every element on a new line within a list that contains
+      interstitial comments.
+    """),
     EACH_DICT_ENTRY_ON_SEPARATE_LINE=textwrap.dedent("""\
-      Place each dictionary entry onto its own line."""),
+      Place each dictionary entry onto its own line.
+    """),
     FORCE_MULTILINE_DICT=textwrap.dedent("""\
       Require multiline dictionary even if it would normally fit on one line.
       For example:
 
         config = {
             'key1': 'value1'
-        }"""),
+        }
+    """),
     I18N_COMMENT=textwrap.dedent("""\
       The regex for an i18n comment. The presence of this comment stops
       reformatting of that line, because the comments are required to be
-      next to the string they translate."""),
+      next to the string they translate.
+    """),
     I18N_FUNCTION_CALL=textwrap.dedent("""\
       The i18n function call names. The presence of this function stops
       reformattting on that line, because the string it has cannot be moved
-      away from the i18n comment."""),
+      away from the i18n comment.
+    """),
     INDENT_CLOSING_BRACKETS=textwrap.dedent("""\
       Put closing brackets on a separate line, indented, if the bracketed
       expression can't fit in a single line. Applies to all kinds of brackets,
@@ -193,7 +228,7 @@ _STYLE_HELP = dict(
             start_ts=now()-timedelta(days=3),
             end_ts=now(),
             )        # <--- this bracket is indented and on a separate line
-        """),
+    """),
     INDENT_DICTIONARY_VALUE=textwrap.dedent("""\
       Indent the dictionary value if it cannot fit on the same line as the
       dictionary key. For example:
@@ -204,13 +239,16 @@ _STYLE_HELP = dict(
             'key2': value1 +
                     value2,
         }
-      """),
-    INDENT_WIDTH=textwrap.dedent("""\
-      The number of columns to use for indentation."""),
+    """),
     INDENT_BLANK_LINES=textwrap.dedent("""\
-      Indent blank lines."""),
+      Indent blank lines.
+    """),
+    INDENT_WIDTH=textwrap.dedent("""\
+      The number of columns to use for indentation.
+    """),
     JOIN_MULTIPLE_LINES=textwrap.dedent("""\
-      Join short lines into one line. E.g., single line 'if' statements."""),
+      Join short lines into one line. E.g., single line 'if' statements.
+    """),
     NO_SPACES_AROUND_SELECTED_BINARY_OPERATORS=textwrap.dedent("""\
       Do not include spaces around selected binary operators. For example:
 
@@ -219,21 +257,21 @@ _STYLE_HELP = dict(
       will be formatted as follows when configured with "*,/":
 
         1 + 2*3 - 4/5
-      """),
+    """),
     SPACE_BETWEEN_ENDING_COMMA_AND_CLOSING_BRACKET=textwrap.dedent("""\
       Insert a space between the ending comma and closing bracket of a list,
-      etc."""),
+      etc.
+    """),
     SPACE_INSIDE_BRACKETS=textwrap.dedent("""\
       Use spaces inside brackets, braces, and parentheses.  For example:
 
         method_call( 1 )
         my_dict[ 3 ][ 1 ][ get_index( *args, **kwargs ) ]
         my_set = { 1, 2, 3 }
-      """),
-    SPACES_AROUND_POWER_OPERATOR=textwrap.dedent("""\
-      Use spaces around the power operator."""),
+    """),
     SPACES_AROUND_DEFAULT_OR_NAMED_ASSIGN=textwrap.dedent("""\
-      Use spaces around default or named assigns."""),
+      Use spaces around default or named assigns.
+    """),
     SPACES_AROUND_DICT_DELIMITERS=textwrap.dedent("""\
       Adds a space after the opening '{' and before the ending '}' dict
       delimiters.
@@ -243,7 +281,7 @@ _STYLE_HELP = dict(
       will be formatted as:
 
         { 1: 2 }
-      """),
+    """),
     SPACES_AROUND_LIST_DELIMITERS=textwrap.dedent("""\
       Adds a space after the opening '[' and before the ending ']' list
       delimiters.
@@ -253,12 +291,15 @@ _STYLE_HELP = dict(
       will be formatted as:
 
         [ 1, 2 ]
-      """),
+    """),
+    SPACES_AROUND_POWER_OPERATOR=textwrap.dedent("""\
+      Use spaces around the power operator.
+    """),
     SPACES_AROUND_SUBSCRIPT_COLON=textwrap.dedent("""\
       Use spaces around the subscript / slice operator.  For example:
 
         my_list[1 : 10 : 2]
-      """),
+    """),
     SPACES_AROUND_TUPLE_DELIMITERS=textwrap.dedent("""\
       Adds a space after the opening '(' and before the ending ')' tuple
       delimiters.
@@ -268,7 +309,7 @@ _STYLE_HELP = dict(
       will be formatted as:
 
         ( 1, 2, 3 )
-      """),
+    """),
     SPACES_BEFORE_COMMENT=textwrap.dedent("""\
       The number of spaces required before a trailing comment.
       This can be a single value (representing the number of spaces
@@ -310,24 +351,30 @@ _STYLE_HELP = dict(
         a_very_long_statement_that_extends_beyond_the_final_column  # Comment <-- the end of line comments are aligned based on the line length
         short                                                       # This is a shorter statement
 
-      """),  # noqa
-    SPLIT_ARGUMENTS_WHEN_COMMA_TERMINATED=textwrap.dedent("""\
-      Split before arguments if the argument list is terminated by a
-      comma."""),
+    """),  # noqa
     SPLIT_ALL_COMMA_SEPARATED_VALUES=textwrap.dedent("""\
-      Split before arguments"""),
+      Split before arguments.
+    """),
     SPLIT_ALL_TOP_LEVEL_COMMA_SEPARATED_VALUES=textwrap.dedent("""\
       Split before arguments, but do not split all subexpressions recursively
-      (unless needed)."""),
+      (unless needed).
+    """),
+    SPLIT_ARGUMENTS_WHEN_COMMA_TERMINATED=textwrap.dedent("""\
+      Split before arguments if the argument list is terminated by a
+      comma.
+    """),
     SPLIT_BEFORE_ARITHMETIC_OPERATOR=textwrap.dedent("""\
       Set to True to prefer splitting before '+', '-', '*', '/', '//', or '@'
-      rather than after."""),
+      rather than after.
+    """),
     SPLIT_BEFORE_BITWISE_OPERATOR=textwrap.dedent("""\
       Set to True to prefer splitting before '&', '|' or '^' rather than
-      after."""),
+      after.
+    """),
     SPLIT_BEFORE_CLOSING_BRACKET=textwrap.dedent("""\
       Split before the closing bracket if a list or dict literal doesn't fit on
-      a single line."""),
+      a single line.
+    """),
     SPLIT_BEFORE_DICT_SET_GENERATOR=textwrap.dedent("""\
       Split before a dictionary or set generator (comp_for). For example, note
       the split before the 'for':
@@ -335,7 +382,8 @@ _STYLE_HELP = dict(
         foo = {
             variable: 'Hello world, have a nice day!'
             for variable in bar if variable != 42
-        }"""),
+        }
+    """),
     SPLIT_BEFORE_DOT=textwrap.dedent("""\
       Split before the '.' if we need to split a longer expression:
 
@@ -345,19 +393,22 @@ _STYLE_HELP = dict(
 
         foo = ('This is a really long string: {}, {}, {}, {}'
                .format(a, b, c, d))
-      """),  # noqa
+    """),  # noqa
     SPLIT_BEFORE_EXPRESSION_AFTER_OPENING_PAREN=textwrap.dedent("""\
       Split after the opening paren which surrounds an expression if it doesn't
       fit on a single line.
-      """),
+    """),
     SPLIT_BEFORE_FIRST_ARGUMENT=textwrap.dedent("""\
       If an argument / parameter list is going to be split, then split before
-      the first argument."""),
+      the first argument.
+    """),
     SPLIT_BEFORE_LOGICAL_OPERATOR=textwrap.dedent("""\
       Set to True to prefer splitting before 'and' or 'or' rather than
-      after."""),
+      after.
+    """),
     SPLIT_BEFORE_NAMED_ASSIGNS=textwrap.dedent("""\
-      Split named assignments onto individual lines."""),
+      Split named assignments onto individual lines.
+    """),
     SPLIT_COMPLEX_COMPREHENSION=textwrap.dedent("""\
       Set to True to split list comprehensions and generators that have
       non-trivial expressions and multiple clauses before each of these
@@ -373,27 +424,34 @@ _STYLE_HELP = dict(
             a_long_var + 100
             for a_long_var in xrange(1000)
             if a_long_var % 10]
-      """),
+    """),
     SPLIT_PENALTY_AFTER_OPENING_BRACKET=textwrap.dedent("""\
-      The penalty for splitting right after the opening bracket."""),
+      The penalty for splitting right after the opening bracket.
+    """),
     SPLIT_PENALTY_AFTER_UNARY_OPERATOR=textwrap.dedent("""\
-      The penalty for splitting the line after a unary operator."""),
+      The penalty for splitting the line after a unary operator.
+    """),
     SPLIT_PENALTY_ARITHMETIC_OPERATOR=textwrap.dedent("""\
       The penalty of splitting the line around the '+', '-', '*', '/', '//',
-      ``%``, and '@' operators."""),
+      `%`, and '@' operators.
+    """),
     SPLIT_PENALTY_BEFORE_IF_EXPR=textwrap.dedent("""\
-      The penalty for splitting right before an if expression."""),
+      The penalty for splitting right before an if expression.
+    """),
     SPLIT_PENALTY_BITWISE_OPERATOR=textwrap.dedent("""\
-      The penalty of splitting the line around the '&', '|', and '^'
-      operators."""),
+      The penalty of splitting the line around the '&', '|', and '^' operators.
+    """),
     SPLIT_PENALTY_COMPREHENSION=textwrap.dedent("""\
       The penalty for splitting a list comprehension or generator
-      expression."""),
+      expression.
+    """),
     SPLIT_PENALTY_EXCESS_CHARACTER=textwrap.dedent("""\
-      The penalty for characters over the column limit."""),
+      The penalty for characters over the column limit.
+    """),
     SPLIT_PENALTY_FOR_ADDED_LINE_SPLIT=textwrap.dedent("""\
       The penalty incurred by adding a line split to the logical line. The
-      more line splits added the higher the penalty."""),
+      more line splits added the higher the penalty.
+    """),
     SPLIT_PENALTY_IMPORT_NAMES=textwrap.dedent("""\
       The penalty of splitting a list of "import as" names. For example:
 
@@ -405,13 +463,13 @@ _STYLE_HELP = dict(
 
         from a_very_long_or_indented_module_name_yada_yad import (
             long_argument_1, long_argument_2, long_argument_3)
-      """),  # noqa
+    """),  # noqa
     SPLIT_PENALTY_LOGICAL_OPERATOR=textwrap.dedent("""\
-      The penalty of splitting the line around the 'and' and 'or'
-      operators."""),
+      The penalty of splitting the line around the 'and' and 'or' operators.
+    """),
     USE_TABS=textwrap.dedent("""\
-      Use the Tab character for indentation."""),
-    # BASED_ON_STYLE='Which predefined style this style is based on',
+      Use the Tab character for indentation.
+    """),
 )
 
 
@@ -419,14 +477,14 @@ def CreatePEP8Style():
   """Create the PEP8 formatting style."""
   return dict(
       ALIGN_CLOSING_BRACKET_WITH_VISUAL_INDENT=True,
-      ALLOW_MULTILINE_LAMBDAS=False,
       ALLOW_MULTILINE_DICTIONARY_KEYS=False,
+      ALLOW_MULTILINE_LAMBDAS=False,
       ALLOW_SPLIT_BEFORE_DEFAULT_OR_NAMED_ASSIGNS=True,
       ALLOW_SPLIT_BEFORE_DICT_VALUE=True,
       ARITHMETIC_PRECEDENCE_INDICATION=False,
-      BLANK_LINE_BEFORE_NESTED_CLASS_OR_DEF=True,
       BLANK_LINE_BEFORE_CLASS_DOCSTRING=False,
       BLANK_LINE_BEFORE_MODULE_DOCSTRING=False,
+      BLANK_LINE_BEFORE_NESTED_CLASS_OR_DEF=True,
       BLANK_LINES_AROUND_TOP_LEVEL_DEFINITION=2,
       BLANK_LINES_BETWEEN_TOP_LEVEL_IMPORTS_AND_VARIABLES=1,
       COALESCE_BRACKETS=False,
@@ -434,12 +492,13 @@ def CreatePEP8Style():
       CONTINUATION_ALIGN_STYLE='SPACE',
       CONTINUATION_INDENT_WIDTH=4,
       DEDENT_CLOSING_BRACKETS=False,
-      INDENT_CLOSING_BRACKETS=False,
       DISABLE_ENDING_COMMA_HEURISTIC=False,
+      DISABLE_SPLIT_LIST_WITH_COMMENT=False,
       EACH_DICT_ENTRY_ON_SEPARATE_LINE=True,
       FORCE_MULTILINE_DICT=False,
       I18N_COMMENT='',
       I18N_FUNCTION_CALL='',
+      INDENT_CLOSING_BRACKETS=False,
       INDENT_DICTIONARY_VALUE=False,
       INDENT_WIDTH=4,
       INDENT_BLANK_LINES=False,
@@ -447,16 +506,16 @@ def CreatePEP8Style():
       NO_SPACES_AROUND_SELECTED_BINARY_OPERATORS=set(),
       SPACE_BETWEEN_ENDING_COMMA_AND_CLOSING_BRACKET=True,
       SPACE_INSIDE_BRACKETS=False,
-      SPACES_AROUND_POWER_OPERATOR=False,
       SPACES_AROUND_DEFAULT_OR_NAMED_ASSIGN=False,
       SPACES_AROUND_DICT_DELIMITERS=False,
       SPACES_AROUND_LIST_DELIMITERS=False,
+      SPACES_AROUND_POWER_OPERATOR=False,
       SPACES_AROUND_SUBSCRIPT_COLON=False,
       SPACES_AROUND_TUPLE_DELIMITERS=False,
       SPACES_BEFORE_COMMENT=2,
-      SPLIT_ARGUMENTS_WHEN_COMMA_TERMINATED=False,
       SPLIT_ALL_COMMA_SEPARATED_VALUES=False,
       SPLIT_ALL_TOP_LEVEL_COMMA_SEPARATED_VALUES=False,
+      SPLIT_ARGUMENTS_WHEN_COMMA_TERMINATED=False,
       SPLIT_BEFORE_ARITHMETIC_OPERATOR=False,
       SPLIT_BEFORE_BITWISE_OPERATOR=True,
       SPLIT_BEFORE_CLOSING_BRACKET=True,
@@ -526,15 +585,15 @@ def CreateFacebookStyle():
   style['SPLIT_PENALTY_AFTER_OPENING_BRACKET'] = 0
   style['SPLIT_PENALTY_BEFORE_IF_EXPR'] = 30
   style['SPLIT_PENALTY_FOR_ADDED_LINE_SPLIT'] = 30
-  style['SPLIT_BEFORE_LOGICAL_OPERATOR'] = False
   style['SPLIT_BEFORE_BITWISE_OPERATOR'] = False
+  style['SPLIT_BEFORE_LOGICAL_OPERATOR'] = False
   return style
 
 
 _STYLE_NAME_TO_FACTORY = dict(
-    pep8=CreatePEP8Style,
-    google=CreateGoogleStyle,
     facebook=CreateFacebookStyle,
+    google=CreateGoogleStyle,
+    pep8=CreatePEP8Style,
     yapf=CreateYapfStyle,
 )
 
@@ -579,7 +638,7 @@ def _StringSetConverter(s):
 
 def _BoolConverter(s):
   """Option value converter for a boolean."""
-  return py3compat.CONFIGPARSER_BOOLEAN_STATES[s.lower()]
+  return ConfigParser.BOOLEAN_STATES[s.lower()]
 
 
 def _IntListConverter(s):
@@ -607,14 +666,14 @@ def _IntOrIntListConverter(s):
 # Note: this dict has to map all the supported style options.
 _STYLE_OPTION_VALUE_CONVERTER = dict(
     ALIGN_CLOSING_BRACKET_WITH_VISUAL_INDENT=_BoolConverter,
-    ALLOW_MULTILINE_LAMBDAS=_BoolConverter,
     ALLOW_MULTILINE_DICTIONARY_KEYS=_BoolConverter,
+    ALLOW_MULTILINE_LAMBDAS=_BoolConverter,
     ALLOW_SPLIT_BEFORE_DEFAULT_OR_NAMED_ASSIGNS=_BoolConverter,
     ALLOW_SPLIT_BEFORE_DICT_VALUE=_BoolConverter,
     ARITHMETIC_PRECEDENCE_INDICATION=_BoolConverter,
-    BLANK_LINE_BEFORE_NESTED_CLASS_OR_DEF=_BoolConverter,
     BLANK_LINE_BEFORE_CLASS_DOCSTRING=_BoolConverter,
     BLANK_LINE_BEFORE_MODULE_DOCSTRING=_BoolConverter,
+    BLANK_LINE_BEFORE_NESTED_CLASS_OR_DEF=_BoolConverter,
     BLANK_LINES_AROUND_TOP_LEVEL_DEFINITION=int,
     BLANK_LINES_BETWEEN_TOP_LEVEL_IMPORTS_AND_VARIABLES=int,
     COALESCE_BRACKETS=_BoolConverter,
@@ -622,29 +681,30 @@ _STYLE_OPTION_VALUE_CONVERTER = dict(
     CONTINUATION_ALIGN_STYLE=_ContinuationAlignStyleStringConverter,
     CONTINUATION_INDENT_WIDTH=int,
     DEDENT_CLOSING_BRACKETS=_BoolConverter,
-    INDENT_CLOSING_BRACKETS=_BoolConverter,
     DISABLE_ENDING_COMMA_HEURISTIC=_BoolConverter,
+    DISABLE_SPLIT_LIST_WITH_COMMENT=_BoolConverter,
     EACH_DICT_ENTRY_ON_SEPARATE_LINE=_BoolConverter,
     FORCE_MULTILINE_DICT=_BoolConverter,
     I18N_COMMENT=str,
     I18N_FUNCTION_CALL=_StringListConverter,
+    INDENT_BLANK_LINES=_BoolConverter,
+    INDENT_CLOSING_BRACKETS=_BoolConverter,
     INDENT_DICTIONARY_VALUE=_BoolConverter,
     INDENT_WIDTH=int,
-    INDENT_BLANK_LINES=_BoolConverter,
     JOIN_MULTIPLE_LINES=_BoolConverter,
     NO_SPACES_AROUND_SELECTED_BINARY_OPERATORS=_StringSetConverter,
     SPACE_BETWEEN_ENDING_COMMA_AND_CLOSING_BRACKET=_BoolConverter,
     SPACE_INSIDE_BRACKETS=_BoolConverter,
-    SPACES_AROUND_POWER_OPERATOR=_BoolConverter,
     SPACES_AROUND_DEFAULT_OR_NAMED_ASSIGN=_BoolConverter,
     SPACES_AROUND_DICT_DELIMITERS=_BoolConverter,
     SPACES_AROUND_LIST_DELIMITERS=_BoolConverter,
+    SPACES_AROUND_POWER_OPERATOR=_BoolConverter,
     SPACES_AROUND_SUBSCRIPT_COLON=_BoolConverter,
     SPACES_AROUND_TUPLE_DELIMITERS=_BoolConverter,
     SPACES_BEFORE_COMMENT=_IntOrIntListConverter,
-    SPLIT_ARGUMENTS_WHEN_COMMA_TERMINATED=_BoolConverter,
     SPLIT_ALL_COMMA_SEPARATED_VALUES=_BoolConverter,
     SPLIT_ALL_TOP_LEVEL_COMMA_SEPARATED_VALUES=_BoolConverter,
+    SPLIT_ARGUMENTS_WHEN_COMMA_TERMINATED=_BoolConverter,
     SPLIT_BEFORE_ARITHMETIC_OPERATOR=_BoolConverter,
     SPLIT_BEFORE_BITWISE_OPERATOR=_BoolConverter,
     SPLIT_BEFORE_CLOSING_BRACKET=_BoolConverter,
@@ -702,7 +762,7 @@ def CreateStyleFromConfig(style_config):
 
   if isinstance(style_config, dict):
     config = _CreateConfigParserFromConfigDict(style_config)
-  elif isinstance(style_config, py3compat.basestring):
+  elif isinstance(style_config, str):
     style_factory = _STYLE_NAME_TO_FACTORY.get(style_config.lower())
     if style_factory is not None:
       return style_factory()
@@ -716,7 +776,7 @@ def CreateStyleFromConfig(style_config):
 
 
 def _CreateConfigParserFromConfigDict(config_dict):
-  config = py3compat.ConfigParser()
+  config = ConfigParser()
   config.add_section('style')
   for key, value in config_dict.items():
     config.set('style', key, str(value))
@@ -728,7 +788,7 @@ def _CreateConfigParserFromConfigString(config_string):
   if config_string[0] != '{' or config_string[-1] != '}':
     raise StyleConfigError(
         "Invalid style dict syntax: '{}'.".format(config_string))
-  config = py3compat.ConfigParser()
+  config = ConfigParser()
   config.add_section('style')
   for key, value, _ in re.findall(
       r'([a-zA-Z0-9_]+)\s*[:=]\s*'
@@ -746,18 +806,12 @@ def _CreateConfigParserFromConfigFile(config_filename):
     # Provide a more meaningful error here.
     raise StyleConfigError(
         '"{0}" is not a valid style or file path'.format(config_filename))
-  with open(config_filename) as style_file:
-    config = py3compat.ConfigParser()
-    if config_filename.endswith(PYPROJECT_TOML):
-      try:
-        import toml
-      except ImportError:
-        raise errors.YapfError(
-            "toml package is needed for using pyproject.toml as a "
-            "configuration file")
-
-      pyproject_toml = toml.load(style_file)
-      style_dict = pyproject_toml.get("tool", {}).get("yapf", None)
+  config = ConfigParser()
+
+  if config_filename.endswith(PYPROJECT_TOML):
+    with open(config_filename, 'rb') as style_file:
+      pyproject_toml = tomllib.load(style_file)
+      style_dict = pyproject_toml.get('tool', {}).get('yapf', None)
       if style_dict is None:
         raise StyleConfigError(
             'Unable to find section [tool.yapf] in {0}'.format(config_filename))
@@ -766,7 +820,9 @@ def _CreateConfigParserFromConfigFile(config_filename):
         config.set('style', k, str(v))
       return config
 
+  with open(config_filename) as style_file:
     config.read_file(style_file)
+
     if config_filename.endswith(SETUP_CONFIG):
       if not config.has_section('yapf'):
         raise StyleConfigError(
diff --git a/yapf/yapflib/subtypes.py b/yapf/yapflib/subtypes.py
index b4b7efe..3c234fb 100644
--- a/yapf/yapflib/subtypes.py
+++ b/yapf/yapflib/subtypes.py
@@ -38,3 +38,4 @@ TYPED_NAME_ARG_LIST = 21
 SIMPLE_EXPRESSION = 22
 PARAMETER_START = 23
 PARAMETER_STOP = 24
+LAMBDEF = 25
diff --git a/yapf/yapflib/verifier.py b/yapf/yapflib/verifier.py
deleted file mode 100644
index bcbe6fb..0000000
--- a/yapf/yapflib/verifier.py
+++ /dev/null
@@ -1,93 +0,0 @@
-# Copyright 2015 Google Inc. All Rights Reserved.
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#     http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-"""Verify that the generated code is valid code.
-
-This takes a line of code and "normalizes" it. I.e., it transforms the snippet
-into something that has the potential to compile.
-
-    VerifyCode(): the main function exported by this module.
-"""
-
-import ast
-import re
-import sys
-import textwrap
-
-
-class InternalError(Exception):
-  """Internal error in verifying formatted code."""
-  pass
-
-
-def VerifyCode(code):
-  """Verify that the reformatted code is syntactically correct.
-
-  Arguments:
-    code: (unicode) The reformatted code snippet.
-
-  Raises:
-    SyntaxError if the code was reformatted incorrectly.
-  """
-  try:
-    compile(textwrap.dedent(code).encode('UTF-8'), '<string>', 'exec')
-  except SyntaxError:
-    try:
-      ast.parse(textwrap.dedent(code.lstrip('\n')).lstrip(), '<string>', 'exec')
-    except SyntaxError:
-      try:
-        normalized_code = _NormalizeCode(code)
-        compile(normalized_code.encode('UTF-8'), '<string>', 'exec')
-      except SyntaxError:
-        raise InternalError(sys.exc_info()[1])
-
-
-def _NormalizeCode(code):
-  """Make sure that the code snippet is compilable."""
-  code = textwrap.dedent(code.lstrip('\n')).lstrip()
-
-  # Split the code to lines and get rid of all leading full-comment lines as
-  # they can mess up the normalization attempt.
-  lines = code.split('\n')
-  i = 0
-  for i, line in enumerate(lines):
-    line = line.strip()
-    if line and not line.startswith('#'):
-      break
-  code = '\n'.join(lines[i:]) + '\n'
-
-  if re.match(r'(if|while|for|with|def|class|async|await)\b', code):
-    code += '\n    pass'
-  elif re.match(r'(elif|else)\b', code):
-    try:
-      try_code = 'if True:\n    pass\n' + code + '\n    pass'
-      ast.parse(
-          textwrap.dedent(try_code.lstrip('\n')).lstrip(), '<string>', 'exec')
-      code = try_code
-    except SyntaxError:
-      # The assumption here is that the code is on a single line.
-      code = 'if True: pass\n' + code
-  elif code.startswith('@'):
-    code += '\ndef _():\n    pass'
-  elif re.match(r'try\b', code):
-    code += '\n    pass\nexcept:\n    pass'
-  elif re.match(r'(except|finally)\b', code):
-    code = 'try:\n    pass\n' + code + '\n    pass'
-  elif re.match(r'(return|yield)\b', code):
-    code = 'def _():\n    ' + code
-  elif re.match(r'(continue|break)\b', code):
-    code = 'while True:\n    ' + code
-  elif re.match(r'print\b', code):
-    code = 'from __future__ import print_function\n' + code
-
-  return code + '\n'
diff --git a/yapf/yapflib/yapf_api.py b/yapf/yapflib/yapf_api.py
index 09c31bc..aa010bb 100644
--- a/yapf/yapflib/yapf_api.py
+++ b/yapf/yapflib/yapf_api.py
@@ -29,36 +29,31 @@ These APIs have some common arguments:
     than a whole file.
   print_diff: (bool) Instead of returning the reformatted source, return a
     diff that turns the formatted source into reformatter source.
-  verify: (bool) True if reformatted code should be verified for syntax.
 """
 
+import codecs
 import difflib
 import re
-import sys
 
-from lib2to3.pgen2 import parse
-from lib2to3.pgen2 import tokenize
-
-from yapf.yapflib import blank_line_calculator
-from yapf.yapflib import comment_splicer
-from yapf.yapflib import continuation_splicer
+from yapf.pyparser import pyparser
+from yapf.pytree import blank_line_calculator
+from yapf.pytree import comment_splicer
+from yapf.pytree import continuation_splicer
+from yapf.pytree import pytree_unwrapper
+from yapf.pytree import pytree_utils
+from yapf.pytree import split_penalty
+from yapf.pytree import subtype_assigner
 from yapf.yapflib import errors
 from yapf.yapflib import file_resources
 from yapf.yapflib import identify_container
-from yapf.yapflib import py3compat
-from yapf.yapflib import pytree_unwrapper
-from yapf.yapflib import pytree_utils
 from yapf.yapflib import reformatter
-from yapf.yapflib import split_penalty
 from yapf.yapflib import style
-from yapf.yapflib import subtype_assigner
 
 
 def FormatFile(filename,
                style_config=None,
                lines=None,
                print_diff=False,
-               verify=False,
                in_place=False,
                logger=None):
   """Format a single Python file and return the formatted code.
@@ -74,7 +69,6 @@ def FormatFile(filename,
       than a whole file.
     print_diff: (bool) Instead of returning the reformatted source, return a
       diff that turns the formatted source into reformatter source.
-    verify: (bool) True if reformatted code should be verified for syntax.
     in_place: (bool) If True, write the reformatted code back to the file.
     logger: (io streamer) A stream to output logging.
 
@@ -87,8 +81,6 @@ def FormatFile(filename,
     IOError: raised if there was an error reading the file.
     ValueError: raised if in_place and print_diff are both specified.
   """
-  _CheckPythonVersion()
-
   if in_place and print_diff:
     raise ValueError('Cannot pass both in_place and print_diff.')
 
@@ -98,13 +90,11 @@ def FormatFile(filename,
       style_config=style_config,
       filename=filename,
       lines=lines,
-      print_diff=print_diff,
-      verify=verify)
-  if reformatted_source.rstrip('\n'):
-    lines = reformatted_source.rstrip('\n').split('\n')
-    reformatted_source = newline.join(iter(lines)) + newline
+      print_diff=print_diff)
+  if newline != '\n':
+    reformatted_source = reformatted_source.replace('\n', newline)
   if in_place:
-    if original_source and original_source != reformatted_source:
+    if changed:
       file_resources.WriteReformattedCode(filename, reformatted_source,
                                           encoding, in_place)
     return None, encoding, changed
@@ -112,7 +102,7 @@ def FormatFile(filename,
   return reformatted_source, encoding, changed
 
 
-def FormatTree(tree, style_config=None, lines=None, verify=False):
+def FormatTree(tree, style_config=None, lines=None):
   """Format a parsed lib2to3 pytree.
 
   This provides an alternative entry point to YAPF.
@@ -126,12 +116,10 @@ def FormatTree(tree, style_config=None, lines=None, verify=False):
       that we want to format. The lines are 1-based indexed. It can be used by
       third-party code (e.g., IDEs) when reformatting a snippet of code rather
       than a whole file.
-    verify: (bool) True if reformatted code should be verified for syntax.
 
   Returns:
     The source formatted according to the given formatting style.
   """
-  _CheckPythonVersion()
   style.SetGlobalStyle(style.CreateStyleFromConfig(style_config))
 
   # Run passes on the tree, modifying it in place.
@@ -148,15 +136,43 @@ def FormatTree(tree, style_config=None, lines=None, verify=False):
 
   lines = _LineRangesToSet(lines)
   _MarkLinesToFormat(llines, lines)
-  return reformatter.Reformat(_SplitSemicolons(llines), verify, lines)
+  return reformatter.Reformat(_SplitSemicolons(llines), lines)
+
+
+def FormatAST(ast, style_config=None, lines=None):
+  """Format a parsed lib2to3 pytree.
+
+  This provides an alternative entry point to YAPF.
+
+  Arguments:
+    unformatted_source: (unicode) The code to format.
+    style_config: (string) Either a style name or a path to a file that contains
+      formatting style settings. If None is specified, use the default style
+      as set in style.DEFAULT_STYLE_FACTORY
+    lines: (list of tuples of integers) A list of tuples of lines, [start, end],
+      that we want to format. The lines are 1-based indexed. It can be used by
+      third-party code (e.g., IDEs) when reformatting a snippet of code rather
+      than a whole file.
+
+  Returns:
+    The source formatted according to the given formatting style.
+  """
+  style.SetGlobalStyle(style.CreateStyleFromConfig(style_config))
+
+  llines = pyparser.ParseCode(ast)
+  for lline in llines:
+    lline.CalculateFormattingInformation()
+
+  lines = _LineRangesToSet(lines)
+  _MarkLinesToFormat(llines, lines)
+  return reformatter.Reformat(_SplitSemicolons(llines), lines)
 
 
 def FormatCode(unformatted_source,
                filename='<unknown>',
                style_config=None,
                lines=None,
-               print_diff=False,
-               verify=False):
+               print_diff=False):
   """Format a string of Python code.
 
   This provides an alternative entry point to YAPF.
@@ -173,7 +189,6 @@ def FormatCode(unformatted_source,
       than a whole file.
     print_diff: (bool) Instead of returning the reformatted source, return a
       diff that turns the formatted source into reformatter source.
-    verify: (bool) True if reformatted code should be verified for syntax.
 
   Returns:
     Tuple of (reformatted_source, changed). reformatted_source conforms to the
@@ -185,31 +200,19 @@ def FormatCode(unformatted_source,
     e.filename = filename
     raise errors.YapfError(errors.FormatErrorMsg(e))
 
-  reformatted_source = FormatTree(
-      tree, style_config=style_config, lines=lines, verify=verify)
+  reformatted_source = FormatTree(tree, style_config=style_config, lines=lines)
 
   if unformatted_source == reformatted_source:
     return '' if print_diff else reformatted_source, False
 
-  code_diff = _GetUnifiedDiff(
-      unformatted_source, reformatted_source, filename=filename)
-
   if print_diff:
+    code_diff = _GetUnifiedDiff(
+        unformatted_source, reformatted_source, filename=filename)
     return code_diff, code_diff.strip() != ''  # pylint: disable=g-explicit-bool-comparison # noqa
 
   return reformatted_source, True
 
 
-def _CheckPythonVersion():  # pragma: no cover
-  errmsg = 'yapf is only supported for Python 2.7 or 3.4+'
-  if sys.version_info[0] == 2:
-    if sys.version_info[1] < 7:
-      raise RuntimeError(errmsg)
-  elif sys.version_info[0] == 3:
-    if sys.version_info[1] < 4:
-      raise RuntimeError(errmsg)
-
-
 def ReadFile(filename, logger=None):
   """Read the contents of the file.
 
@@ -231,8 +234,7 @@ def ReadFile(filename, logger=None):
     encoding = file_resources.FileEncoding(filename)
 
     # Preserves line endings.
-    with py3compat.open_with_encoding(
-        filename, mode='r', encoding=encoding, newline='') as fd:
+    with codecs.open(filename, mode='r', encoding=encoding) as fd:
       lines = fd.readlines()
 
     line_ending = file_resources.LineEnding(lines)
@@ -259,8 +261,8 @@ def _SplitSemicolons(lines):
   return res
 
 
-DISABLE_PATTERN = r'^#.*\byapf:\s*disable\b'
-ENABLE_PATTERN = r'^#.*\byapf:\s*enable\b'
+DISABLE_PATTERN = r'^#.*\b(?:yapf:\s*disable|fmt: ?off)\b'
+ENABLE_PATTERN = r'^#.*\b(?:yapf:\s*enable|fmt: ?on)\b'
 
 
 def _LineRangesToSet(line_ranges):
diff --git a/yapftests/blank_line_calculator_test.py b/yapftests/blank_line_calculator_test.py
index 18fa83e..7c9ab0f 100644
--- a/yapftests/blank_line_calculator_test.py
+++ b/yapftests/blank_line_calculator_test.py
@@ -35,12 +35,12 @@ class BasicBlankLineCalculatorTest(yapf_test_helper.YAPFTest):
 
         def foo():
           pass
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         @bork()
         def foo():
           pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -59,7 +59,7 @@ class BasicBlankLineCalculatorTest(yapf_test_helper.YAPFTest):
 
           def method(self):
             pass
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         import sys
 
@@ -76,7 +76,7 @@ class BasicBlankLineCalculatorTest(yapf_test_helper.YAPFTest):
           @baz()
           def method(self):
             pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -96,7 +96,7 @@ class BasicBlankLineCalculatorTest(yapf_test_helper.YAPFTest):
           raise Error
         except Error as error:
           pass
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         def foo():
           pass
@@ -121,7 +121,7 @@ class BasicBlankLineCalculatorTest(yapf_test_helper.YAPFTest):
           raise Error
         except Error as error:
           pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -154,7 +154,7 @@ class BasicBlankLineCalculatorTest(yapf_test_helper.YAPFTest):
             # Another multiline
             # comment
             pass
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         # This is the first comment
         # And it's multiline
@@ -187,7 +187,7 @@ class BasicBlankLineCalculatorTest(yapf_test_helper.YAPFTest):
             # Another multiline
             # comment
             pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -198,7 +198,7 @@ class BasicBlankLineCalculatorTest(yapf_test_helper.YAPFTest):
           # pylint: disable=invalid-name
           def f(self):
             pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -211,7 +211,7 @@ class BasicBlankLineCalculatorTest(yapf_test_helper.YAPFTest):
 
         class Foo(object):
           pass
-        ''')
+    ''')
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -221,7 +221,7 @@ class BasicBlankLineCalculatorTest(yapf_test_helper.YAPFTest):
         @foo()
         def a():
           pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -232,7 +232,7 @@ class BasicBlankLineCalculatorTest(yapf_test_helper.YAPFTest):
         @foo()
         def a():
           pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -249,7 +249,7 @@ class BasicBlankLineCalculatorTest(yapf_test_helper.YAPFTest):
           #    reason="https://github.com/pypa/setuptools/issues/706")
           def test_unicode_filename_in_sdist(self, sdist_unicode, tmpdir, monkeypatch):
             pass
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -261,7 +261,7 @@ class BasicBlankLineCalculatorTest(yapf_test_helper.YAPFTest):
           class TaskValidationError(Error): pass
 
           class DeployAPIHTTPError(Error): pass
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
       class DeployAPIClient(object):
 
@@ -273,12 +273,12 @@ class BasicBlankLineCalculatorTest(yapf_test_helper.YAPFTest):
 
         class DeployAPIHTTPError(Error):
           pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testLinesOnRangeBoundary(self):
-    unformatted_code = textwrap.dedent(u"""\
+    unformatted_code = textwrap.dedent("""\
         def A():
           pass
 
@@ -291,8 +291,8 @@ class BasicBlankLineCalculatorTest(yapf_test_helper.YAPFTest):
           pass  # 10
         def E():
           pass
-        """)
-    expected_formatted_code = textwrap.dedent(u"""\
+    """)
+    expected_formatted_code = textwrap.dedent("""\
         def A():
           pass
 
@@ -308,14 +308,14 @@ class BasicBlankLineCalculatorTest(yapf_test_helper.YAPFTest):
           pass  # 10
         def E():
           pass
-        """)
+    """)
     code, changed = yapf_api.FormatCode(
         unformatted_code, lines=[(4, 5), (9, 10)])
     self.assertCodeEqual(expected_formatted_code, code)
     self.assertTrue(changed)
 
   def testLinesRangeBoundaryNotOutside(self):
-    unformatted_code = textwrap.dedent(u"""\
+    unformatted_code = textwrap.dedent("""\
         def A():
           pass
 
@@ -328,8 +328,8 @@ class BasicBlankLineCalculatorTest(yapf_test_helper.YAPFTest):
 
         def C():
           pass
-        """)
-    expected_formatted_code = textwrap.dedent(u"""\
+    """)
+    expected_formatted_code = textwrap.dedent("""\
         def A():
           pass
 
@@ -342,13 +342,13 @@ class BasicBlankLineCalculatorTest(yapf_test_helper.YAPFTest):
 
         def C():
           pass
-        """)
+    """)
     code, changed = yapf_api.FormatCode(unformatted_code, lines=[(6, 7)])
     self.assertCodeEqual(expected_formatted_code, code)
     self.assertFalse(changed)
 
   def testLinesRangeRemove(self):
-    unformatted_code = textwrap.dedent(u"""\
+    unformatted_code = textwrap.dedent("""\
         def A():
           pass
 
@@ -362,8 +362,8 @@ class BasicBlankLineCalculatorTest(yapf_test_helper.YAPFTest):
 
         def C():
           pass
-        """)
-    expected_formatted_code = textwrap.dedent(u"""\
+    """)
+    expected_formatted_code = textwrap.dedent("""\
         def A():
           pass
 
@@ -376,13 +376,13 @@ class BasicBlankLineCalculatorTest(yapf_test_helper.YAPFTest):
 
         def C():
           pass
-        """)
+    """)
     code, changed = yapf_api.FormatCode(unformatted_code, lines=[(5, 9)])
     self.assertCodeEqual(expected_formatted_code, code)
     self.assertTrue(changed)
 
   def testLinesRangeRemoveSome(self):
-    unformatted_code = textwrap.dedent(u"""\
+    unformatted_code = textwrap.dedent("""\
         def A():
           pass
 
@@ -397,8 +397,8 @@ class BasicBlankLineCalculatorTest(yapf_test_helper.YAPFTest):
 
         def C():
           pass
-        """)
-    expected_formatted_code = textwrap.dedent(u"""\
+    """)
+    expected_formatted_code = textwrap.dedent("""\
         def A():
           pass
 
@@ -412,7 +412,7 @@ class BasicBlankLineCalculatorTest(yapf_test_helper.YAPFTest):
 
         def C():
           pass
-        """)
+    """)
     code, changed = yapf_api.FormatCode(unformatted_code, lines=[(6, 9)])
     self.assertCodeEqual(expected_formatted_code, code)
     self.assertTrue(changed)
diff --git a/yapftests/comment_splicer_test.py b/yapftests/comment_splicer_test.py
index aacc888..3a63da7 100644
--- a/yapftests/comment_splicer_test.py
+++ b/yapftests/comment_splicer_test.py
@@ -16,12 +16,13 @@
 import textwrap
 import unittest
 
-from yapf.yapflib import comment_splicer
-from yapf.yapflib import py3compat
-from yapf.yapflib import pytree_utils
+from yapf.pytree import comment_splicer
+from yapf.pytree import pytree_utils
 
+from yapftests import yapf_test_helper
 
-class CommentSplicerTest(unittest.TestCase):
+
+class CommentSplicerTest(yapf_test_helper.YAPFTest):
 
   def _AssertNodeType(self, expected_type, node):
     self.assertEqual(expected_type, pytree_utils.NodeName(node))
@@ -38,14 +39,15 @@ class CommentSplicerTest(unittest.TestCase):
 
   def _FindNthChildNamed(self, node, name, n=1):
     for i, child in enumerate(
-        py3compat.ifilter(lambda c: pytree_utils.NodeName(c) == name,
-                          node.pre_order())):
+        [c for c in node.pre_order() if pytree_utils.NodeName(c) == name]):
       if i == n - 1:
         return child
     raise RuntimeError('No Nth child for n={0}'.format(n))
 
   def testSimpleInline(self):
-    code = 'foo = 1 # and a comment\n'
+    code = textwrap.dedent("""\
+        foo = 1 # and a comment
+    """)
     tree = pytree_utils.ParseCodeToTree(code)
     comment_splicer.SpliceComments(tree)
 
@@ -58,11 +60,11 @@ class CommentSplicerTest(unittest.TestCase):
     self._AssertNodeIsComment(comment_node, '# and a comment')
 
   def testSimpleSeparateLine(self):
-    code = textwrap.dedent(r'''
-      foo = 1
-      # first comment
-      bar = 2
-      ''')
+    code = textwrap.dedent("""\
+        foo = 1
+        # first comment
+        bar = 2
+    """)
     tree = pytree_utils.ParseCodeToTree(code)
     comment_splicer.SpliceComments(tree)
 
@@ -73,12 +75,12 @@ class CommentSplicerTest(unittest.TestCase):
     self._AssertNodeIsComment(comment_node)
 
   def testTwoLineComment(self):
-    code = textwrap.dedent(r'''
-      foo = 1
-      # first comment
-      # second comment
-      bar = 2
-      ''')
+    code = textwrap.dedent("""\
+        foo = 1
+        # first comment
+        # second comment
+        bar = 2
+    """)
     tree = pytree_utils.ParseCodeToTree(code)
     comment_splicer.SpliceComments(tree)
 
@@ -87,11 +89,11 @@ class CommentSplicerTest(unittest.TestCase):
     self._AssertNodeIsComment(tree.children[1])
 
   def testCommentIsFirstChildInCompound(self):
-    code = textwrap.dedent(r'''
-      if x:
-        # a comment
-        foo = 1
-      ''')
+    code = textwrap.dedent("""
+        if x:
+          # a comment
+          foo = 1
+    """)
     tree = pytree_utils.ParseCodeToTree(code)
     comment_splicer.SpliceComments(tree)
 
@@ -103,11 +105,11 @@ class CommentSplicerTest(unittest.TestCase):
     self._AssertNodeIsComment(if_suite.children[1])
 
   def testCommentIsLastChildInCompound(self):
-    code = textwrap.dedent(r'''
-      if x:
-        foo = 1
-        # a comment
-      ''')
+    code = textwrap.dedent("""\
+        if x:
+          foo = 1
+          # a comment
+    """)
     tree = pytree_utils.ParseCodeToTree(code)
     comment_splicer.SpliceComments(tree)
 
@@ -119,11 +121,11 @@ class CommentSplicerTest(unittest.TestCase):
     self._AssertNodeIsComment(if_suite.children[-2])
 
   def testInlineAfterSeparateLine(self):
-    code = textwrap.dedent(r'''
-      bar = 1
-      # line comment
-      foo = 1 # inline comment
-      ''')
+    code = textwrap.dedent("""\
+        bar = 1
+        # line comment
+        foo = 1 # inline comment
+    """)
     tree = pytree_utils.ParseCodeToTree(code)
     comment_splicer.SpliceComments(tree)
 
@@ -137,11 +139,11 @@ class CommentSplicerTest(unittest.TestCase):
     self._AssertNodeIsComment(inline_comment_node, '# inline comment')
 
   def testSeparateLineAfterInline(self):
-    code = textwrap.dedent(r'''
-      bar = 1
-      foo = 1 # inline comment
-      # line comment
-      ''')
+    code = textwrap.dedent("""\
+        bar = 1
+        foo = 1 # inline comment
+        # line comment
+    """)
     tree = pytree_utils.ParseCodeToTree(code)
     comment_splicer.SpliceComments(tree)
 
@@ -155,12 +157,12 @@ class CommentSplicerTest(unittest.TestCase):
     self._AssertNodeIsComment(inline_comment_node, '# inline comment')
 
   def testCommentBeforeDedent(self):
-    code = textwrap.dedent(r'''
-      if bar:
-        z = 1
-      # a comment
-      j = 2
-      ''')
+    code = textwrap.dedent("""\
+        if bar:
+          z = 1
+        # a comment
+        j = 2
+    """)
     tree = pytree_utils.ParseCodeToTree(code)
     comment_splicer.SpliceComments(tree)
 
@@ -170,13 +172,13 @@ class CommentSplicerTest(unittest.TestCase):
     self._AssertNodeType('DEDENT', if_suite.children[-1])
 
   def testCommentBeforeDedentTwoLevel(self):
-    code = textwrap.dedent(r'''
-      if foo:
-        if bar:
-          z = 1
-        # a comment
-      y = 1
-      ''')
+    code = textwrap.dedent("""\
+        if foo:
+          if bar:
+            z = 1
+          # a comment
+        y = 1
+    """)
     tree = pytree_utils.ParseCodeToTree(code)
     comment_splicer.SpliceComments(tree)
 
@@ -187,13 +189,13 @@ class CommentSplicerTest(unittest.TestCase):
     self._AssertNodeType('DEDENT', if_suite.children[-1])
 
   def testCommentBeforeDedentTwoLevelImproperlyIndented(self):
-    code = textwrap.dedent(r'''
-      if foo:
-        if bar:
-          z = 1
-         # comment 2
-      y = 1
-      ''')
+    code = textwrap.dedent("""\
+        if foo:
+          if bar:
+            z = 1
+           # comment 2
+        y = 1
+    """)
     tree = pytree_utils.ParseCodeToTree(code)
     comment_splicer.SpliceComments(tree)
 
@@ -207,15 +209,15 @@ class CommentSplicerTest(unittest.TestCase):
     self._AssertNodeType('DEDENT', if_suite.children[-1])
 
   def testCommentBeforeDedentThreeLevel(self):
-    code = textwrap.dedent(r'''
-      if foo:
-        if bar:
-          z = 1
-          # comment 2
-        # comment 1
-      # comment 0
-      j = 2
-      ''')
+    code = textwrap.dedent("""\
+        if foo:
+          if bar:
+            z = 1
+            # comment 2
+          # comment 1
+        # comment 0
+        j = 2
+    """)
     tree = pytree_utils.ParseCodeToTree(code)
     comment_splicer.SpliceComments(tree)
 
@@ -234,13 +236,13 @@ class CommentSplicerTest(unittest.TestCase):
     self._AssertNodeType('DEDENT', if_suite_2.children[-1])
 
   def testCommentsInClass(self):
-    code = textwrap.dedent(r'''
-      class Foo:
-        """docstring abc..."""
-        # top-level comment
-        def foo(): pass
-        # another comment
-      ''')
+    code = textwrap.dedent("""\
+        class Foo:
+          '''docstring abc...'''
+          # top-level comment
+          def foo(): pass
+          # another comment
+    """)
 
     tree = pytree_utils.ParseCodeToTree(code)
     comment_splicer.SpliceComments(tree)
@@ -256,13 +258,13 @@ class CommentSplicerTest(unittest.TestCase):
     self._AssertNodeIsComment(toplevel_comment, '# top-level')
 
   def testMultipleBlockComments(self):
-    code = textwrap.dedent(r'''
+    code = textwrap.dedent("""\
         # Block comment number 1
 
         # Block comment number 2
         def f():
           pass
-        ''')
+    """)
 
     tree = pytree_utils.ParseCodeToTree(code)
     comment_splicer.SpliceComments(tree)
@@ -275,7 +277,7 @@ class CommentSplicerTest(unittest.TestCase):
     self._AssertNodeIsComment(block_comment_2, '# Block comment number 2')
 
   def testCommentsOnDedents(self):
-    code = textwrap.dedent(r'''
+    code = textwrap.dedent("""\
         class Foo(object):
           # A comment for qux.
           def qux(self):
@@ -285,7 +287,7 @@ class CommentSplicerTest(unittest.TestCase):
 
           def mux(self):
             pass
-        ''')
+    """)
 
     tree = pytree_utils.ParseCodeToTree(code)
     comment_splicer.SpliceComments(tree)
@@ -299,10 +301,10 @@ class CommentSplicerTest(unittest.TestCase):
     self._AssertNodeIsComment(interim_comment, '# Interim comment.')
 
   def testExprComments(self):
-    code = textwrap.dedent(r'''
-      foo( # Request fractions of an hour.
-        948.0/3600, 20)
-    ''')
+    code = textwrap.dedent("""\
+        foo( # Request fractions of an hour.
+          948.0/3600, 20)
+    """)
     tree = pytree_utils.ParseCodeToTree(code)
     comment_splicer.SpliceComments(tree)
 
@@ -311,12 +313,12 @@ class CommentSplicerTest(unittest.TestCase):
     self._AssertNodeIsComment(comment, '# Request fractions of an hour.')
 
   def testMultipleCommentsInOneExpr(self):
-    code = textwrap.dedent(r'''
-      foo( # com 1
-        948.0/3600, # com 2
-        20 + 12 # com 3
-        )
-    ''')
+    code = textwrap.dedent("""\
+        foo( # com 1
+          948.0/3600, # com 2
+          20 + 12 # com 3
+          )
+    """)
     tree = pytree_utils.ParseCodeToTree(code)
     comment_splicer.SpliceComments(tree)
 
diff --git a/yapftests/file_resources_test.py b/yapftests/file_resources_test.py
index 31184c4..e71742c 100644
--- a/yapftests/file_resources_test.py
+++ b/yapftests/file_resources_test.py
@@ -14,17 +14,19 @@
 # limitations under the License.
 """Tests for yapf.file_resources."""
 
+import codecs
 import contextlib
 import os
 import shutil
 import tempfile
 import unittest
+from io import BytesIO
 
 from yapf.yapflib import errors
 from yapf.yapflib import file_resources
-from yapf.yapflib import py3compat
 
 from yapftests import utils
+from yapftests import yapf_test_helper
 
 
 @contextlib.contextmanager
@@ -46,7 +48,7 @@ def _exists_mocked_in_module(module, mock_implementation):
     setattr(module, 'exists', unmocked_exists)
 
 
-class GetExcludePatternsForDir(unittest.TestCase):
+class GetExcludePatternsForDir(yapf_test_helper.YAPFTest):
 
   def setUp(self):  # pylint: disable=g-missing-super-call
     self.test_tmpdir = tempfile.mkdtemp()
@@ -74,10 +76,6 @@ class GetExcludePatternsForDir(unittest.TestCase):
       file_resources.GetExcludePatternsForDir(self.test_tmpdir)
 
   def test_get_exclude_file_patterns_from_pyproject(self):
-    try:
-      import toml
-    except ImportError:
-      return
     local_ignore_file = os.path.join(self.test_tmpdir, 'pyproject.toml')
     ignore_patterns = ['temp/**/*.py', 'temp2/*.py']
     with open(local_ignore_file, 'w') as f:
@@ -90,28 +88,7 @@ class GetExcludePatternsForDir(unittest.TestCase):
         sorted(file_resources.GetExcludePatternsForDir(self.test_tmpdir)),
         sorted(ignore_patterns))
 
-  @unittest.skipUnless(py3compat.PY36, 'Requires Python 3.6')
-  def test_get_exclude_file_patterns_from_pyproject_with_wrong_syntax(self):
-    try:
-      import toml
-    except ImportError:
-      return
-    local_ignore_file = os.path.join(self.test_tmpdir, 'pyproject.toml')
-    ignore_patterns = ['temp/**/*.py', './wrong/syntax/*.py']
-    with open(local_ignore_file, 'w') as f:
-      f.write('[tool.yapfignore]\n')
-      f.write('ignore_patterns=[')
-      f.writelines('\n,'.join(['"{}"'.format(p) for p in ignore_patterns]))
-      f.write(']')
-
-    with self.assertRaises(errors.YapfError):
-      file_resources.GetExcludePatternsForDir(self.test_tmpdir)
-
   def test_get_exclude_file_patterns_from_pyproject_no_ignore_section(self):
-    try:
-      import toml
-    except ImportError:
-      return
     local_ignore_file = os.path.join(self.test_tmpdir, 'pyproject.toml')
     ignore_patterns = []
     open(local_ignore_file, 'w').close()
@@ -121,10 +98,6 @@ class GetExcludePatternsForDir(unittest.TestCase):
         sorted(ignore_patterns))
 
   def test_get_exclude_file_patterns_from_pyproject_ignore_section_empty(self):
-    try:
-      import toml
-    except ImportError:
-      return
     local_ignore_file = os.path.join(self.test_tmpdir, 'pyproject.toml')
     ignore_patterns = []
     with open(local_ignore_file, 'w') as f:
@@ -142,7 +115,7 @@ class GetExcludePatternsForDir(unittest.TestCase):
         sorted(ignore_patterns))
 
 
-class GetDefaultStyleForDirTest(unittest.TestCase):
+class GetDefaultStyleForDirTest(yapf_test_helper.YAPFTest):
 
   def setUp(self):  # pylint: disable=g-missing-super-call
     self.test_tmpdir = tempfile.mkdtemp()
@@ -190,12 +163,6 @@ class GetDefaultStyleForDirTest(unittest.TestCase):
                      file_resources.GetDefaultStyleForDir(test_dir))
 
   def test_pyproject_toml(self):
-    # An empty pyproject.toml file should not be used
-    try:
-      import toml
-    except ImportError:
-      return
-
     pyproject_toml = os.path.join(self.test_tmpdir, 'pyproject.toml')
     open(pyproject_toml, 'w').close()
 
@@ -237,7 +204,7 @@ def _touch_files(filenames):
     open(name, 'a').close()
 
 
-class GetCommandLineFilesTest(unittest.TestCase):
+class GetCommandLineFilesTest(yapf_test_helper.YAPFTest):
 
   def setUp(self):  # pylint: disable=g-missing-super-call
     self.test_tmpdir = tempfile.mkdtemp()
@@ -350,7 +317,7 @@ class GetCommandLineFilesTest(unittest.TestCase):
     child of the current directory which has been specified in a relative
     manner.
 
-    At its core, the bug has to do with overzelous stripping of "./foo" so that
+    At its core, the bug has to do with overzealous stripping of "./foo" so that
     it removes too much from "./.foo" .
     """
     tdir1 = self._make_test_dir('.test1')
@@ -406,7 +373,7 @@ class GetCommandLineFilesTest(unittest.TestCase):
                                            ]))
 
     self.assertEqual(
-        found, ['test3/foo/bar/bas/xxx/testfile3.py'.replace("/", os.path.sep)])
+        found, ['test3/foo/bar/bas/xxx/testfile3.py'.replace('/', os.path.sep)])
 
     found = sorted(
         file_resources.GetCommandLineFiles(['.'],
@@ -417,14 +384,14 @@ class GetCommandLineFilesTest(unittest.TestCase):
                                            ]))
 
     self.assertEqual(
-        found, ['./test2/testinner/testfile2.py'.replace("/", os.path.sep)])
+        found, ['./test2/testinner/testfile2.py'.replace('/', os.path.sep)])
 
   def test_find_with_excluded_current_dir(self):
     with self.assertRaises(errors.YapfError):
       file_resources.GetCommandLineFiles([], False, exclude=['./z'])
 
 
-class IsPythonFileTest(unittest.TestCase):
+class IsPythonFileTest(yapf_test_helper.YAPFTest):
 
   def setUp(self):  # pylint: disable=g-missing-super-call
     self.test_tmpdir = tempfile.mkdtemp()
@@ -445,29 +412,29 @@ class IsPythonFileTest(unittest.TestCase):
   def test_python_shebang(self):
     file1 = os.path.join(self.test_tmpdir, 'testfile1')
     with open(file1, 'w') as f:
-      f.write(u'#!/usr/bin/python\n')
+      f.write('#!/usr/bin/python\n')
     self.assertTrue(file_resources.IsPythonFile(file1))
 
     file2 = os.path.join(self.test_tmpdir, 'testfile2.run')
     with open(file2, 'w') as f:
-      f.write(u'#! /bin/python2\n')
+      f.write('#! /bin/python2\n')
     self.assertTrue(file_resources.IsPythonFile(file1))
 
   def test_with_latin_encoding(self):
     file1 = os.path.join(self.test_tmpdir, 'testfile1')
-    with py3compat.open_with_encoding(file1, mode='w', encoding='latin-1') as f:
-      f.write(u'#! /bin/python2\n')
+    with codecs.open(file1, mode='w', encoding='latin-1') as f:
+      f.write('#! /bin/python2\n')
     self.assertTrue(file_resources.IsPythonFile(file1))
 
   def test_with_invalid_encoding(self):
     file1 = os.path.join(self.test_tmpdir, 'testfile1')
     with open(file1, 'w') as f:
-      f.write(u'#! /bin/python2\n')
-      f.write(u'# -*- coding: iso-3-14159 -*-\n')
+      f.write('#! /bin/python2\n')
+      f.write('# -*- coding: iso-3-14159 -*-\n')
     self.assertFalse(file_resources.IsPythonFile(file1))
 
 
-class IsIgnoredTest(unittest.TestCase):
+class IsIgnoredTest(yapf_test_helper.YAPFTest):
 
   def test_root_path(self):
     self.assertTrue(file_resources.IsIgnored('media', ['media']))
@@ -486,7 +453,7 @@ class IsIgnoredTest(unittest.TestCase):
 class BufferedByteStream(object):
 
   def __init__(self):
-    self.stream = py3compat.BytesIO()
+    self.stream = BytesIO()
 
   def getvalue(self):  # pylint: disable=invalid-name
     return self.stream.getvalue().decode('utf-8')
@@ -496,7 +463,7 @@ class BufferedByteStream(object):
     return self.stream
 
 
-class WriteReformattedCodeTest(unittest.TestCase):
+class WriteReformattedCodeTest(yapf_test_helper.YAPFTest):
 
   @classmethod
   def setUpClass(cls):  # pylint: disable=g-missing-super-call
@@ -507,7 +474,7 @@ class WriteReformattedCodeTest(unittest.TestCase):
     shutil.rmtree(cls.test_tmpdir)
 
   def test_write_to_file(self):
-    s = u'foobar\n'
+    s = 'foobar\n'
     with utils.NamedTempFile(dirname=self.test_tmpdir) as (f, fname):
       file_resources.WriteReformattedCode(
           fname, s, in_place=True, encoding='utf-8')
@@ -517,8 +484,8 @@ class WriteReformattedCodeTest(unittest.TestCase):
         self.assertEqual(f2.read(), s)
 
   def test_write_to_stdout(self):
-    s = u'foobar'
-    stream = BufferedByteStream() if py3compat.PY3 else py3compat.StringIO()
+    s = 'foobar'
+    stream = BufferedByteStream()
     with utils.stdout_redirector(stream):
       file_resources.WriteReformattedCode(
           None, s, in_place=False, encoding='utf-8')
@@ -526,14 +493,14 @@ class WriteReformattedCodeTest(unittest.TestCase):
 
   def test_write_encoded_to_stdout(self):
     s = '\ufeff# -*- coding: utf-8 -*-\nresult = "passed"\n'  # pylint: disable=anomalous-unicode-escape-in-string # noqa
-    stream = BufferedByteStream() if py3compat.PY3 else py3compat.StringIO()
+    stream = BufferedByteStream()
     with utils.stdout_redirector(stream):
       file_resources.WriteReformattedCode(
           None, s, in_place=False, encoding='utf-8')
     self.assertEqual(stream.getvalue(), s)
 
 
-class LineEndingTest(unittest.TestCase):
+class LineEndingTest(yapf_test_helper.YAPFTest):
 
   def test_line_ending_linefeed(self):
     lines = ['spam\n', 'spam\n']
@@ -560,6 +527,26 @@ class LineEndingTest(unittest.TestCase):
     actual = file_resources.LineEnding(lines)
     self.assertEqual(actual, '\n')
 
+  def test_line_ending_empty(self):
+    lines = []
+    actual = file_resources.LineEnding(lines)
+    self.assertEqual(actual, '\n')
+
+  def test_line_ending_no_newline(self):
+    lines = ['spam']
+    actual = file_resources.LineEnding(lines)
+    self.assertEqual(actual, '\n')
+
+  def test_line_ending_tie(self):
+    lines = [
+        'spam\n',
+        'spam\n',
+        'spam\r\n',
+        'spam\r\n',
+    ]
+    actual = file_resources.LineEnding(lines)
+    self.assertEqual(actual, '\n')
+
 
 if __name__ == '__main__':
   unittest.main()
diff --git a/yapftests/format_decision_state_test.py b/yapftests/format_decision_state_test.py
index 9d62267..4dd7b8b 100644
--- a/yapftests/format_decision_state_test.py
+++ b/yapftests/format_decision_state_test.py
@@ -16,9 +16,9 @@
 import textwrap
 import unittest
 
+from yapf.pytree import pytree_utils
 from yapf.yapflib import format_decision_state
 from yapf.yapflib import logical_line
-from yapf.yapflib import pytree_utils
 from yapf.yapflib import style
 
 from yapftests import yapf_test_helper
@@ -31,10 +31,10 @@ class FormatDecisionStateTest(yapf_test_helper.YAPFTest):
     style.SetGlobalStyle(style.CreateYapfStyle())
 
   def testSimpleFunctionDefWithNoSplitting(self):
-    code = textwrap.dedent(r"""
-      def f(a, b):
-        pass
-      """)
+    code = textwrap.dedent("""\
+        def f(a, b):
+          pass
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     lline = logical_line.LogicalLine(0, _FilterLine(llines[0]))
     lline.CalculateFormattingInformation()
@@ -85,10 +85,10 @@ class FormatDecisionStateTest(yapf_test_helper.YAPFTest):
     self.assertEqual(repr(state), repr(clone))
 
   def testSimpleFunctionDefWithSplitting(self):
-    code = textwrap.dedent(r"""
-      def f(a, b):
-        pass
-      """)
+    code = textwrap.dedent("""\
+        def f(a, b):
+          pass
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     lline = logical_line.LogicalLine(0, _FilterLine(llines[0]))
     lline.CalculateFormattingInformation()
diff --git a/yapftests/format_token_test.py b/yapftests/format_token_test.py
index e324983..0db5680 100644
--- a/yapftests/format_token_test.py
+++ b/yapftests/format_token_test.py
@@ -15,13 +15,15 @@
 
 import unittest
 
-from lib2to3 import pytree
-from lib2to3.pgen2 import token
+from yapf_third_party._ylib2to3 import pytree
+from yapf_third_party._ylib2to3.pgen2 import token
 
 from yapf.yapflib import format_token
 
+from yapftests import yapf_test_helper
 
-class TabbedContinuationAlignPaddingTest(unittest.TestCase):
+
+class TabbedContinuationAlignPaddingTest(yapf_test_helper.YAPFTest):
 
   def testSpace(self):
     align_style = 'SPACE'
@@ -63,26 +65,30 @@ class TabbedContinuationAlignPaddingTest(unittest.TestCase):
     self.assertEqual(pad, '\t' * 2)
 
 
-class FormatTokenTest(unittest.TestCase):
+class FormatTokenTest(yapf_test_helper.YAPFTest):
 
   def testSimple(self):
-    tok = format_token.FormatToken(pytree.Leaf(token.STRING, "'hello world'"))
+    tok = format_token.FormatToken(
+        pytree.Leaf(token.STRING, "'hello world'"), 'STRING')
     self.assertEqual(
         "FormatToken(name=DOCSTRING, value='hello world', column=0, "
-        "lineno=0, splitpenalty=0)", str(tok))
+        'lineno=0, splitpenalty=0)', str(tok))
     self.assertTrue(tok.is_string)
 
-    tok = format_token.FormatToken(pytree.Leaf(token.COMMENT, '# A comment'))
+    tok = format_token.FormatToken(
+        pytree.Leaf(token.COMMENT, '# A comment'), 'COMMENT')
     self.assertEqual(
         'FormatToken(name=COMMENT, value=# A comment, column=0, '
         'lineno=0, splitpenalty=0)', str(tok))
     self.assertTrue(tok.is_comment)
 
   def testIsMultilineString(self):
-    tok = format_token.FormatToken(pytree.Leaf(token.STRING, '"""hello"""'))
+    tok = format_token.FormatToken(
+        pytree.Leaf(token.STRING, '"""hello"""'), 'STRING')
     self.assertTrue(tok.is_multiline_string)
 
-    tok = format_token.FormatToken(pytree.Leaf(token.STRING, 'r"""hello"""'))
+    tok = format_token.FormatToken(
+        pytree.Leaf(token.STRING, 'r"""hello"""'), 'STRING')
     self.assertTrue(tok.is_multiline_string)
 
 
diff --git a/yapftests/line_joiner_test.py b/yapftests/line_joiner_test.py
index 2eaf164..01dd479 100644
--- a/yapftests/line_joiner_test.py
+++ b/yapftests/line_joiner_test.py
@@ -39,42 +39,42 @@ class LineJoinerTest(yapf_test_helper.YAPFTest):
     self.assertCodeEqual(line_joiner.CanMergeMultipleLines(llines), join_lines)
 
   def testSimpleSingleLineStatement(self):
-    code = textwrap.dedent(u"""\
+    code = textwrap.dedent("""\
         if isinstance(a, int): continue
-        """)
+    """)
     self._CheckLineJoining(code, join_lines=True)
 
   def testSimpleMultipleLineStatement(self):
-    code = textwrap.dedent(u"""\
+    code = textwrap.dedent("""\
         if isinstance(b, int):
             continue
-        """)
+    """)
     self._CheckLineJoining(code, join_lines=False)
 
   def testSimpleMultipleLineComplexStatement(self):
-    code = textwrap.dedent(u"""\
+    code = textwrap.dedent("""\
         if isinstance(c, int):
             while True:
                 continue
-        """)
+    """)
     self._CheckLineJoining(code, join_lines=False)
 
   def testSimpleMultipleLineStatementWithComment(self):
-    code = textwrap.dedent(u"""\
+    code = textwrap.dedent("""\
         if isinstance(d, int): continue  # We're pleased that d's an int.
-        """)
+    """)
     self._CheckLineJoining(code, join_lines=True)
 
   def testSimpleMultipleLineStatementWithLargeIndent(self):
-    code = textwrap.dedent(u"""\
+    code = textwrap.dedent("""\
         if isinstance(e, int):    continue
-        """)
+    """)
     self._CheckLineJoining(code, join_lines=True)
 
   def testOverColumnLimit(self):
-    code = textwrap.dedent(u"""\
+    code = textwrap.dedent("""\
         if instance(bbbbbbbbbbbbbbbbbbbbbbbbb, int): cccccccccccccccccccccccccc = ddddddddddddddddddddd
-        """)  # noqa
+    """)  # noqa
     self._CheckLineJoining(code, join_lines=False)
 
 
diff --git a/yapftests/logical_line_test.py b/yapftests/logical_line_test.py
index 6876efe..2526b59 100644
--- a/yapftests/logical_line_test.py
+++ b/yapftests/logical_line_test.py
@@ -16,58 +16,55 @@
 import textwrap
 import unittest
 
-from lib2to3 import pytree
-from lib2to3.pgen2 import token
+from yapf_third_party._ylib2to3 import pytree
+from yapf_third_party._ylib2to3.pgen2 import token
 
+from yapf.pytree import split_penalty
 from yapf.yapflib import format_token
 from yapf.yapflib import logical_line
-from yapf.yapflib import split_penalty
 
 from yapftests import yapf_test_helper
 
 
-class LogicalLineBasicTest(unittest.TestCase):
+class LogicalLineBasicTest(yapf_test_helper.YAPFTest):
 
   def testConstruction(self):
-    toks = _MakeFormatTokenList([(token.DOT, '.'), (token.VBAR, '|')])
+    toks = _MakeFormatTokenList([(token.DOT, '.', 'DOT'),
+                                 (token.VBAR, '|', 'VBAR')])
     lline = logical_line.LogicalLine(20, toks)
     self.assertEqual(20, lline.depth)
     self.assertEqual(['DOT', 'VBAR'], [tok.name for tok in lline.tokens])
 
   def testFirstLast(self):
-    toks = _MakeFormatTokenList([(token.DOT, '.'), (token.LPAR, '('),
-                                 (token.VBAR, '|')])
+    toks = _MakeFormatTokenList([(token.DOT, '.', 'DOT'),
+                                 (token.LPAR, '(', 'LPAR'),
+                                 (token.VBAR, '|', 'VBAR')])
     lline = logical_line.LogicalLine(20, toks)
     self.assertEqual(20, lline.depth)
     self.assertEqual('DOT', lline.first.name)
     self.assertEqual('VBAR', lline.last.name)
 
   def testAsCode(self):
-    toks = _MakeFormatTokenList([(token.DOT, '.'), (token.LPAR, '('),
-                                 (token.VBAR, '|')])
+    toks = _MakeFormatTokenList([(token.DOT, '.', 'DOT'),
+                                 (token.LPAR, '(', 'LPAR'),
+                                 (token.VBAR, '|', 'VBAR')])
     lline = logical_line.LogicalLine(2, toks)
     self.assertEqual('    . ( |', lline.AsCode())
 
   def testAppendToken(self):
     lline = logical_line.LogicalLine(0)
-    lline.AppendToken(_MakeFormatTokenLeaf(token.LPAR, '('))
-    lline.AppendToken(_MakeFormatTokenLeaf(token.RPAR, ')'))
-    self.assertEqual(['LPAR', 'RPAR'], [tok.name for tok in lline.tokens])
-
-  def testAppendNode(self):
-    lline = logical_line.LogicalLine(0)
-    lline.AppendNode(pytree.Leaf(token.LPAR, '('))
-    lline.AppendNode(pytree.Leaf(token.RPAR, ')'))
+    lline.AppendToken(_MakeFormatTokenLeaf(token.LPAR, '(', 'LPAR'))
+    lline.AppendToken(_MakeFormatTokenLeaf(token.RPAR, ')', 'RPAR'))
     self.assertEqual(['LPAR', 'RPAR'], [tok.name for tok in lline.tokens])
 
 
 class LogicalLineFormattingInformationTest(yapf_test_helper.YAPFTest):
 
   def testFuncDef(self):
-    code = textwrap.dedent(r"""
+    code = textwrap.dedent("""\
         def f(a, b):
           pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
 
     f = llines[0].tokens[1]
@@ -81,14 +78,14 @@ class LogicalLineFormattingInformationTest(yapf_test_helper.YAPFTest):
     self.assertEqual(lparen.split_penalty, split_penalty.UNBREAKABLE)
 
 
-def _MakeFormatTokenLeaf(token_type, token_value):
-  return format_token.FormatToken(pytree.Leaf(token_type, token_value))
+def _MakeFormatTokenLeaf(token_type, token_value, name):
+  return format_token.FormatToken(pytree.Leaf(token_type, token_value), name)
 
 
 def _MakeFormatTokenList(token_type_values):
   return [
-      _MakeFormatTokenLeaf(token_type, token_value)
-      for token_type, token_value in token_type_values
+      _MakeFormatTokenLeaf(token_type, token_value, token_name)
+      for token_type, token_value, token_name in token_type_values
   ]
 
 
diff --git a/yapftests/main_test.py b/yapftests/main_test.py
index c83b8b6..b5d9b92 100644
--- a/yapftests/main_test.py
+++ b/yapftests/main_test.py
@@ -14,12 +14,12 @@
 # limitations under the License.
 """Tests for yapf.__init__.main."""
 
-from contextlib import contextmanager
 import sys
 import unittest
-import yapf
+from contextlib import contextmanager
+from io import StringIO
 
-from yapf.yapflib import py3compat
+import yapf
 
 from yapftests import yapf_test_helper
 
@@ -34,10 +34,10 @@ class IO(object):
   class Buffer(object):
 
     def __init__(self):
-      self.string_io = py3compat.StringIO()
+      self.string_io = StringIO()
 
     def write(self, s):
-      if py3compat.PY3 and isinstance(s, bytes):
+      if isinstance(s, bytes):
         s = str(s, 'utf-8')
       self.string_io.write(s)
 
@@ -78,11 +78,11 @@ def patched_input(code):
     return next(lines)
 
   try:
-    orig_raw_import = yapf.py3compat.raw_input
-    yapf.py3compat.raw_input = patch_raw_input
+    orig_raw_import = yapf._raw_input
+    yapf._raw_input = patch_raw_input
     yield
   finally:
-    yapf.py3compat.raw_input = orig_raw_import
+    yapf._raw_input = orig_raw_import
 
 
 class RunMainTest(yapf_test_helper.YAPFTest):
diff --git a/yapftests/pytree_unwrapper_test.py b/yapftests/pytree_unwrapper_test.py
index b6ab809..b297560 100644
--- a/yapftests/pytree_unwrapper_test.py
+++ b/yapftests/pytree_unwrapper_test.py
@@ -16,7 +16,7 @@
 import textwrap
 import unittest
 
-from yapf.yapflib import pytree_utils
+from yapf.pytree import pytree_utils
 
 from yapftests import yapf_test_helper
 
@@ -43,11 +43,11 @@ class PytreeUnwrapperTest(yapf_test_helper.YAPFTest):
     self.assertEqual(list_of_expected, actual)
 
   def testSimpleFileScope(self):
-    code = textwrap.dedent(r"""
-      x = 1
-      # a comment
-      y = 2
-      """)
+    code = textwrap.dedent("""\
+        x = 1
+        # a comment
+        y = 2
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self._CheckLogicalLines(llines, [
         (0, ['x', '=', '1']),
@@ -56,20 +56,20 @@ class PytreeUnwrapperTest(yapf_test_helper.YAPFTest):
     ])
 
   def testSimpleMultilineStatement(self):
-    code = textwrap.dedent(r"""
-      y = (1 +
-           x)
-      """)
+    code = textwrap.dedent("""\
+        y = (1 +
+             x)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self._CheckLogicalLines(llines, [
         (0, ['y', '=', '(', '1', '+', 'x', ')']),
     ])
 
   def testFileScopeWithInlineComment(self):
-    code = textwrap.dedent(r"""
-      x = 1    # a comment
-      y = 2
-      """)
+    code = textwrap.dedent("""\
+        x = 1    # a comment
+        y = 2
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self._CheckLogicalLines(llines, [
         (0, ['x', '=', '1', '# a comment']),
@@ -77,11 +77,11 @@ class PytreeUnwrapperTest(yapf_test_helper.YAPFTest):
     ])
 
   def testSimpleIf(self):
-    code = textwrap.dedent(r"""
-      if foo:
-          x = 1
-          y = 2
-      """)
+    code = textwrap.dedent("""\
+        if foo:
+            x = 1
+            y = 2
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self._CheckLogicalLines(llines, [
         (0, ['if', 'foo', ':']),
@@ -90,12 +90,12 @@ class PytreeUnwrapperTest(yapf_test_helper.YAPFTest):
     ])
 
   def testSimpleIfWithComments(self):
-    code = textwrap.dedent(r"""
-      # c1
-      if foo: # c2
-          x = 1
-          y = 2
-      """)
+    code = textwrap.dedent("""\
+        # c1
+        if foo: # c2
+            x = 1
+            y = 2
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self._CheckLogicalLines(llines, [
         (0, ['# c1']),
@@ -105,13 +105,13 @@ class PytreeUnwrapperTest(yapf_test_helper.YAPFTest):
     ])
 
   def testIfWithCommentsInside(self):
-    code = textwrap.dedent(r"""
-      if foo:
-          # c1
-          x = 1 # c2
-          # c3
-          y = 2
-      """)
+    code = textwrap.dedent("""\
+        if foo:
+            # c1
+            x = 1 # c2
+            # c3
+            y = 2
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self._CheckLogicalLines(llines, [
         (0, ['if', 'foo', ':']),
@@ -122,15 +122,15 @@ class PytreeUnwrapperTest(yapf_test_helper.YAPFTest):
     ])
 
   def testIfElifElse(self):
-    code = textwrap.dedent(r"""
-       if x:
-         x = 1 # c1
-       elif y: # c2
-         y = 1
-       else:
-         # c3
-         z = 1
-      """)
+    code = textwrap.dedent("""\
+        if x:
+          x = 1 # c1
+        elif y: # c2
+          y = 1
+        else:
+          # c3
+          z = 1
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self._CheckLogicalLines(llines, [
         (0, ['if', 'x', ':']),
@@ -143,14 +143,14 @@ class PytreeUnwrapperTest(yapf_test_helper.YAPFTest):
     ])
 
   def testNestedCompoundTwoLevel(self):
-    code = textwrap.dedent(r"""
-       if x:
-         x = 1 # c1
-         while t:
-           # c2
-           j = 1
-         k = 1
-      """)
+    code = textwrap.dedent("""\
+        if x:
+          x = 1 # c1
+          while t:
+            # c2
+            j = 1
+          k = 1
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self._CheckLogicalLines(llines, [
         (0, ['if', 'x', ':']),
@@ -162,11 +162,11 @@ class PytreeUnwrapperTest(yapf_test_helper.YAPFTest):
     ])
 
   def testSimpleWhile(self):
-    code = textwrap.dedent(r"""
-       while x > 1: # c1
-          # c2
-          x = 1
-      """)
+    code = textwrap.dedent("""\
+        while x > 1: # c1
+           # c2
+           x = 1
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self._CheckLogicalLines(llines, [
         (0, ['while', 'x', '>', '1', ':', '# c1']),
@@ -175,18 +175,18 @@ class PytreeUnwrapperTest(yapf_test_helper.YAPFTest):
     ])
 
   def testSimpleTry(self):
-    code = textwrap.dedent(r"""
-      try:
-        pass
-      except:
-        pass
-      except:
-        pass
-      else:
-        pass
-      finally:
-        pass
-      """)
+    code = textwrap.dedent("""\
+        try:
+          pass
+        except:
+          pass
+        except:
+          pass
+        else:
+          pass
+        finally:
+          pass
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self._CheckLogicalLines(llines, [
         (0, ['try', ':']),
@@ -202,11 +202,11 @@ class PytreeUnwrapperTest(yapf_test_helper.YAPFTest):
     ])
 
   def testSimpleFuncdef(self):
-    code = textwrap.dedent(r"""
-      def foo(x): # c1
-        # c2
-        return x
-      """)
+    code = textwrap.dedent("""\
+        def foo(x): # c1
+          # c2
+          return x
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self._CheckLogicalLines(llines, [
         (0, ['def', 'foo', '(', 'x', ')', ':', '# c1']),
@@ -215,15 +215,15 @@ class PytreeUnwrapperTest(yapf_test_helper.YAPFTest):
     ])
 
   def testTwoFuncDefs(self):
-    code = textwrap.dedent(r"""
-      def foo(x): # c1
-        # c2
-        return x
-
-      def bar(): # c3
-        # c4
-        return x
-      """)
+    code = textwrap.dedent("""\
+        def foo(x): # c1
+          # c2
+          return x
+
+        def bar(): # c3
+          # c4
+          return x
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self._CheckLogicalLines(llines, [
         (0, ['def', 'foo', '(', 'x', ')', ':', '# c1']),
@@ -235,11 +235,11 @@ class PytreeUnwrapperTest(yapf_test_helper.YAPFTest):
     ])
 
   def testSimpleClassDef(self):
-    code = textwrap.dedent(r"""
-      class Klass: # c1
-        # c2
-        p = 1
-      """)
+    code = textwrap.dedent("""\
+        class Klass: # c1
+          # c2
+          p = 1
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self._CheckLogicalLines(llines, [
         (0, ['class', 'Klass', ':', '# c1']),
@@ -248,9 +248,9 @@ class PytreeUnwrapperTest(yapf_test_helper.YAPFTest):
     ])
 
   def testSingleLineStmtInFunc(self):
-    code = textwrap.dedent(r"""
+    code = textwrap.dedent("""\
         def f(): return 37
-      """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self._CheckLogicalLines(llines, [
         (0, ['def', 'f', '(', ')', ':']),
@@ -258,13 +258,13 @@ class PytreeUnwrapperTest(yapf_test_helper.YAPFTest):
     ])
 
   def testMultipleComments(self):
-    code = textwrap.dedent(r"""
+    code = textwrap.dedent("""\
         # Comment #1
 
         # Comment #2
         def f():
           pass
-      """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self._CheckLogicalLines(llines, [
         (0, ['# Comment #1']),
@@ -274,13 +274,13 @@ class PytreeUnwrapperTest(yapf_test_helper.YAPFTest):
     ])
 
   def testSplitListWithComment(self):
-    code = textwrap.dedent(r"""
-      a = [
-          'a',
-          'b',
-          'c',  # hello world
-      ]
-      """)
+    code = textwrap.dedent("""\
+        a = [
+            'a',
+            'b',
+            'c',  # hello world
+        ]
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self._CheckLogicalLines(llines, [(0, [
         'a', '=', '[', "'a'", ',', "'b'", ',', "'c'", ',', '# hello world', ']'
@@ -320,7 +320,7 @@ class MatchBracketsTest(yapf_test_helper.YAPFTest):
     code = textwrap.dedent("""\
         def foo(a, b=['w','d'], c=[42, 37]):
           pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self._CheckMatchingBrackets(llines, [
         [(2, 20), (7, 11), (15, 19)],
@@ -332,7 +332,7 @@ class MatchBracketsTest(yapf_test_helper.YAPFTest):
         @bar()
         def foo(a, b, c):
           pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self._CheckMatchingBrackets(llines, [
         [(2, 3)],
@@ -344,7 +344,7 @@ class MatchBracketsTest(yapf_test_helper.YAPFTest):
     code = textwrap.dedent("""\
         class A(B, C, D):
           pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self._CheckMatchingBrackets(llines, [
         [(2, 8)],
diff --git a/yapftests/pytree_utils_test.py b/yapftests/pytree_utils_test.py
index 3b9fde7..fe31eb8 100644
--- a/yapftests/pytree_utils_test.py
+++ b/yapftests/pytree_utils_test.py
@@ -15,11 +15,13 @@
 
 import unittest
 
-from lib2to3 import pygram
-from lib2to3 import pytree
-from lib2to3.pgen2 import token
+from yapf_third_party._ylib2to3 import pygram
+from yapf_third_party._ylib2to3 import pytree
+from yapf_third_party._ylib2to3.pgen2 import token
 
-from yapf.yapflib import pytree_utils
+from yapf.pytree import pytree_utils
+
+from yapftests import yapf_test_helper
 
 # More direct access to the symbol->number mapping living within the grammar
 # module.
@@ -33,7 +35,7 @@ _FOO4 = 'foo4'
 _FOO5 = 'foo5'
 
 
-class NodeNameTest(unittest.TestCase):
+class NodeNameTest(yapf_test_helper.YAPFTest):
 
   def testNodeNameForLeaf(self):
     leaf = pytree.Leaf(token.LPAR, '(')
@@ -45,7 +47,7 @@ class NodeNameTest(unittest.TestCase):
     self.assertEqual('suite', pytree_utils.NodeName(node))
 
 
-class ParseCodeToTreeTest(unittest.TestCase):
+class ParseCodeToTreeTest(yapf_test_helper.YAPFTest):
 
   def testParseCodeToTree(self):
     # Since ParseCodeToTree is a thin wrapper around underlying lib2to3
@@ -63,19 +65,15 @@ class ParseCodeToTreeTest(unittest.TestCase):
     self.assertEqual('simple_stmt', pytree_utils.NodeName(tree.children[0]))
 
   def testPrintStatementToTree(self):
-    tree = pytree_utils.ParseCodeToTree('print "hello world"\n')
-    self.assertEqual('file_input', pytree_utils.NodeName(tree))
-    self.assertEqual(2, len(tree.children))
-    self.assertEqual('simple_stmt', pytree_utils.NodeName(tree.children[0]))
+    with self.assertRaises(SyntaxError):
+      pytree_utils.ParseCodeToTree('print "hello world"\n')
 
   def testClassNotLocal(self):
-    tree = pytree_utils.ParseCodeToTree('class nonlocal: pass\n')
-    self.assertEqual('file_input', pytree_utils.NodeName(tree))
-    self.assertEqual(2, len(tree.children))
-    self.assertEqual('classdef', pytree_utils.NodeName(tree.children[0]))
+    with self.assertRaises(SyntaxError):
+      pytree_utils.ParseCodeToTree('class nonlocal: pass\n')
 
 
-class InsertNodesBeforeAfterTest(unittest.TestCase):
+class InsertNodesBeforeAfterTest(yapf_test_helper.YAPFTest):
 
   def _BuildSimpleTree(self):
     # Builds a simple tree we can play with in the tests.
@@ -147,7 +145,7 @@ class InsertNodesBeforeAfterTest(unittest.TestCase):
                                     self._simple_tree.children[0])
 
 
-class AnnotationsTest(unittest.TestCase):
+class AnnotationsTest(yapf_test_helper.YAPFTest):
 
   def setUp(self):
     self._leaf = pytree.Leaf(token.LPAR, '(')
diff --git a/yapftests/pytree_visitor_test.py b/yapftests/pytree_visitor_test.py
index 1908249..1d908d4 100644
--- a/yapftests/pytree_visitor_test.py
+++ b/yapftests/pytree_visitor_test.py
@@ -14,10 +14,12 @@
 """Tests for yapf.pytree_visitor."""
 
 import unittest
+from io import StringIO
 
-from yapf.yapflib import py3compat
-from yapf.yapflib import pytree_utils
-from yapf.yapflib import pytree_visitor
+from yapf.pytree import pytree_utils
+from yapf.pytree import pytree_visitor
+
+from yapftests import yapf_test_helper
 
 
 class _NodeNameCollector(pytree_visitor.PyTreeVisitor):
@@ -46,19 +48,19 @@ class _NodeNameCollector(pytree_visitor.PyTreeVisitor):
     self.DefaultLeafVisit(leaf)
 
 
-_VISITOR_TEST_SIMPLE_CODE = r"""
+_VISITOR_TEST_SIMPLE_CODE = """\
 foo = bar
 baz = x
 """
 
-_VISITOR_TEST_NESTED_CODE = r"""
+_VISITOR_TEST_NESTED_CODE = """\
 if x:
   if y:
     return z
 """
 
 
-class PytreeVisitorTest(unittest.TestCase):
+class PytreeVisitorTest(yapf_test_helper.YAPFTest):
 
   def testCollectAllNodeNamesSimpleCode(self):
     tree = pytree_utils.ParseCodeToTree(_VISITOR_TEST_SIMPLE_CODE)
@@ -96,7 +98,7 @@ class PytreeVisitorTest(unittest.TestCase):
     # PyTreeDumper is mainly a debugging utility, so only do basic sanity
     # checking.
     tree = pytree_utils.ParseCodeToTree(_VISITOR_TEST_SIMPLE_CODE)
-    stream = py3compat.StringIO()
+    stream = StringIO()
     pytree_visitor.PyTreeDumper(target_stream=stream).Visit(tree)
 
     dump_output = stream.getvalue()
@@ -107,7 +109,7 @@ class PytreeVisitorTest(unittest.TestCase):
   def testDumpPyTree(self):
     # Similar sanity checking for the convenience wrapper DumpPyTree
     tree = pytree_utils.ParseCodeToTree(_VISITOR_TEST_SIMPLE_CODE)
-    stream = py3compat.StringIO()
+    stream = StringIO()
     pytree_visitor.DumpPyTree(tree, target_stream=stream)
 
     dump_output = stream.getvalue()
diff --git a/yapftests/reformatter_basic_test.py b/yapftests/reformatter_basic_test.py
index 5037f11..74b1ba4 100644
--- a/yapftests/reformatter_basic_test.py
+++ b/yapftests/reformatter_basic_test.py
@@ -13,10 +13,10 @@
 # limitations under the License.
 """Basic tests for yapf.reformatter."""
 
+import sys
 import textwrap
 import unittest
 
-from yapf.yapflib import py3compat
 from yapf.yapflib import reformatter
 from yapf.yapflib import style
 
@@ -34,193 +34,285 @@ class BasicReformatterTest(yapf_test_helper.YAPFTest):
         style.CreateStyleFromConfig(
             '{split_all_comma_separated_values: true, column_limit: 40}'))
     unformatted_code = textwrap.dedent("""\
-          responseDict = {"timestamp": timestamp, "someValue":   value, "whatever": 120}
-          """)  # noqa
+        responseDict = {"timestamp": timestamp, "someValue":   value, "whatever": 120}
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
-          responseDict = {
-              "timestamp": timestamp,
-              "someValue": value,
-              "whatever": 120
-          }
-          """)
+        responseDict = {
+            "timestamp": timestamp,
+            "someValue": value,
+            "whatever": 120
+        }
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
     unformatted_code = textwrap.dedent("""\
-          yes = { 'yes': 'no', 'no': 'yes', }
-          """)
+        yes = { 'yes': 'no', 'no': 'yes', }
+    """)
     expected_formatted_code = textwrap.dedent("""\
-          yes = {
-              'yes': 'no',
-              'no': 'yes',
-          }
-          """)
+        yes = {
+            'yes': 'no',
+            'no': 'yes',
+        }
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
     unformatted_code = textwrap.dedent("""\
-          def foo(long_arg, really_long_arg, really_really_long_arg, cant_keep_all_these_args):
-                pass
-          """)  # noqa
-    expected_formatted_code = textwrap.dedent("""\
-          def foo(long_arg,
-                  really_long_arg,
-                  really_really_long_arg,
-                  cant_keep_all_these_args):
+        def foo(long_arg, really_long_arg, really_really_long_arg, cant_keep_all_these_args):
             pass
-          """)
+    """)  # noqa
+    expected_formatted_code = textwrap.dedent("""\
+        def foo(long_arg,
+                really_long_arg,
+                really_really_long_arg,
+                cant_keep_all_these_args):
+          pass
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
     unformatted_code = textwrap.dedent("""\
-          foo_tuple = [long_arg, really_long_arg, really_really_long_arg, cant_keep_all_these_args]
-          """)  # noqa
+        foo_tuple = [long_arg, really_long_arg, really_really_long_arg, cant_keep_all_these_args]
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
-          foo_tuple = [
-              long_arg,
-              really_long_arg,
-              really_really_long_arg,
-              cant_keep_all_these_args
-          ]
-          """)
+        foo_tuple = [
+            long_arg,
+            really_long_arg,
+            really_really_long_arg,
+            cant_keep_all_these_args
+        ]
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
     unformatted_code = textwrap.dedent("""\
-          foo_tuple = [short, arg]
-          """)
+        foo_tuple = [short, arg]
+    """)
     expected_formatted_code = textwrap.dedent("""\
-          foo_tuple = [short, arg]
-          """)
+        foo_tuple = [short, arg]
+    """)
+    llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
+    self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
+    unformatted_code = textwrap.dedent("""\
+        values = [ lambda arg1, arg2: arg1 + arg2 ]
+    """)  # noqa
+    expected_formatted_code = textwrap.dedent("""\
+        values = [
+            lambda arg1, arg2: arg1 + arg2
+        ]
+    """)
+    llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
+    self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
+    unformatted_code = textwrap.dedent("""\
+        values = [
+            (some_arg1, some_arg2) for some_arg1, some_arg2 in values
+        ]
+    """)  # noqa
+    expected_formatted_code = textwrap.dedent("""\
+        values = [
+            (some_arg1,
+             some_arg2)
+            for some_arg1, some_arg2 in values
+        ]
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
     # There is a test for split_all_top_level_comma_separated_values, with
     # different expected value
     unformatted_code = textwrap.dedent("""\
-          someLongFunction(this_is_a_very_long_parameter,
-              abc=(a, this_will_just_fit_xxxxxxx))
-          """)
+        someLongFunction(this_is_a_very_long_parameter,
+            abc=(a, this_will_just_fit_xxxxxxx))
+    """)
     expected_formatted_code = textwrap.dedent("""\
-          someLongFunction(
-              this_is_a_very_long_parameter,
-              abc=(a,
-                   this_will_just_fit_xxxxxxx))
-          """)
+        someLongFunction(
+            this_is_a_very_long_parameter,
+            abc=(a,
+                 this_will_just_fit_xxxxxxx))
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testSplittingTopLevelAllArgs(self):
-    style.SetGlobalStyle(
-        style.CreateStyleFromConfig(
-            '{split_all_top_level_comma_separated_values: true, '
-            'column_limit: 40}'))
+    style_dict = style.CreateStyleFromConfig(
+        '{split_all_top_level_comma_separated_values: true, '
+        'column_limit: 40}')
+    style.SetGlobalStyle(style_dict)
     # Works the same way as split_all_comma_separated_values
     unformatted_code = textwrap.dedent("""\
-          responseDict = {"timestamp": timestamp, "someValue":   value, "whatever": 120}
-          """)  # noqa
+        responseDict = {"timestamp": timestamp, "someValue":   value, "whatever": 120}
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
-          responseDict = {
-              "timestamp": timestamp,
-              "someValue": value,
-              "whatever": 120
-          }
-          """)
+        responseDict = {
+            "timestamp": timestamp,
+            "someValue": value,
+            "whatever": 120
+        }
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
     # Works the same way as split_all_comma_separated_values
     unformatted_code = textwrap.dedent("""\
-          def foo(long_arg, really_long_arg, really_really_long_arg, cant_keep_all_these_args):
-                pass
-          """)  # noqa
+        def foo(long_arg, really_long_arg, really_really_long_arg, cant_keep_all_these_args):
+              pass
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
-          def foo(long_arg,
-                  really_long_arg,
-                  really_really_long_arg,
-                  cant_keep_all_these_args):
-            pass
-          """)
+        def foo(long_arg,
+                really_long_arg,
+                really_really_long_arg,
+                cant_keep_all_these_args):
+          pass
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
     # Works the same way as split_all_comma_separated_values
     unformatted_code = textwrap.dedent("""\
-          foo_tuple = [long_arg, really_long_arg, really_really_long_arg, cant_keep_all_these_args]
-          """)  # noqa
+        foo_tuple = [long_arg, really_long_arg, really_really_long_arg, cant_keep_all_these_args]
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
-          foo_tuple = [
-              long_arg,
-              really_long_arg,
-              really_really_long_arg,
-              cant_keep_all_these_args
-          ]
-          """)
+        foo_tuple = [
+            long_arg,
+            really_long_arg,
+            really_really_long_arg,
+            cant_keep_all_these_args
+        ]
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
     # Works the same way as split_all_comma_separated_values
     unformatted_code = textwrap.dedent("""\
-          foo_tuple = [short, arg]
-          """)
+        foo_tuple = [short, arg]
+    """)
     expected_formatted_code = textwrap.dedent("""\
-          foo_tuple = [short, arg]
-          """)
+        foo_tuple = [short, arg]
+    """)
+    llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
+    self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
+    # Works the same way as split_all_comma_separated_values
+    unformatted_code = textwrap.dedent("""\
+        values = [ lambda arg1, arg2: arg1 + arg2 ]
+    """)  # noqa
+    expected_formatted_code = textwrap.dedent("""\
+        values = [
+            lambda arg1, arg2: arg1 + arg2
+        ]
+    """)
+    llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
+    self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
+    # There is a test for split_all_comma_separated_values, with different
+    # expected value
+    unformatted_code = textwrap.dedent("""\
+        values = [
+            (some_arg1, some_arg2) for some_arg1, some_arg2 in values
+        ]
+    """)  # noqa
+    expected_formatted_code = textwrap.dedent("""\
+        values = [
+            (some_arg1, some_arg2)
+            for some_arg1, some_arg2 in values
+        ]
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
     # There is a test for split_all_comma_separated_values, with different
     # expected value
+    unformatted_code = textwrap.dedent("""\
+        someLongFunction(this_is_a_very_long_parameter,
+            abc=(a, this_will_just_fit_xxxxxxx))
+    """)
+    expected_formatted_code = textwrap.dedent("""\
+        someLongFunction(
+            this_is_a_very_long_parameter,
+            abc=(a, this_will_just_fit_xxxxxxx))
+    """)
+    llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
+    actual_formatted_code = reformatter.Reformat(llines)
+    self.assertEqual(40, len(actual_formatted_code.splitlines()[-1]))
+    self.assertCodeEqual(expected_formatted_code, actual_formatted_code)
+
+    unformatted_code = textwrap.dedent("""\
+        someLongFunction(this_is_a_very_long_parameter,
+            abc=(a, this_will_not_fit_xxxxxxxxx))
+    """)
+    expected_formatted_code = textwrap.dedent("""\
+        someLongFunction(
+            this_is_a_very_long_parameter,
+            abc=(a,
+                 this_will_not_fit_xxxxxxxxx))
+    """)
+    llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
+    self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
+
+    # This tests when there is an embedded dictionary that will fit in a line
+    original_multiline = style_dict['FORCE_MULTILINE_DICT']
+    style_dict['FORCE_MULTILINE_DICT'] = False
+    style.SetGlobalStyle(style_dict)
     unformatted_code = textwrap.dedent("""\
           someLongFunction(this_is_a_very_long_parameter,
-              abc=(a, this_will_just_fit_xxxxxxx))
+              abc={a: b, b: c})
           """)
     expected_formatted_code = textwrap.dedent("""\
           someLongFunction(
               this_is_a_very_long_parameter,
-              abc=(a, this_will_just_fit_xxxxxxx))
+              abc={
+                  a: b, b: c
+              })
           """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     actual_formatted_code = reformatter.Reformat(llines)
-    self.assertEqual(40, len(actual_formatted_code.splitlines()[-1]))
     self.assertCodeEqual(expected_formatted_code, actual_formatted_code)
 
+    # This tests when there is an embedded dictionary that will fit in a line,
+    #  but FORCE_MULTILINE_DICT is set
+    style_dict['FORCE_MULTILINE_DICT'] = True
+    style.SetGlobalStyle(style_dict)
     unformatted_code = textwrap.dedent("""\
           someLongFunction(this_is_a_very_long_parameter,
-              abc=(a, this_will_not_fit_xxxxxxxxx))
+              abc={a: b, b: c})
           """)
     expected_formatted_code = textwrap.dedent("""\
           someLongFunction(
               this_is_a_very_long_parameter,
-              abc=(a,
-                   this_will_not_fit_xxxxxxxxx))
+              abc={
+                  a: b,
+                  b: c
+              })
           """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
-    self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
+    actual_formatted_code = reformatter.Reformat(llines)
+    self.assertCodeEqual(expected_formatted_code, actual_formatted_code)
+
+    style_dict['FORCE_MULTILINE_DICT'] = original_multiline
+    style.SetGlobalStyle(style_dict)
 
     # Exercise the case where there's no opening bracket (for a, b)
     unformatted_code = textwrap.dedent("""\
-          a, b = f(
-              a_very_long_parameter, yet_another_one, and_another)
-          """)
+        a, b = f(
+            a_very_long_parameter, yet_another_one, and_another)
+    """)
     expected_formatted_code = textwrap.dedent("""\
-          a, b = f(
-              a_very_long_parameter, yet_another_one, and_another)
-          """)
+        a, b = f(
+            a_very_long_parameter, yet_another_one, and_another)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
     # Don't require splitting before comments.
     unformatted_code = textwrap.dedent("""\
-          KO = {
-              'ABC': Abc, # abc
-              'DEF': Def, # def
-              'LOL': Lol, # wtf
-              'GHI': Ghi,
-              'JKL': Jkl,
-          }
-          """)
+        KO = {
+            'ABC': Abc, # abc
+            'DEF': Def, # def
+            'LOL': Lol, # wtf
+            'GHI': Ghi,
+            'JKL': Jkl,
+        }
+    """)
     expected_formatted_code = textwrap.dedent("""\
-          KO = {
-              'ABC': Abc,  # abc
-              'DEF': Def,  # def
-              'LOL': Lol,  # wtf
-              'GHI': Ghi,
-              'JKL': Jkl,
-          }
-          """)
+        KO = {
+            'ABC': Abc,  # abc
+            'DEF': Def,  # def
+            'LOL': Lol,  # wtf
+            'GHI': Ghi,
+            'JKL': Jkl,
+        }
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -236,7 +328,7 @@ class BasicReformatterTest(yapf_test_helper.YAPFTest):
           if (xxxxxxxxxxxx.yyyyyyyy(zzzzzzzzzzzzz[0]) == 'aaaaaaaaaaa' and
               xxxxxxxxxxxx.yyyyyyyy(zzzzzzzzzzzzz[0].mmmmmmmm[0]) == 'bbbbbbb'):
             pass
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         def g():  # Trailing comment
           if (xxxxxxxxxxxx.yyyyyyyy(zzzzzzzzzzzzz[0]) == 'aaaaaaaaaaa' and
@@ -249,20 +341,43 @@ class BasicReformatterTest(yapf_test_helper.YAPFTest):
           if (xxxxxxxxxxxx.yyyyyyyy(zzzzzzzzzzzzz[0]) == 'aaaaaaaaaaa' and
               xxxxxxxxxxxx.yyyyyyyy(zzzzzzzzzzzzz[0].mmmmmmmm[0]) == 'bbbbbbb'):
             pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
+  def testParamListWithTrailingComments(self):
+    unformatted_code = textwrap.dedent("""\
+        def f(a,
+              b, #
+              c):
+          pass
+    """)
+    expected_formatted_code = textwrap.dedent("""\
+        def f(a, b,  #
+              c):
+          pass
+    """)
+    try:
+      style.SetGlobalStyle(
+          style.CreateStyleFromConfig(
+              '{based_on_style: yapf,'
+              ' disable_split_list_with_comment: True}'))
+      llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
+      self.assertCodeEqual(expected_formatted_code,
+                           reformatter.Reformat(llines))
+    finally:
+      style.SetGlobalStyle(style.CreateYapfStyle())
+
   def testBlankLinesBetweenTopLevelImportsAndVariables(self):
     unformatted_code = textwrap.dedent("""\
         import foo as bar
         VAR = 'baz'
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         import foo as bar
 
         VAR = 'baz'
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -270,13 +385,13 @@ class BasicReformatterTest(yapf_test_helper.YAPFTest):
         import foo as bar
 
         VAR = 'baz'
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         import foo as bar
 
 
         VAR = 'baz'
-        """)
+    """)
     try:
       style.SetGlobalStyle(
           style.CreateStyleFromConfig(
@@ -291,11 +406,11 @@ class BasicReformatterTest(yapf_test_helper.YAPFTest):
     unformatted_code = textwrap.dedent("""\
         import foo as bar
         # Some comment
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         import foo as bar
         # Some comment
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -303,14 +418,14 @@ class BasicReformatterTest(yapf_test_helper.YAPFTest):
         import foo as bar
         class Baz():
           pass
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         import foo as bar
 
 
         class Baz():
           pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -318,14 +433,14 @@ class BasicReformatterTest(yapf_test_helper.YAPFTest):
         import foo as bar
         def foobar():
           pass
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         import foo as bar
 
 
         def foobar():
           pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -333,12 +448,12 @@ class BasicReformatterTest(yapf_test_helper.YAPFTest):
         def foobar():
           from foo import Bar
           Bar.baz()
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         def foobar():
           from foo import Bar
           Bar.baz()
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -349,11 +464,11 @@ class BasicReformatterTest(yapf_test_helper.YAPFTest):
 
 
 
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         def foobar():  # foo
           pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -362,10 +477,10 @@ class BasicReformatterTest(yapf_test_helper.YAPFTest):
 
         'c':927}
 
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         x = {'a': 37, 'b': 42, 'c': 927}
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -387,7 +502,7 @@ class BasicReformatterTest(yapf_test_helper.YAPFTest):
         def bar():
 
           return 0
-        """)
+    """)
     expected_formatted_code = """\
 class foo(object):\n  \n  def foobar(self):\n    \n    pass\n  \n  def barfoo(self, x, y):  # bar\n    \n    if x:\n      \n      return y\n\n\ndef bar():\n  \n  return 0
 """  # noqa
@@ -424,7 +539,7 @@ class foo(object):\n  \n  def foobar(self):\n    \n    pass\n  \n  def barfoo(se
               return y
         def f  (   a ) :
           return      37+-+a[42-x :  y**3]
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         x = {'a': 37, 'b': 42, 'c': 927}
 
@@ -444,7 +559,7 @@ class foo(object):\n  \n  def foobar(self):\n    \n    pass\n  \n  def barfoo(se
 
         def f(a):
           return 37 + -+a[42 - x:y**3]
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -470,7 +585,7 @@ class foo(object):\n  \n  def foobar(self):\n    \n    pass\n  \n  def barfoo(se
 
         class Qux(object):
           pass
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         class Foo(object):
           pass
@@ -497,14 +612,14 @@ class foo(object):\n  \n  def foobar(self):\n    \n    pass\n  \n  def barfoo(se
 
         class Qux(object):
           pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testSingleComment(self):
     code = textwrap.dedent("""\
         # Thing 1
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -514,7 +629,7 @@ class foo(object):\n  \n  def foobar(self):\n    \n    pass\n  \n  def barfoo(se
     expected_formatted_code = textwrap.dedent("""\
         # Thing 1
         # Thing 2
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -531,7 +646,7 @@ class foo(object):\n  \n  def foobar(self):\n    \n    pass\n  \n  def barfoo(se
 
               # Ending comment.
           })
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -540,7 +655,7 @@ class foo(object):\n  \n  def foobar(self):\n    \n    pass\n  \n  def barfoo(se
         import foo as bar
         # Thing 1
         # Thing 2
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -561,7 +676,7 @@ class foo(object):\n  \n  def foobar(self):\n    \n    pass\n  \n  def barfoo(se
             """
             print('hello {}'.format('world'))
             return 42
-        ''')
+    ''')
     expected_formatted_code = textwrap.dedent('''\
         u"""Module-level docstring."""
         import os
@@ -578,7 +693,7 @@ class foo(object):\n  \n  def foobar(self):\n    \n    pass\n  \n  def barfoo(se
             """
             print('hello {}'.format('world'))
             return 42
-        ''')
+    ''')
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -596,7 +711,7 @@ class foo(object):\n  \n  def foobar(self):\n    \n    pass\n  \n  def barfoo(se
             # Another multiline
             # comment
             pass
-        ''')
+    ''')
     expected_formatted_code = textwrap.dedent('''\
         """Hello world"""
 
@@ -613,7 +728,7 @@ class foo(object):\n  \n  def foobar(self):\n    \n    pass\n  \n  def barfoo(se
             # Another multiline
             # comment
             pass
-        ''')
+    ''')
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -640,7 +755,7 @@ class foo(object):\n  \n  def foobar(self):\n    \n    pass\n  \n  def barfoo(se
             # Another multiline
             # comment
             pass
-        ''')
+    ''')
     expected_formatted_code = textwrap.dedent('''\
         """Hello world
 
@@ -666,17 +781,17 @@ class foo(object):\n  \n  def foobar(self):\n    \n    pass\n  \n  def barfoo(se
             # Another multiline
             # comment
             pass
-        ''')
+    ''')
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testTupleCommaBeforeLastParen(self):
     unformatted_code = textwrap.dedent("""\
         a = ( 1, )
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         a = (1,)
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -692,7 +807,7 @@ class foo(object):\n  \n  def foobar(self):\n    \n    pass\n  \n  def barfoo(se
         def f():
           assert port >= minimum, 'Unexpected port %d when minimum was %d.' % (port,
                                                                                minimum)
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -704,7 +819,7 @@ class foo(object):\n  \n  def foobar(self):\n    \n    pass\n  \n  def barfoo(se
           @baz()
           def x(self):
             pass
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         @foo()
         class A(object):
@@ -713,7 +828,7 @@ class foo(object):\n  \n  def foobar(self):\n    \n    pass\n  \n  def barfoo(se
           @baz()
           def x(self):
             pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -724,14 +839,14 @@ class foo(object):\n  \n  def foobar(self):\n    \n    pass\n  \n  def barfoo(se
         @bar
         def x  (self):
             pass
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         @foo()
         # frob
         @bar
         def x(self):
           pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -740,11 +855,11 @@ class foo(object):\n  \n  def foobar(self):\n    \n    pass\n  \n  def barfoo(se
         def given(y):
             [k for k in ()
               if k in y]
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         def given(y):
           [k for k in () if k in y]
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -755,13 +870,13 @@ class foo(object):\n  \n  def foobar(self):\n    \n    pass\n  \n  def barfoo(se
                 long_var_name + 1
                 for long_var_name in ()
                 if long_var_name == 2]
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         def given(y):
           long_variable_name = [
               long_var_name + 1 for long_var_name in () if long_var_name == 2
           ]
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -770,12 +885,12 @@ class foo(object):\n  \n  def foobar(self):\n    \n    pass\n  \n  def barfoo(se
         def given(used_identifiers):
           return (sum(len(identifier)
                       for identifier in used_identifiers) / len(used_identifiers))
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         def given(used_identifiers):
           return (sum(len(identifier) for identifier in used_identifiers) /
                   len(used_identifiers))
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -786,7 +901,7 @@ class foo(object):\n  \n  def foobar(self):\n    \n    pass\n  \n  def barfoo(se
                 long_var_name + 1
                 for long_var_name, number_two in ()
                 if long_var_name == 2 and number_two == 3]
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         def given(y):
           long_variable_name = [
@@ -794,7 +909,7 @@ class foo(object):\n  \n  def foobar(self):\n    \n    pass\n  \n  def barfoo(se
               for long_var_name, number_two in ()
               if long_var_name == 2 and number_two == 3
           ]
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -805,43 +920,43 @@ class foo(object):\n  \n  def foobar(self):\n    \n    pass\n  \n  def barfoo(se
                 long_var_name
                 for long_var_name, number_two in ()
                 if long_var_name == 2 and number_two == 3]
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         def given(y):
           long_variable_name = [
               long_var_name for long_var_name, number_two in ()
               if long_var_name == 2 and number_two == 3
           ]
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testOpeningAndClosingBrackets(self):
-    unformatted_code = """\
-foo( (1, ) )
-foo( ( 1, 2, 3  ) )
-foo( ( 1, 2, 3, ) )
-"""
-    expected_formatted_code = """\
-foo((1,))
-foo((1, 2, 3))
-foo((
-    1,
-    2,
-    3,
-))
-"""
+    unformatted_code = textwrap.dedent("""\
+        foo( (1, ) )
+        foo( ( 1, 2, 3  ) )
+        foo( ( 1, 2, 3, ) )
+    """)
+    expected_formatted_code = textwrap.dedent("""\
+        foo((1,))
+        foo((1, 2, 3))
+        foo((
+            1,
+            2,
+            3,
+        ))
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testSingleLineFunctions(self):
     unformatted_code = textwrap.dedent("""\
         def foo():  return 42
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         def foo():
           return 42
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -849,23 +964,23 @@ foo((
     # If the queue isn't properly constructed, then a token in the middle of the
     # line may be selected as the one with least penalty. The tokens after that
     # one are then splatted at the end of the line with no formatting.
-    unformatted_code = """\
-find_symbol(node.type) + "< " + " ".join(find_pattern(n) for n in node.child) + " >"
-"""  # noqa
-    expected_formatted_code = """\
-find_symbol(node.type) + "< " + " ".join(
-    find_pattern(n) for n in node.child) + " >"
-"""
+    unformatted_code = textwrap.dedent("""\
+        find_symbol(node.type) + "< " + " ".join(find_pattern(n) for n in node.child) + " >"
+    """)  # noqa
+    expected_formatted_code = textwrap.dedent("""\
+        find_symbol(node.type) + "< " + " ".join(
+            find_pattern(n) for n in node.child) + " >"
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testNoSpacesBetweenSubscriptsAndCalls(self):
     unformatted_code = textwrap.dedent("""\
         aaaaaaaaaa = bbbbbbbb.ccccccccc() [42] (a, 2)
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         aaaaaaaaaa = bbbbbbbb.ccccccccc()[42](a, 2)
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -873,10 +988,10 @@ find_symbol(node.type) + "< " + " ".join(
     # Unary operator.
     unformatted_code = textwrap.dedent("""\
         aaaaaaaaaa = bbbbbbbb.ccccccccc[ -1 ]( -42 )
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         aaaaaaaaaa = bbbbbbbb.ccccccccc[-1](-42)
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -884,11 +999,11 @@ find_symbol(node.type) + "< " + " ".join(
     unformatted_code = textwrap.dedent("""\
         aaaaaaaaaa = bbbbbbbb.ccccccccc( *varargs )
         aaaaaaaaaa = bbbbbbbb.ccccccccc( **kwargs )
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         aaaaaaaaaa = bbbbbbbb.ccccccccc(*varargs)
         aaaaaaaaaa = bbbbbbbb.ccccccccc(**kwargs)
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -898,13 +1013,13 @@ find_symbol(node.type) + "< " + " ".join(
             # This is a multiline
             # comment.
             pass
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         if True:
           # This is a multiline
           # comment.
           pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -916,7 +1031,7 @@ find_symbol(node.type) + "< " + " ".join(
             'yield_stmt': 'import_stmt', lambda: 'global_stmt': 'exec_stmt', 'assert_stmt':
             'if_stmt', 'while_stmt': 'for_stmt',
         })
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         _PYTHON_STATEMENTS = frozenset({
             lambda x, y: 'simple_stmt': 'small_stmt',
@@ -929,7 +1044,7 @@ find_symbol(node.type) + "< " + " ".join(
             'assert_stmt': 'if_stmt',
             'while_stmt': 'for_stmt',
         })
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -947,7 +1062,7 @@ xxxxxxxxxxx, yyyyyyyyyyyy, vvvvvvvvv)
                                                 vvvvvvvvv)
           aaaaaaaaaaaaaa.bbbbbbbbbbbbbb.ccccccc(zzzzzzzzzzzz, xxxxxxxxxxx, yyyyyyyyyyyy,
                                                 vvvvvvvvv)
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -960,14 +1075,14 @@ xxxxxxxxxxx, yyyyyyyyyyyy, vvvvvvvvv)
           # Yo man.
           # Yo man.
           a = 42
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testSpaceBetweenStringAndParentheses(self):
     code = textwrap.dedent("""\
         b = '0' ('hello')
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -982,7 +1097,7 @@ xxxxxxxxxxx, yyyyyyyyyyyy, vvvvvvvvv)
               # Yo man.
               a = 42
             ''')
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -994,7 +1109,7 @@ xxxxxxxxxxx, yyyyyyyyyyyy, vvvvvvvvv)
         <b>Residence: </b>"""+palace["Winter"]+"""<br>
         </body>
         </html>"""
-        ''')  # noqa
+    ''')  # noqa
     expected_formatted_code = textwrap.dedent('''\
         def f():
           email_text += """<html>This is a really long docstring that goes over the column limit and is multi-line.<br><br>
@@ -1003,7 +1118,7 @@ xxxxxxxxxxx, yyyyyyyyyyyy, vvvvvvvvv)
         <b>Residence: </b>""" + palace["Winter"] + """<br>
         </body>
         </html>"""
-        ''')  # noqa
+    ''')  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -1015,7 +1130,7 @@ xxxxxxxxxxx, yyyyyyyyyyyy, vvvvvvvvv)
             b):  # A trailing comment
           # Whoa! A normal comment!!
           pass  # Another trailing comment
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1024,12 +1139,12 @@ xxxxxxxxxxx, yyyyyyyyyyyy, vvvvvvvvv)
         def f():
           raise RuntimeError('unable to find insertion point for target node',
                              (target,))
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         def f():
           raise RuntimeError('unable to find insertion point for target node',
                              (target,))
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -1043,7 +1158,7 @@ xxxxxxxxxxx, yyyyyyyyyyyy, vvvvvvvvv)
                 self._SetTokenSubtype(
                     child, subtype=_ARGLIST_TOKEN_TO_SUBTYPE.get(
                         child.value, format_token.Subtype.NONE))
-        ''')
+    ''')
     expected_formatted_code = textwrap.dedent('''\
         class F:
 
@@ -1055,17 +1170,17 @@ xxxxxxxxxxx, yyyyyyyyyyyy, vvvvvvvvv)
                     child,
                     subtype=_ARGLIST_TOKEN_TO_SUBTYPE.get(child.value,
                                                           format_token.Subtype.NONE))
-        ''')  # noqa
+    ''')  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testTrailingCommaAndBracket(self):
-    unformatted_code = textwrap.dedent('''\
+    unformatted_code = textwrap.dedent("""\
         a = { 42, }
         b = ( 42, )
         c = [ 42, ]
-        ''')
-    expected_formatted_code = textwrap.dedent('''\
+    """)
+    expected_formatted_code = textwrap.dedent("""\
         a = {
             42,
         }
@@ -1073,20 +1188,20 @@ xxxxxxxxxxx, yyyyyyyyyyyy, vvvvvvvvv)
         c = [
             42,
         ]
-        ''')
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testI18n(self):
     code = textwrap.dedent("""\
         N_('Some years ago - never mind how long precisely - having little or no money in my purse, and nothing particular to interest me on shore, I thought I would sail about a little and see the watery part of the world.')  # A comment is here.
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
     code = textwrap.dedent("""\
         foo('Fake function call')  #. Some years ago - never mind how long precisely - having little or no money in my purse, and nothing particular to interest me on shore, I thought I would sail about a little and see the watery part of the world.
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1100,12 +1215,12 @@ xxxxxxxxxxx, yyyyyyyyyyyy, vvvvvvvvv)
               #. Second i18n comment.
               'snork': 'bar#.*=\\\\0',
           })
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testClosingBracketIndent(self):
-    code = textwrap.dedent('''\
+    code = textwrap.dedent("""\
         def f():
 
           def g():
@@ -1113,7 +1228,7 @@ xxxxxxxxxxx, yyyyyyyyyyyy, vvvvvvvvv)
                    xxxxxxxxxxxxxxxxxxxxx(
                        yyyyyyyyyyyyy[zzzzz].aaaaaaaa[0]) == 'bbbbbbb'):
               pass
-        ''')  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1131,7 +1246,7 @@ xxxxxxxxxxx, yyyyyyyyyyyy, vvvvvvvvv)
                     "horkhorkhork": 4,
                     "porkporkpork": 5,
                     })
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         class Foo(object):
 
@@ -1145,7 +1260,7 @@ xxxxxxxxxxx, yyyyyyyyyyyy, vvvvvvvvv)
                     "horkhorkhork": 4,
                     "porkporkpork": 5,
                 })
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -1158,21 +1273,21 @@ xxxxxxxxxxx, yyyyyyyyyyyy, vvvvvvvvv)
                 itertools.ifilter(lambda c: pytree_utils.NodeName(c) == name,
                                   node.pre_order())):
               pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testFunctionCallContinuationLine(self):
-    code = """\
-class foo:
-
-  def bar(self, node, name, n=1):
-    if True:
-      if True:
-        return [(aaaaaaaaaa,
-                 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb(
-                     cccc, ddddddddddddddddddddddddddddddddddddd))]
-"""
+    code = textwrap.dedent("""\
+        class foo:
+
+          def bar(self, node, name, n=1):
+            if True:
+              if True:
+                return [(aaaaaaaaaa,
+                         bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb(
+                             cccc, ddddddddddddddddddddddddddddddddddddd))]
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1184,7 +1299,7 @@ class foo:
                        #. Error message indicating an invalid e-mail address.
                        message=N_('Please check your email address.'), **kwargs):
             pass
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1192,7 +1307,7 @@ class foo:
     code = textwrap.dedent("""\
         if ~(a or b):
           pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1210,7 +1325,7 @@ class foo:
                        aaaaaaaaaaaaaaaaaa=False,
                        bbbbbbbbbbbbbbb=False):
             pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1222,7 +1337,7 @@ class foo:
                 ccccccccccccc=ccccccccccccc, ddddddd=ddddddd, eeee=eeee,
                 fffff=fffff, ggggggg=ggggggg, hhhhhhhhhhhhh=hhhhhhhhhhhhh,
                 iiiiiii=iiiiiiiiiiiiii)
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         class Fnord(object):
 
@@ -1235,7 +1350,7 @@ class foo:
                 ggggggg=ggggggg,
                 hhhhhhhhhhhhh=hhhhhhhhhhhhh,
                 iiiiiii=iiiiiiiiiiiiii)
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -1243,7 +1358,7 @@ class foo:
     code = textwrap.dedent("""\
         if not (this and that):
           pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1256,18 +1371,18 @@ class foo:
                   os.path.join(filename, f)
                   for f in os.listdir(filename)
                   if IsPythonFile(os.path.join(filename, f)))
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testExpressionPenalties(self):
     code = textwrap.dedent("""\
-      def f():
-        if ((left.value == '(' and right.value == ')') or
-            (left.value == '[' and right.value == ']') or
-            (left.value == '{' and right.value == '}')):
-          return False
-        """)
+        def f():
+          if ((left.value == '(' and right.value == ')') or
+              (left.value == '[' and right.value == ']') or
+              (left.value == '{' and right.value == '}')):
+            return False
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1278,7 +1393,7 @@ class foo:
         try: a = 42
         except: b = 42
         with open(a) as fd: a = fd.read()
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         while True:
           continue
@@ -1290,7 +1405,7 @@ class foo:
           b = 42
         with open(a) as fd:
           a = fd.read()
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -1298,7 +1413,7 @@ class foo:
     unformatted_code = textwrap.dedent("""\
         FOO = ['bar', 'baz', 'mux', 'qux', 'quux', 'quuux', 'quuuux',
           'quuuuux', 'quuuuuux', 'quuuuuuux', lambda a, b: 37,]
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         FOO = [
             'bar',
@@ -1313,7 +1428,7 @@ class foo:
             'quuuuuuux',
             lambda a, b: 37,
         ]
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -1332,14 +1447,14 @@ class foo:
             'quuuuuuux',  # quuuuuuux
             lambda a, b: 37  # lambda
         ]
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testRelativeImportStatements(self):
     code = textwrap.dedent("""\
         from ... import bork
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1350,11 +1465,11 @@ class foo:
             ("...", "."), "..",
             ".............................................."
         )
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb = aaaaaaaaaaa(
             ("...", "."), "..", "..............................................")
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -1373,7 +1488,7 @@ class foo:
             pass
         except:
           pass
-        """)
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         import signal
 
@@ -1388,7 +1503,7 @@ class foo:
             pass
         except:
           pass
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -1400,17 +1515,17 @@ class foo:
             if self.aaaaaaaaaaaaaaaaaaaa not in self.bbbbbbbbbb(
                 cccccccccccccccccccc=True):
               pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testTrailerOnSingleLine(self):
-    code = """\
-urlpatterns = patterns('', url(r'^$', 'homepage_view'),
-                       url(r'^/login/$', 'login_view'),
-                       url(r'^/login/$', 'logout_view'),
-                       url(r'^/user/(?P<username>\\w+)/$', 'profile_view'))
-"""
+    code = textwrap.dedent("""\
+        urlpatterns = patterns('', url(r'^$', 'homepage_view'),
+                               url(r'^/login/$', 'login_view'),
+                               url(r'^/login/$', 'logout_view'),
+                               url(r'^/user/(?P<username>\\w+)/$', 'profile_view'))
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1423,7 +1538,7 @@ urlpatterns = patterns('', url(r'^$', 'homepage_view'),
               if (child.type == grammar_token.NAME and
                   child.value in substatement_names):
                 pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1434,14 +1549,14 @@ urlpatterns = patterns('', url(r'^$', 'homepage_view'),
                "ante hendrerit. Donec et mollis dolor. Praesent et diam eget libero egestas mattis "\\
                "sit amet vitae augue. Nam tincidunt congue enim, ut porta lorem lacinia consectetur. "\\
                "Donec ut libero sed arcu vehicula ultricies a non tortor. Lorem ipsum dolor sit amet"
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
     code = textwrap.dedent("""\
         from __future__ import nested_scopes, generators, division, absolute_import, with_statement, \\
             print_function, unicode_literals
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1449,7 +1564,7 @@ urlpatterns = patterns('', url(r'^$', 'homepage_view'),
         if aaaaaaaaa == 42 and bbbbbbbbbbbbbb == 42 and \\
            cccccccc == 42:
           pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1460,7 +1575,7 @@ urlpatterns = patterns('', url(r'^$', 'homepage_view'),
                   #c1
                   key2=arg)\\
                         .fn3()
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1469,16 +1584,16 @@ urlpatterns = patterns('', url(r'^$', 'homepage_view'),
         xyz = \\
             \\
             some_thing()
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testContinuationMarkerAfterStringWithContinuation(self):
-    code = """\
-s = 'foo \\
-    bar' \\
-    .format()
-"""
+    code = textwrap.dedent("""\
+        s = 'foo \\
+            bar' \\
+            .format()
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1488,14 +1603,14 @@ s = 'foo \\
             'output_dirs', [],
             'Lorem ipsum dolor sit amet, consetetur adipiscing elit. Donec a diam lectus. '
             'Sed sit amet ipsum mauris. Maecenas congue.')
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testSplitStringsIfSurroundedByParens(self):
     unformatted_code = textwrap.dedent("""\
         a = foo.bar({'xxxxxxxxxxxxxxxxxxxxxxx' 'yyyyyyyyyyyyyyyyyyyyyyyyyy': baz[42]} + 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' 'bbbbbbbbbbbbbbbbbbbbbbbbbb' 'cccccccccccccccccccccccccccccccc' 'ddddddddddddddddddddddddddddd')
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         a = foo.bar({'xxxxxxxxxxxxxxxxxxxxxxx'
                      'yyyyyyyyyyyyyyyyyyyyyyyyyy': baz[42]} +
@@ -1503,7 +1618,7 @@ s = 'foo \\
                     'bbbbbbbbbbbbbbbbbbbbbbbbbb'
                     'cccccccccccccccccccccccccccccccc'
                     'ddddddddddddddddddddddddddddd')
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -1511,7 +1626,7 @@ s = 'foo \\
         a = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
 'bbbbbbbbbbbbbbbbbbbbbbbbbb' 'cccccccccccccccccccccccccccccccc' \
 'ddddddddddddddddddddddddddddd'
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1531,7 +1646,7 @@ s = 'foo \\
         import os
 
         assert os.environ['FOO'] == '123'
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1539,17 +1654,47 @@ s = 'foo \\
     code = textwrap.dedent("""\
         a_very_long_function_call_yada_yada_etc_etc_etc(long_arg1,
                                                         long_arg2 / long_arg3)
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
+  def testNoSplittingAroundCompOperators(self):
+    code = textwrap.dedent("""\
+        c = (aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa is not bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)
+        c = (aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa in bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)
+        c = (aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa not in bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)
+
+        c = (aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa is bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)
+        c = (aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa <= bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)
+    """)  # noqa
+    expected_code = textwrap.dedent("""\
+        c = (
+            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
+            is not bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)
+        c = (
+            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
+            in bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)
+        c = (
+            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
+            not in bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)
+
+        c = (
+            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
+            is bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)
+        c = (
+            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
+            <= bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)
+    """)
+    llines = yapf_test_helper.ParseAndUnwrap(code)
+    self.assertCodeEqual(expected_code, reformatter.Reformat(llines))
+
   def testNoSplittingWithinSubscriptList(self):
     code = textwrap.dedent("""\
         somequitelongvariablename.somemember[(a, b)] = {
             'somelongkey': 1,
             'someotherlongkey': 2
         }
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1561,7 +1706,7 @@ s = 'foo \\
             self.write(s=[
                 '%s%s %s' % ('many of really', 'long strings', '+ just makes up 81')
             ])
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1571,7 +1716,7 @@ s = 'foo \\
             if True:
               if contract == allow_contract and attr_dict.get(if_attribute) == has_value:
                 return True
-        """)  # noqa
+    """)  # noqa
     expected_code = textwrap.dedent("""\
         def _():
           if True:
@@ -1579,7 +1724,7 @@ s = 'foo \\
               if contract == allow_contract and attr_dict.get(
                   if_attribute) == has_value:
                 return True
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_code, reformatter.Reformat(llines))
 
@@ -1590,10 +1735,22 @@ s = 'foo \\
             for variable in fnord
             if variable != 37
         }
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
+    unformatted_code = textwrap.dedent("""\
+        foo = {
+            x: x
+            for x in fnord
+        }
+    """)  # noqa
+    expected_code = textwrap.dedent("""\
+        foo = {x: x for x in fnord}
+    """)
+    llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
+    self.assertCodeEqual(expected_code, reformatter.Reformat(llines))
+
   def testUnaryOpInDictionaryValue(self):
     code = textwrap.dedent("""\
         beta = "123"
@@ -1601,7 +1758,7 @@ s = 'foo \\
         test = {'alpha': beta[-1]}
 
         print(beta[-1])
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1613,33 +1770,37 @@ s = 'foo \\
               if True:
                 remote_checksum = self.get_checksum(conn, tmp, dest, inject,
                                                     not directory_prepended, source)
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testRelaxArraySubscriptAffinity(self):
-    code = """\
-class A(object):
+    code = textwrap.dedent("""\
+        class A(object):
 
-  def f(self, aaaaaaaaa, bbbbbbbbbbbbb, row):
-    if True:
-      if True:
-        if True:
-          if True:
-            if row[4] is None or row[5] is None:
-              bbbbbbbbbbbbb[
-                  '..............'] = row[5] if row[5] is not None else 5
-"""
+          def f(self, aaaaaaaaa, bbbbbbbbbbbbb, row):
+            if True:
+              if True:
+                if True:
+                  if True:
+                    if row[4] is None or row[5] is None:
+                      bbbbbbbbbbbbb[
+                          '..............'] = row[5] if row[5] is not None else 5
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testFunctionCallInDict(self):
-    code = "a = {'a': b(c=d, **e)}\n"
+    code = textwrap.dedent("""\
+        a = {'a': b(c=d, **e)}
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testFunctionCallInNestedDict(self):
-    code = "a = {'a': {'a': {'a': b(c=d, **e)}}}\n"
+    code = textwrap.dedent("""\
+        a = {'a': {'a': {'a': b(c=d, **e)}}}
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1648,100 +1809,100 @@ class A(object):
         def test():
           if not "Foooooooooooooooooooooooooooooo" or "Foooooooooooooooooooooooooooooo" == "Foooooooooooooooooooooooooooooo":
             pass
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testSplitListWithComment(self):
     code = textwrap.dedent("""\
-      a = [
-          'a',
-          'b',
-          'c'  # hello world
-      ]
-      """)
+        a = [
+            'a',
+            'b',
+            'c'  # hello world
+        ]
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testOverColumnLimit(self):
     unformatted_code = textwrap.dedent("""\
-      class Test:
+        class Test:
 
-        def testSomething(self):
-          expected = {
-              ('aaaaaaaaaaaaa', 'bbbb'): 'ccccccccccccccccccccccccccccccccccccccccccc',
-              ('aaaaaaaaaaaaa', 'bbbb'): 'ccccccccccccccccccccccccccccccccccccccccccc',
-              ('aaaaaaaaaaaaa', 'bbbb'): 'ccccccccccccccccccccccccccccccccccccccccccc',
-          }
-        """)  # noqa
-    expected_formatted_code = textwrap.dedent("""\
-      class Test:
-
-        def testSomething(self):
-          expected = {
-              ('aaaaaaaaaaaaa', 'bbbb'):
-                  'ccccccccccccccccccccccccccccccccccccccccccc',
-              ('aaaaaaaaaaaaa', 'bbbb'):
-                  'ccccccccccccccccccccccccccccccccccccccccccc',
-              ('aaaaaaaaaaaaa', 'bbbb'):
-                  'ccccccccccccccccccccccccccccccccccccccccccc',
-          }
-        """)
+          def testSomething(self):
+            expected = {
+                ('aaaaaaaaaaaaa', 'bbbb'): 'ccccccccccccccccccccccccccccccccccccccccccc',
+                ('aaaaaaaaaaaaa', 'bbbb'): 'ccccccccccccccccccccccccccccccccccccccccccc',
+                ('aaaaaaaaaaaaa', 'bbbb'): 'ccccccccccccccccccccccccccccccccccccccccccc',
+            }
+    """)  # noqa
+    expected_formatted_code = textwrap.dedent("""\
+        class Test:
+
+          def testSomething(self):
+            expected = {
+                ('aaaaaaaaaaaaa', 'bbbb'):
+                    'ccccccccccccccccccccccccccccccccccccccccccc',
+                ('aaaaaaaaaaaaa', 'bbbb'):
+                    'ccccccccccccccccccccccccccccccccccccccccccc',
+                ('aaaaaaaaaaaaa', 'bbbb'):
+                    'ccccccccccccccccccccccccccccccccccccccccccc',
+            }
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testEndingComment(self):
     code = textwrap.dedent("""\
-      a = f(
-          a="something",
-          b="something requiring comment which is quite long",  # comment about b (pushes line over 79)
-          c="something else, about which comment doesn't make sense")
-      """)  # noqa
+        a = f(
+            a="something",
+            b="something requiring comment which is quite long",  # comment about b (pushes line over 79)
+            c="something else, about which comment doesn't make sense")
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testContinuationSpaceRetention(self):
     code = textwrap.dedent("""\
-      def fn():
-        return module \\
-               .method(Object(data,
-                   fn2(arg)
-               ))
-      """)
+        def fn():
+          return module \\
+                 .method(Object(data,
+                     fn2(arg)
+                 ))
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testIfExpressionWithFunctionCall(self):
     code = textwrap.dedent("""\
-      if x or z.y(
-          a,
-          c,
-          aaaaaaaaaaaaaaaaaaaaa=aaaaaaaaaaaaaaaaaa,
-          bbbbbbbbbbbbbbbbbbbbb=bbbbbbbbbbbbbbbbbb):
-        pass
-      """)
+        if x or z.y(
+            a,
+            c,
+            aaaaaaaaaaaaaaaaaaaaa=aaaaaaaaaaaaaaaaaa,
+            bbbbbbbbbbbbbbbbbbbbb=bbbbbbbbbbbbbbbbbb):
+          pass
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testUnformattedAfterMultilineString(self):
     code = textwrap.dedent("""\
-      def foo():
-        com_text = \\
-      '''
-      TEST
-      ''' % (input_fname, output_fname)
-      """)
+        def foo():
+          com_text = \\
+        '''
+        TEST
+        ''' % (input_fname, output_fname)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testNoSpacesAroundKeywordDefaultValues(self):
     code = textwrap.dedent("""\
-      sources = {
-          'json': request.get_json(silent=True) or {},
-          'json2': request.get_json(silent=True),
-      }
-      json = request.get_json(silent=True) or {}
-      """)
+        sources = {
+            'json': request.get_json(silent=True) or {},
+            'json2': request.get_json(silent=True),
+        }
+        json = request.get_json(silent=True) or {}
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1750,13 +1911,13 @@ class A(object):
         if True:
           if True:
             status = cf.describe_stacks(StackName=stackname)[u'Stacks'][0][u'StackStatus']
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         if True:
           if True:
             status = cf.describe_stacks(
                 StackName=stackname)[u'Stacks'][0][u'StackStatus']
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -1770,7 +1931,7 @@ class A(object):
                                     aaaaaaa.bbbbbbbbbbbb).group(a.b) +
                           re.search(r'\\d+\\.\\d+\\.\\d+\\.(\\d+)',
                                     ccccccc).group(c.d))
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         xxxxxxxxxxxxxx = (
             re.search(r'(\\d+\\.\\d+\\.\\d+\\.)\\d+', aaaaaaa.bbbbbbbbbbbb).group(1) +
@@ -1778,7 +1939,7 @@ class A(object):
         xxxxxxxxxxxxxx = (
             re.search(r'(\\d+\\.\\d+\\.\\d+\\.)\\d+', aaaaaaa.bbbbbbbbbbbb).group(a.b) +
             re.search(r'\\d+\\.\\d+\\.\\d+\\.(\\d+)', ccccccc).group(c.d))
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -1788,7 +1949,7 @@ class A(object):
           while True:
             aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa = list['bbbbbbbbbbbbbbbbbbbbbbbbb'].split(',')
             aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa = list('bbbbbbbbbbbbbbbbbbbbbbbbb').split(',')
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         while True:
           while True:
@@ -1796,7 +1957,7 @@ class A(object):
                 'bbbbbbbbbbbbbbbbbbbbbbbbb'].split(',')
             aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa = list(
                 'bbbbbbbbbbbbbbbbbbbbbbbbb').split(',')
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -1806,14 +1967,14 @@ class A(object):
 
           def __repr__(self):
             tokens_repr = ','.join(['{0}({1!r})'.format(tok.name, tok.value) for tok in self._tokens])
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         class f:
 
           def __repr__(self):
             tokens_repr = ','.join(
                 ['{0}({1!r})'.format(tok.name, tok.value) for tok in self._tokens])
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -1827,7 +1988,7 @@ class A(object):
             pytree_utils.InsertNodesBefore(_CreateCommentsFromPrefix(
                 comment_prefix, comment_lineno, comment_column,
                 standalone=True))
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         def f():
           if True:
@@ -1838,7 +1999,7 @@ class A(object):
             pytree_utils.InsertNodesBefore(
                 _CreateCommentsFromPrefix(
                     comment_prefix, comment_lineno, comment_column, standalone=True))
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -1846,66 +2007,66 @@ class A(object):
     unformatted_code = textwrap.dedent("""\
         a = b ** 37
         c = (20 ** -3) / (_GRID_ROWS ** (code_length - 10))
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         a = b**37
         c = (20**-3) / (_GRID_ROWS**(code_length - 10))
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
     code = textwrap.dedent("""\
-      def f():
-        if True:
-          if (self.stack[-1].split_before_closing_bracket and
-              # FIXME(morbo): Use the 'matching_bracket' instead of this.
-              # FIXME(morbo): Don't forget about tuples!
-              current.value in ']}'):
-            pass
-      """)
+        def f():
+          if True:
+            if (self.stack[-1].split_before_closing_bracket and
+                # FIXME(morbo): Use the 'matching_bracket' instead of this.
+                # FIXME(morbo): Don't forget about tuples!
+                current.value in ']}'):
+              pass
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testContiguousList(self):
     code = textwrap.dedent("""\
-      [retval1, retval2] = a_very_long_function(argument_1, argument2, argument_3,
-                                                argument_4)
-      """)  # noqa
+        [retval1, retval2] = a_very_long_function(argument_1, argument2, argument_3,
+                                                  argument_4)
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testArgsAndKwargsFormatting(self):
     code = textwrap.dedent("""\
-      a(a=aaaaaaaaaaaaaaaaaaaaa,
-        b=aaaaaaaaaaaaaaaaaaaaaaaa,
-        c=aaaaaaaaaaaaaaaaaa,
-        *d,
-        **e)
-      """)
+        a(a=aaaaaaaaaaaaaaaaaaaaa,
+          b=aaaaaaaaaaaaaaaaaaaaaaaa,
+          c=aaaaaaaaaaaaaaaaaa,
+          *d,
+          **e)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
     code = textwrap.dedent("""\
-      def foo():
-        return [
-            Bar(xxx='some string',
-                yyy='another long string',
-                zzz='a third long string')
-        ]
-      """)
+        def foo():
+          return [
+              Bar(xxx='some string',
+                  yyy='another long string',
+                  zzz='a third long string')
+          ]
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testCommentColumnLimitOverflow(self):
     code = textwrap.dedent("""\
-      def f():
-        if True:
-          TaskManager.get_tags = MagicMock(
-              name='get_tags_mock',
-              return_value=[157031694470475],
-              # side_effect=[(157031694470475), (157031694470475),],
-          )
-      """)
+        def f():
+          if True:
+            TaskManager.get_tags = MagicMock(
+                name='get_tags_mock',
+                return_value=[157031694470475],
+                # side_effect=[(157031694470475), (157031694470475),],
+            )
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1920,7 +2081,7 @@ class A(object):
             if self.do_something:
               d.addCallback(lambda _: self.aaaaaa.bbbbbbbbbbbbbbbb.cccccccccccccccccccccccccccccccc(dddddddddddddd))
             return d
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         class SomeClass(object):
           do_something = True
@@ -1932,7 +2093,7 @@ class A(object):
               d.addCallback(lambda _: self.aaaaaa.bbbbbbbbbbbbbbbb.
                             cccccccccccccccccccccccccccccccc(dddddddddddddd))
             return d
-        """)
+    """)
 
     try:
       style.SetGlobalStyle(
@@ -1954,7 +2115,7 @@ class A(object):
             ('vehicula convallis nulla. Vestibulum dictum nisl in malesuada finibus.',):
                 3
         }
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         MAP_WITH_LONG_KEYS = {
             ('lorem ipsum', 'dolor sit amet'):
@@ -1965,7 +2126,7 @@ class A(object):
             ('vehicula convallis nulla. Vestibulum dictum nisl in malesuada finibus.',):
                 3
         }
-        """)  # noqa
+    """)  # noqa
 
     try:
       style.SetGlobalStyle(
@@ -1991,7 +2152,7 @@ class A(object):
                     }
                 }]
             }
-        """)  # noqa
+    """)  # noqa
 
     try:
       style.SetGlobalStyle(
@@ -2016,7 +2177,7 @@ class A(object):
           def _():
               url = "http://{0}/axis-cgi/admin/param.cgi?{1}".format(
                   value, urllib.urlencode({'action': 'update', 'parameter': value}))
-          """)  # noqa
+      """)  # noqa
       expected_formatted_code = textwrap.dedent("""\
           def _():
               url = "http://{0}/axis-cgi/admin/param.cgi?{1}".format(
@@ -2024,7 +2185,7 @@ class A(object):
                       'action': 'update',
                       'parameter': value
                   }))
-          """)
+      """)
 
       llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
       reformatted_code = reformatter.Reformat(llines)
@@ -2041,36 +2202,36 @@ class A(object):
         def mark_game_scored(gid):
           _connect.execute(_games.update().where(_games.c.gid == gid).values(
               scored=True))
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         def mark_game_scored(gid):
           _connect.execute(
               _games.update().where(_games.c.gid == gid).values(scored=True))
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testDontAddBlankLineAfterMultilineString(self):
     code = textwrap.dedent("""\
-      query = '''SELECT id
-      FROM table
-      WHERE day in {}'''
-      days = ",".join(days)
-      """)
+        query = '''SELECT id
+        FROM table
+        WHERE day in {}'''
+        days = ",".join(days)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testFormattingListComprehensions(self):
     code = textwrap.dedent("""\
-      def a():
-        if True:
+        def a():
           if True:
             if True:
-              columns = [
-                  x for x, y in self._heap_this_is_very_long if x.route[0] == choice
-              ]
-              self._heap = [x for x in self._heap if x.route and x.route[0] == choice]
-      """)  # noqa
+              if True:
+                columns = [
+                    x for x, y in self._heap_this_is_very_long if x.route[0] == choice
+                ]
+                self._heap = [x for x in self._heap if x.route and x.route[0] == choice]
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -2087,7 +2248,7 @@ class A(object):
             long_argument_name_1=1, long_argument_name_2=2, long_argument_name_3=3,
             long_argument_name_4=4
         )
-        """)  # noqa
+    """)  # noqa
 
     try:
       style.SetGlobalStyle(
@@ -2112,12 +2273,12 @@ class A(object):
         if not aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.b(c == d[
                 'eeeeee']).ffffff():
           pass
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         if not aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.b(
             c == d['eeeeee']).ffffff():
           pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -2130,7 +2291,7 @@ class A(object):
                 if True:
                   if True:
                     boxes[id_] = np.concatenate((points.min(axis=0), qoints.max(axis=0)))
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         def _():
           if True:
@@ -2140,7 +2301,7 @@ class A(object):
                   if True:
                     boxes[id_] = np.concatenate(
                         (points.min(axis=0), qoints.max(axis=0)))
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -2157,7 +2318,7 @@ class A(object):
                                   clue for clue in combination if not clue == Verifier.UNMATCHED
                           ), constraints, InvestigationResult.OR
                   )
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         class _():
 
@@ -2169,7 +2330,7 @@ class A(object):
                   return cls._create_investigation_result(
                       (clue for clue in combination if not clue == Verifier.UNMATCHED),
                       constraints, InvestigationResult.OR)
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -2184,7 +2345,11 @@ class A(object):
         a_very_long_function_name(long_argument_name_1, long_argument_name_2, long_argument_name_3, long_argument_name_4,)
 
         r =f0 (1,  2,3,)
-        """)  # noqa
+
+        r =f0 (1,)
+
+        r =f0 (a=1,)
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         function_name(argument_name_1=1, argument_name_2=2, argument_name_3=3)
 
@@ -2212,7 +2377,15 @@ class A(object):
             2,
             3,
         )
-        """)
+
+        r = f0(
+            1,
+        )
+
+        r = f0(
+            a=1,
+        )
+    """)
 
     try:
       style.SetGlobalStyle(
@@ -2235,7 +2408,7 @@ class A(object):
         from toto import titi, tata, tutu  # noqa
         from toto import titi, tata, tutu
         from toto import (titi, tata, tutu)
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -2263,7 +2436,7 @@ class A(object):
         'jjjjjjjjjjjjjjjjjjjjjjjjjj':
             Check('QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ', '=', False),
         }
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         a = {
             'aaaaaaaaaaaaaaaaaaaaaaaa':
@@ -2287,7 +2460,7 @@ class A(object):
             'jjjjjjjjjjjjjjjjjjjjjjjjjj':
                 Check('QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ', '=', False),
         }
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -2297,11 +2470,11 @@ class A(object):
             content={ 'a': 'b' },
             branch_key=branch.key,
             collection_key=collection.key)
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         doc = test_utils.CreateTestDocumentViaController(
             content={'a': 'b'}, branch_key=branch.key, collection_key=collection.key)
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -2311,14 +2484,14 @@ class A(object):
             branch_key=branch.key,
             collection_key=collection.key,
             collection_key2=collection.key2)
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         doc = test_utils.CreateTestDocumentViaController(
             content={'a': 'b'},
             branch_key=branch.key,
             collection_key=collection.key,
             collection_key2=collection.key2)
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -2351,7 +2524,7 @@ class A(object):
             'cccccccccc': ('^21109',  # PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP.
                           ),
         }
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         _A = {
             'cccccccccc': ('^^1',),
@@ -2385,7 +2558,7 @@ class A(object):
                 '^21109',  # PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP.
             ),
         }
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -2399,7 +2572,7 @@ class A(object):
             breadcrumbs = [{'name': 'Admin',
                             'url': url_for(".home")},
                            {'title': title}]
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         class _():
           def _():
@@ -2413,7 +2586,7 @@ class A(object):
                 },
             ]
             breadcrumbs = [{'name': 'Admin', 'url': url_for(".home")}, {'title': title}]
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -2433,18 +2606,18 @@ class A(object):
             Environment.YYYYYYY: 'some text more text even more text yet ag',
             Environment.ZZZZZZZZZZZ: 'some text more text even more text yet again tex',
         }
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testNotInParams(self):
     unformatted_code = textwrap.dedent("""\
         list("a long line to break the line. a long line to break the brk a long lin", not True)
-        """)  # noqa
+    """)  # noqa
     expected_code = textwrap.dedent("""\
         list("a long line to break the line. a long line to break the brk a long lin",
              not True)
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_code, reformatter.Reformat(llines))
 
@@ -2455,14 +2628,14 @@ class A(object):
             with py3compat.open_with_encoding(filename, mode='w',
                                               encoding=encoding) as fd:
               pass
-        """)
+    """)
     expected_code = textwrap.dedent("""\
         def _():
           if True:
             with py3compat.open_with_encoding(
                 filename, mode='w', encoding=encoding) as fd:
               pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_code, reformatter.Reformat(llines))
 
@@ -2477,7 +2650,7 @@ class A(object):
 
           def __init__(self):
             pass
-        ''')
+    ''')
     expected_code = textwrap.dedent('''\
         class A:
           """Does something.
@@ -2487,7 +2660,7 @@ class A(object):
 
           def __init__(self):
             pass
-        ''')
+    ''')
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_code, reformatter.Reformat(llines))
 
@@ -2501,7 +2674,7 @@ class A(object):
 
           def __init__(self):
             pass
-        ''')
+    ''')
     expected_formatted_code = textwrap.dedent('''\
         class A:
 
@@ -2512,7 +2685,7 @@ class A(object):
 
           def __init__(self):
             pass
-        ''')
+    ''')
 
     try:
       style.SetGlobalStyle(
@@ -2536,7 +2709,7 @@ class A(object):
 
         def foobar():
           pass
-        ''')
+    ''')
     expected_code = textwrap.dedent('''\
         #!/usr/bin/env python
         # -*- coding: utf-8 name> -*-
@@ -2545,7 +2718,7 @@ class A(object):
 
         def foobar():
           pass
-        ''')
+    ''')
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_code, reformatter.Reformat(llines))
 
@@ -2557,7 +2730,7 @@ class A(object):
 
         def foobar():
             pass
-        ''')
+    ''')
     expected_formatted_code = textwrap.dedent('''\
         #!/usr/bin/env python
         # -*- coding: utf-8 name> -*-
@@ -2567,7 +2740,7 @@ class A(object):
 
         def foobar():
             pass
-        ''')
+    ''')
 
     try:
       style.SetGlobalStyle(
@@ -2586,23 +2759,36 @@ class A(object):
         def f():
           this_is_a_very_long_function_name(an_extremely_long_variable_name, (
               'a string that may be too long %s' % 'M15'))
-        """)
+    """)
     expected_code = textwrap.dedent("""\
         def f():
           this_is_a_very_long_function_name(
               an_extremely_long_variable_name,
               ('a string that may be too long %s' % 'M15'))
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_code, reformatter.Reformat(llines))
 
   def testSubscriptExpression(self):
     code = textwrap.dedent("""\
         foo = d[not a]
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
+  def testSubscriptExpressionTerminatedByComma(self):
+    unformatted_code = textwrap.dedent("""\
+        A[B, C,]
+    """)
+    expected_code = textwrap.dedent("""\
+        A[
+            B,
+            C,
+        ]
+    """)
+    llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
+    self.assertCodeEqual(expected_code, reformatter.Reformat(llines))
+
   def testListWithFunctionCalls(self):
     unformatted_code = textwrap.dedent("""\
         def foo():
@@ -2615,7 +2801,7 @@ class A(object):
                       yyy='another long string',
                       zzz='a third long string')
           ]
-        """)
+    """)
     expected_code = textwrap.dedent("""\
         def foo():
           return [
@@ -2626,7 +2812,7 @@ class A(object):
                   yyy='another long string',
                   zzz='a third long string')
           ]
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_code, reformatter.Reformat(llines))
 
@@ -2634,29 +2820,29 @@ class A(object):
     unformatted_code = textwrap.dedent("""\
         X=...
         Y = X if ... else X
-        """)
+    """)
     expected_code = textwrap.dedent("""\
         X = ...
         Y = X if ... else X
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_code, reformatter.Reformat(llines))
 
   def testPseudoParens(self):
-    unformatted_code = """\
-my_dict = {
-    'key':  # Some comment about the key
-        {'nested_key': 1, },
-}
-"""
-    expected_code = """\
-my_dict = {
-    'key':  # Some comment about the key
-        {
-            'nested_key': 1,
-        },
-}
-"""
+    unformatted_code = textwrap.dedent("""\
+        my_dict = {
+            'key':  # Some comment about the key
+                {'nested_key': 1, },
+        }
+    """)
+    expected_code = textwrap.dedent("""\
+        my_dict = {
+            'key':  # Some comment about the key
+                {
+                    'nested_key': 1,
+                },
+        }
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_code, reformatter.Reformat(llines))
 
@@ -2665,11 +2851,11 @@ my_dict = {
     unformatted_code = textwrap.dedent("""\
         a_very_long_function_name("long string with formatting {0:s}".format(
             "mystring"))
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         a_very_long_function_name(
             "long string with formatting {0:s}".format("mystring"))
-        """)
+    """)
 
     try:
       style.SetGlobalStyle(
@@ -2688,12 +2874,12 @@ my_dict = {
         def _GetNumberOfSecondsFromElements(year, month, day, hours,
                                             minutes, seconds, microseconds):
           return
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         def _GetNumberOfSecondsFromElements(
             year, month, day, hours, minutes, seconds, microseconds):
           return
-        """)
+    """)
 
     try:
       style.SetGlobalStyle(
@@ -2714,12 +2900,12 @@ my_dict = {
             long_argument_name_3 == 3 or
             long_argument_name_4 == 4):
           pass
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         if (long_argument_name_1 == 1 or long_argument_name_2 == 2 or
             long_argument_name_3 == 3 or long_argument_name_4 == 4):
           pass
-        """)
+    """)
 
     try:
       style.SetGlobalStyle(
@@ -2745,7 +2931,7 @@ my_dict = {
                 u'seconds': seconds
             }
         )
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         date_time_values = ({
             u'year': year,
@@ -2755,7 +2941,7 @@ my_dict = {
             u'minutes': minutes,
             u'seconds': seconds
         })
-        """)
+    """)
 
     try:
       style.SetGlobalStyle(
@@ -2776,7 +2962,7 @@ my_dict = {
                 "validUntil":
                     int(time() + (6 * 7 * 24 * 60 * 60))  # in 6 weeks time
             }
-        """)
+    """)
 
     try:
       style.SetGlobalStyle(
@@ -2788,31 +2974,10 @@ my_dict = {
     finally:
       style.SetGlobalStyle(style.CreateYapfStyle())
 
-  @unittest.skipUnless(not py3compat.PY3, 'Requires Python 2.7')
-  def testAsyncAsNonKeyword(self):
-    try:
-      style.SetGlobalStyle(style.CreatePEP8Style())
-
-      # In Python 2, async may be used as a non-keyword identifier.
-      code = textwrap.dedent("""\
-          from util import async
-
-
-          class A(object):
-
-              def foo(self):
-                  async.run()
-          """)
-
-      llines = yapf_test_helper.ParseAndUnwrap(code)
-      self.assertCodeEqual(code, reformatter.Reformat(llines))
-    finally:
-      style.SetGlobalStyle(style.CreateYapfStyle())
-
   def testDisableEndingCommaHeuristic(self):
     code = textwrap.dedent("""\
         x = [1, 2, 3, 4, 5, 6, 7,]
-        """)
+    """)
 
     try:
       style.SetGlobalStyle(
@@ -2832,7 +2997,7 @@ my_dict = {
 
         def function(first_argument_xxxxxxxxxxxxxxxxxxxxxxx=(0,), second_argument=None) -> None:
           pass
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         def function(
             first_argument_xxxxxxxxxxxxxxxx=(0,), second_argument=None
@@ -2844,7 +3009,7 @@ my_dict = {
             first_argument_xxxxxxxxxxxxxxxxxxxxxxx=(0,), second_argument=None
         ) -> None:
           pass
-        """)  # noqa
+    """)  # noqa
 
     try:
       style.SetGlobalStyle(
@@ -2865,7 +3030,7 @@ my_dict = {
 
         def function(first_argument_xxxxxxxxxxxxxxxxxxxxxxx=(0,), second_argument=None) -> None:
           pass
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         def function(
             first_argument_xxxxxxxxxxxxxxxx=(0,), second_argument=None
@@ -2877,7 +3042,7 @@ my_dict = {
             first_argument_xxxxxxxxxxxxxxxxxxxxxxx=(0,), second_argument=None
             ) -> None:
           pass
-        """)  # noqa
+    """)  # noqa
 
     try:
       style.SetGlobalStyle(
@@ -2898,7 +3063,7 @@ my_dict = {
 
         def function(first_argument_xxxxxxxxxxxxxxxxxxxxxxx=(0,), second_and_last_argument=None):
           pass
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         def function(
             first_argument_xxxxxxxxxxxxxxxx=(0,),
@@ -2912,7 +3077,7 @@ my_dict = {
             first_argument_xxxxxxxxxxxxxxxxxxxxxxx=(0,), second_and_last_argument=None
             ):
           pass
-        """)  # noqa
+    """)  # noqa
 
     try:
       style.SetGlobalStyle(
@@ -2934,7 +3099,7 @@ my_dict = {
         def function():
           some_var = ('a couple', 'small', 'elemens')
           return False
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         def function():
           some_var = (
@@ -2947,7 +3112,7 @@ my_dict = {
         def function():
           some_var = ('a couple', 'small', 'elemens')
           return False
-        """)  # noqa
+    """)  # noqa
 
     try:
       style.SetGlobalStyle(
@@ -2969,7 +3134,7 @@ my_dict = {
         def function():
           some_var = ['a couple', 'small', 'elemens']
           return False
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         def function():
           some_var = [
@@ -2982,7 +3147,7 @@ my_dict = {
         def function():
           some_var = ['a couple', 'small', 'elemens']
           return False
-        """)
+    """)
 
     try:
       style.SetGlobalStyle(
@@ -3004,7 +3169,7 @@ my_dict = {
         def function():
           some_var = {1: 'a couple', 2: 'small', 3: 'elemens'}
           return False
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         def function():
           some_var = {
@@ -3023,7 +3188,7 @@ my_dict = {
         def function():
           some_var = {1: 'a couple', 2: 'small', 3: 'elemens'}
           return False
-        """)  # noqa
+    """)  # noqa
 
     try:
       style.SetGlobalStyle(
@@ -3062,7 +3227,7 @@ my_dict = {
                         }
                     ]
                 }
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         class A:
 
@@ -3085,7 +3250,7 @@ my_dict = {
                     }
                 }]
             }
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -3093,16 +3258,21 @@ my_dict = {
     try:
       style.SetGlobalStyle(
           style.CreateStyleFromConfig('{force_multiline_dict: true}'))
-      unformatted_code = textwrap.dedent(
-          "responseDict = {'childDict': {'spam': 'eggs'}}\n")
+      unformatted_code = textwrap.dedent("""\
+          responseDict = {'childDict': {'spam': 'eggs'}}
+          generatedDict = {x: x for x in 'value'}
+      """)
       llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
       actual = reformatter.Reformat(llines)
       expected = textwrap.dedent("""\
-        responseDict = {
-            'childDict': {
-                'spam': 'eggs'
-            }
-        }
+          responseDict = {
+              'childDict': {
+                  'spam': 'eggs'
+              }
+          }
+          generatedDict = {
+              x: x for x in 'value'
+          }
       """)
       self.assertCodeEqual(expected, actual)
     finally:
@@ -3113,7 +3283,8 @@ my_dict = {
       style.SetGlobalStyle(
           style.CreateStyleFromConfig('{force_multiline_dict: false}'))
       unformatted_code = textwrap.dedent("""\
-        responseDict = {'childDict': {'spam': 'eggs'}}
+          responseDict = {'childDict': {'spam': 'eggs'}}
+          generatedDict = {x: x for x in 'value'}
       """)
       expected_formatted_code = unformatted_code
       llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
@@ -3122,15 +3293,48 @@ my_dict = {
     finally:
       style.SetGlobalStyle(style.CreateYapfStyle())
 
-  @unittest.skipUnless(py3compat.PY38, 'Requires Python 3.8')
   def testWalrus(self):
     unformatted_code = textwrap.dedent("""\
-      if (x  :=  len([1]*1000)>100):
-        print(f'{x} is pretty big' )
+        if (x  :=  len([1]*1000)>100):
+          print(f'{x} is pretty big' )
+    """)
+    expected = textwrap.dedent("""\
+        if (x := len([1] * 1000) > 100):
+          print(f'{x} is pretty big')
+    """)
+    llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
+    self.assertCodeEqual(expected, reformatter.Reformat(llines))
+
+  def testStructuredPatternMatching(self):
+    unformatted_code = textwrap.dedent("""\
+        match command.split():
+          case[action   ]:
+            ...  # interpret single-verb action
+          case[action,    obj]:
+            ...  # interpret action, obj
+    """)
+    expected = textwrap.dedent("""\
+        match command.split():
+          case [action]:
+            ...  # interpret single-verb action
+          case [action, obj]:
+            ...  # interpret action, obj
     """)
+    llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
+    self.assertCodeEqual(expected, reformatter.Reformat(llines))
+
+  def testParenthesizedContextManagers(self):
+    unformatted_code = textwrap.dedent("""\
+        with (cert_authority.cert_pem.tempfile() as ca_temp_path, patch.object(os, 'environ', os.environ | {'REQUESTS_CA_BUNDLE': ca_temp_path}),):
+            httpserver_url = httpserver.url_for('/resource.jar')
+    """)  # noqa: E501
     expected = textwrap.dedent("""\
-      if (x := len([1] * 1000) > 100):
-        print(f'{x} is pretty big')
+        with (
+            cert_authority.cert_pem.tempfile() as ca_temp_path,
+            patch.object(os, 'environ',
+                         os.environ | {'REQUESTS_CA_BUNDLE': ca_temp_path}),
+        ):
+          httpserver_url = httpserver.url_for('/resource.jar')
     """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected, reformatter.Reformat(llines))
diff --git a/yapftests/reformatter_buganizer_test.py b/yapftests/reformatter_buganizer_test.py
index b3de8f9..fcfd78e 100644
--- a/yapftests/reformatter_buganizer_test.py
+++ b/yapftests/reformatter_buganizer_test.py
@@ -29,827 +29,827 @@ class BuganizerFixes(yapf_test_helper.YAPFTest):
     style.SetGlobalStyle(style.CreateYapfStyle())
 
   def testB137580392(self):
-    code = """\
-def _create_testing_simulator_and_sink(
-) -> Tuple[_batch_simulator:_batch_simulator.BatchSimulator,
-           _batch_simulator.SimulationSink]:
-  pass
-"""
+    code = textwrap.dedent("""\
+        def _create_testing_simulator_and_sink(
+        ) -> Tuple[_batch_simulator:_batch_simulator.BatchSimulator,
+                   _batch_simulator.SimulationSink]:
+          pass
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testB73279849(self):
-    unformatted_code = """\
-class A:
-    def _(a):
-        return 'hello'  [  a  ]
-"""
-    expected_formatted_code = """\
-class A:
-  def _(a):
-    return 'hello'[a]
-"""
+    unformatted_code = textwrap.dedent("""\
+        class A:
+            def _(a):
+                return 'hello'  [  a  ]
+    """)
+    expected_formatted_code = textwrap.dedent("""\
+        class A:
+          def _(a):
+            return 'hello'[a]
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testB122455211(self):
-    unformatted_code = """\
-_zzzzzzzzzzzzzzzzzzzz = Union[sssssssssssssssssssss.pppppppppppppppp,
-                     sssssssssssssssssssss.pppppppppppppppppppppppppppp]
-"""
-    expected_formatted_code = """\
-_zzzzzzzzzzzzzzzzzzzz = Union[
-    sssssssssssssssssssss.pppppppppppppppp,
-    sssssssssssssssssssss.pppppppppppppppppppppppppppp]
-"""
+    unformatted_code = textwrap.dedent("""\
+        _zzzzzzzzzzzzzzzzzzzz = Union[sssssssssssssssssssss.pppppppppppppppp,
+                             sssssssssssssssssssss.pppppppppppppppppppppppppppp]
+    """)  # noqa
+    expected_formatted_code = textwrap.dedent("""\
+        _zzzzzzzzzzzzzzzzzzzz = Union[
+            sssssssssssssssssssss.pppppppppppppppp,
+            sssssssssssssssssssss.pppppppppppppppppppppppppppp]
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testB119300344(self):
-    code = """\
-def _GenerateStatsEntries(
-    process_id: Text,
-    timestamp: Optional[rdfvalue.RDFDatetime] = None
-) -> Sequence[stats_values.StatsStoreEntry]:
-  pass
-"""
+    code = textwrap.dedent("""\
+        def _GenerateStatsEntries(
+            process_id: Text,
+            timestamp: Optional[rdfvalue.RDFDatetime] = None
+        ) -> Sequence[stats_values.StatsStoreEntry]:
+          pass
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testB132886019(self):
-    code = """\
-X = {
-    'some_dict_key':
-        frozenset([
-            # pylint: disable=line-too-long
-            '//this/path/is/really/too/long/for/this/line/and/probably/should/be/split',
-        ]),
-}
-"""
+    code = textwrap.dedent("""\
+        X = {
+            'some_dict_key':
+                frozenset([
+                    # pylint: disable=line-too-long
+                    '//this/path/is/really/too/long/for/this/line/and/probably/should/be/split',
+                ]),
+        }
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testB26521719(self):
-    code = """\
-class _():
+    code = textwrap.dedent("""\
+        class _():
 
-  def _(self):
-    self.stubs.Set(some_type_of_arg, 'ThisIsAStringArgument',
-                   lambda *unused_args, **unused_kwargs: fake_resolver)
-"""
+          def _(self):
+            self.stubs.Set(some_type_of_arg, 'ThisIsAStringArgument',
+                           lambda *unused_args, **unused_kwargs: fake_resolver)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testB122541552(self):
-    code = """\
-# pylint: disable=g-explicit-bool-comparison,singleton-comparison
-_QUERY = account.Account.query(account.Account.enabled == True)
-# pylint: enable=g-explicit-bool-comparison,singleton-comparison
+    code = textwrap.dedent("""\
+        # pylint: disable=g-explicit-bool-comparison,singleton-comparison
+        _QUERY = account.Account.query(account.Account.enabled == True)
+        # pylint: enable=g-explicit-bool-comparison,singleton-comparison
 
 
-def _():
-  pass
-"""
+        def _():
+          pass
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testB124415889(self):
-    code = """\
-class _():
+    code = textwrap.dedent("""\
+        class _():
 
-  def run_queue_scanners():
-    return xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx(
-        {
-            components.NAME.FNOR: True,
-            components.NAME.DEVO: True,
-        },
-        default=False)
-
-  def modules_to_install():
-    modules = DeepCopy(GetDef({}))
-    modules.update({
-        'xxxxxxxxxxxxxxxxxxxx':
-            GetDef('zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz', None),
-    })
-    return modules
-"""
+          def run_queue_scanners():
+            return xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx(
+                {
+                    components.NAME.FNOR: True,
+                    components.NAME.DEVO: True,
+                },
+                default=False)
+
+          def modules_to_install():
+            modules = DeepCopy(GetDef({}))
+            modules.update({
+                'xxxxxxxxxxxxxxxxxxxx':
+                    GetDef('zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz', None),
+            })
+            return modules
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testB73166511(self):
-    code = """\
-def _():
-  if min_std is not None:
-    groundtruth_age_variances = tf.maximum(groundtruth_age_variances,
-                                           min_std**2)
-"""
+    code = textwrap.dedent("""\
+        def _():
+          if min_std is not None:
+            groundtruth_age_variances = tf.maximum(groundtruth_age_variances,
+                                                   min_std**2)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testB118624921(self):
-    code = """\
-def _():
-  function_call(
-      alert_name='xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
-      time_delta='1h',
-      alert_level='bbbbbbbb',
-      metric='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
-      bork=foo)
-"""
+    code = textwrap.dedent("""\
+        def _():
+          function_call(
+              alert_name='xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
+              time_delta='1h',
+              alert_level='bbbbbbbb',
+              metric='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
+              bork=foo)
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testB35417079(self):
-    code = """\
-class _():
-
-  def _():
-    X = (
-        _ares_label_prefix +
-        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'  # pylint: disable=line-too-long
-        'PyTypePyTypePyTypePyTypePyTypePyTypePyTypePyTypePyTypePyTypePyTypePyTypePyType'  # pytype: disable=attribute-error
-        'CopybaraCopybaraCopybaraCopybaraCopybaraCopybaraCopybaraCopybaraCopybara'  # copybara:strip
-    )
-"""  # noqa
+    code = textwrap.dedent("""\
+        class _():
+
+          def _():
+            X = (
+                _ares_label_prefix +
+                'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'  # pylint: disable=line-too-long
+                'PyTypePyTypePyTypePyTypePyTypePyTypePyTypePyTypePyTypePyTypePyTypePyTypePyType'  # pytype: disable=attribute-error
+                'CopybaraCopybaraCopybaraCopybaraCopybaraCopybaraCopybaraCopybaraCopybara'  # copybara:strip
+            )
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testB120047670(self):
-    unformatted_code = """\
-X = {
-    'NO_PING_COMPONENTS': [
-        79775,          # Releases / FOO API
-        79770,          # Releases / BAZ API
-        79780],         # Releases / MUX API
-
-    'PING_BLOCKED_BUGS': False,
-}
-"""
-    expected_formatted_code = """\
-X = {
-    'NO_PING_COMPONENTS': [
-        79775,  # Releases / FOO API
-        79770,  # Releases / BAZ API
-        79780
-    ],  # Releases / MUX API
-    'PING_BLOCKED_BUGS': False,
-}
-"""
+    unformatted_code = textwrap.dedent("""\
+        X = {
+            'NO_PING_COMPONENTS': [
+                79775,          # Releases / FOO API
+                79770,          # Releases / BAZ API
+                79780],         # Releases / MUX API
+
+            'PING_BLOCKED_BUGS': False,
+        }
+    """)
+    expected_formatted_code = textwrap.dedent("""\
+        X = {
+            'NO_PING_COMPONENTS': [
+                79775,  # Releases / FOO API
+                79770,  # Releases / BAZ API
+                79780
+            ],  # Releases / MUX API
+            'PING_BLOCKED_BUGS': False,
+        }
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testB120245013(self):
-    unformatted_code = """\
-class Foo(object):
-  def testNoAlertForShortPeriod(self, rutabaga):
-    self.targets[:][streamz_path,self._fillInOtherFields(streamz_path, {streamz_field_of_interest:True})] = series.Counter('1s', '+ 500x10000')
-"""  # noqa
-    expected_formatted_code = """\
-class Foo(object):
+    unformatted_code = textwrap.dedent("""\
+        class Foo(object):
+          def testNoAlertForShortPeriod(self, rutabaga):
+            self.targets[:][streamz_path,self._fillInOtherFields(streamz_path, {streamz_field_of_interest:True})] = series.Counter('1s', '+ 500x10000')
+    """)  # noqa
+    expected_formatted_code = textwrap.dedent("""\
+        class Foo(object):
 
-  def testNoAlertForShortPeriod(self, rutabaga):
-    self.targets[:][
-        streamz_path,
-        self._fillInOtherFields(streamz_path, {streamz_field_of_interest: True}
-                               )] = series.Counter('1s', '+ 500x10000')
-"""
+          def testNoAlertForShortPeriod(self, rutabaga):
+            self.targets[:][
+                streamz_path,
+                self._fillInOtherFields(streamz_path, {streamz_field_of_interest: True}
+                                       )] = series.Counter('1s', '+ 500x10000')
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testB117841880(self):
-    code = """\
-def xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx(
-    aaaaaaaaaaaaaaaaaaa: AnyStr,
-    bbbbbbbbbbbb: Optional[Sequence[AnyStr]] = None,
-    cccccccccc: AnyStr = cst.DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD,
-    dddddddddd: Sequence[SliceDimension] = (),
-    eeeeeeeeeeee: AnyStr = cst.DEFAULT_CONTROL_NAME,
-    ffffffffffffffffffff: Optional[Callable[[pd.DataFrame],
-                                            pd.DataFrame]] = None,
-    gggggggggggggg: ooooooooooooo = ooooooooooooo()
-) -> pd.DataFrame:
-  pass
-"""
+    code = textwrap.dedent("""\
+        def xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx(
+            aaaaaaaaaaaaaaaaaaa: AnyStr,
+            bbbbbbbbbbbb: Optional[Sequence[AnyStr]] = None,
+            cccccccccc: AnyStr = cst.DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD,
+            dddddddddd: Sequence[SliceDimension] = (),
+            eeeeeeeeeeee: AnyStr = cst.DEFAULT_CONTROL_NAME,
+            ffffffffffffffffffff: Optional[Callable[[pd.DataFrame],
+                                                    pd.DataFrame]] = None,
+            gggggggggggggg: ooooooooooooo = ooooooooooooo()
+        ) -> pd.DataFrame:
+          pass
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testB111764402(self):
-    unformatted_code = """\
-x = self.stubs.stub(video_classification_map,              'read_video_classifications',       (lambda external_ids, **unused_kwargs:                     {external_id: self._get_serving_classification('video') for external_id in external_ids}))
-"""  # noqa
-    expected_formatted_code = """\
-x = self.stubs.stub(video_classification_map, 'read_video_classifications',
-                    (lambda external_ids, **unused_kwargs: {
-                        external_id: self._get_serving_classification('video')
-                        for external_id in external_ids
-                    }))
-"""
+    unformatted_code = textwrap.dedent("""\
+        x = self.stubs.stub(video_classification_map,              'read_video_classifications',       (lambda external_ids, **unused_kwargs:                     {external_id: self._get_serving_classification('video') for external_id in external_ids}))
+    """)  # noqa
+    expected_formatted_code = textwrap.dedent("""\
+        x = self.stubs.stub(video_classification_map, 'read_video_classifications',
+                            (lambda external_ids, **unused_kwargs: {
+                                external_id: self._get_serving_classification('video')
+                                for external_id in external_ids
+                            }))
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testB116825060(self):
-    code = """\
-result_df = pd.DataFrame({LEARNED_CTR_COLUMN: learned_ctr},
-                         index=df_metrics.index)
-"""
+    code = textwrap.dedent("""\
+        result_df = pd.DataFrame({LEARNED_CTR_COLUMN: learned_ctr},
+                                 index=df_metrics.index)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testB112711217(self):
-    code = """\
-def _():
-  stats['moderated'] = ~stats.moderation_reason.isin(
-      approved_moderation_reasons)
-"""
+    code = textwrap.dedent("""\
+        def _():
+          stats['moderated'] = ~stats.moderation_reason.isin(
+              approved_moderation_reasons)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testB112867548(self):
-    unformatted_code = """\
-def _():
-  return flask.make_response(
-      'Records: {}, Problems: {}, More: {}'.format(
-          process_result.result_ct, process_result.problem_ct,
-          process_result.has_more),
-      httplib.ACCEPTED if process_result.has_more else httplib.OK,
-      {'content-type': _TEXT_CONTEXT_TYPE})
-"""
-    expected_formatted_code = """\
-def _():
-  return flask.make_response(
-      'Records: {}, Problems: {}, More: {}'.format(process_result.result_ct,
-                                                   process_result.problem_ct,
-                                                   process_result.has_more),
-      httplib.ACCEPTED if process_result.has_more else httplib.OK,
-      {'content-type': _TEXT_CONTEXT_TYPE})
-"""
+    unformatted_code = textwrap.dedent("""\
+        def _():
+          return flask.make_response(
+              'Records: {}, Problems: {}, More: {}'.format(
+                  process_result.result_ct, process_result.problem_ct,
+                  process_result.has_more),
+              httplib.ACCEPTED if process_result.has_more else httplib.OK,
+              {'content-type': _TEXT_CONTEXT_TYPE})
+    """)
+    expected_formatted_code = textwrap.dedent("""\
+        def _():
+          return flask.make_response(
+              'Records: {}, Problems: {}, More: {}'.format(process_result.result_ct,
+                                                           process_result.problem_ct,
+                                                           process_result.has_more),
+              httplib.ACCEPTED if process_result.has_more else httplib.OK,
+              {'content-type': _TEXT_CONTEXT_TYPE})
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testB112651423(self):
-    unformatted_code = """\
-def potato(feeditems, browse_use_case=None):
-  for item in turnip:
-    if kumquat:
-      if not feeds_variants.variants['FEEDS_LOAD_PLAYLIST_VIDEOS_FOR_ALL_ITEMS'] and item.video:
-        continue
-"""  # noqa
-    expected_formatted_code = """\
-def potato(feeditems, browse_use_case=None):
-  for item in turnip:
-    if kumquat:
-      if not feeds_variants.variants[
-          'FEEDS_LOAD_PLAYLIST_VIDEOS_FOR_ALL_ITEMS'] and item.video:
-        continue
-"""
+    unformatted_code = textwrap.dedent("""\
+        def potato(feeditems, browse_use_case=None):
+          for item in turnip:
+            if kumquat:
+              if not feeds_variants.variants['FEEDS_LOAD_PLAYLIST_VIDEOS_FOR_ALL_ITEMS'] and item.video:
+                continue
+    """)  # noqa
+    expected_formatted_code = textwrap.dedent("""\
+        def potato(feeditems, browse_use_case=None):
+          for item in turnip:
+            if kumquat:
+              if not feeds_variants.variants[
+                  'FEEDS_LOAD_PLAYLIST_VIDEOS_FOR_ALL_ITEMS'] and item.video:
+                continue
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testB80484938(self):
-    code = """\
-for sssssss, aaaaaaaaaa in [
-    ('ssssssssssssssssssss', 'sssssssssssssssssssssssss'),
-    ('nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn',
-     'nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn'),
-    ('pppppppppppppppppppppppppppp', 'pppppppppppppppppppppppppppppppp'),
-    ('wwwwwwwwwwwwwwwwwwww', 'wwwwwwwwwwwwwwwwwwwwwwwww'),
-    ('sssssssssssssssss', 'sssssssssssssssssssssss'),
-    ('ggggggggggggggggggggggg', 'gggggggggggggggggggggggggggg'),
-    ('ggggggggggggggggg', 'gggggggggggggggggggggg'),
-    ('eeeeeeeeeeeeeeeeeeeeee', 'eeeeeeeeeeeeeeeeeeeeeeeeeee')
-]:
-  pass
-
-for sssssss, aaaaaaaaaa in [
-    ('ssssssssssssssssssss', 'sssssssssssssssssssssssss'),
-    ('nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn', 'nnnnnnnnnnnnnnnnnnnnnnnnn'),
-    ('pppppppppppppppppppppppppppp', 'pppppppppppppppppppppppppppppppp'),
-    ('wwwwwwwwwwwwwwwwwwww', 'wwwwwwwwwwwwwwwwwwwwwwwww'),
-    ('sssssssssssssssss', 'sssssssssssssssssssssss'),
-    ('ggggggggggggggggggggggg', 'gggggggggggggggggggggggggggg'),
-    ('ggggggggggggggggg', 'gggggggggggggggggggggg'),
-    ('eeeeeeeeeeeeeeeeeeeeee', 'eeeeeeeeeeeeeeeeeeeeeeeeeee')
-]:
-  pass
-
-for sssssss, aaaaaaaaaa in [
-    ('ssssssssssssssssssss', 'sssssssssssssssssssssssss'),
-    ('nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn',
-     'nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn'),
-    ('pppppppppppppppppppppppppppp', 'pppppppppppppppppppppppppppppppp'),
-    ('wwwwwwwwwwwwwwwwwwww', 'wwwwwwwwwwwwwwwwwwwwwwwww'),
-    ('sssssssssssssssss', 'sssssssssssssssssssssss'),
-    ('ggggggggggggggggggggggg', 'gggggggggggggggggggggggggggg'),
-    ('ggggggggggggggggg', 'gggggggggggggggggggggg'),
-    ('eeeeeeeeeeeeeeeeeeeeee', 'eeeeeeeeeeeeeeeeeeeeeeeeeee'),
-]:
-  pass
-"""
+    code = textwrap.dedent("""\
+        for sssssss, aaaaaaaaaa in [
+            ('ssssssssssssssssssss', 'sssssssssssssssssssssssss'),
+            ('nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn',
+             'nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn'),
+            ('pppppppppppppppppppppppppppp', 'pppppppppppppppppppppppppppppppp'),
+            ('wwwwwwwwwwwwwwwwwwww', 'wwwwwwwwwwwwwwwwwwwwwwwww'),
+            ('sssssssssssssssss', 'sssssssssssssssssssssss'),
+            ('ggggggggggggggggggggggg', 'gggggggggggggggggggggggggggg'),
+            ('ggggggggggggggggg', 'gggggggggggggggggggggg'),
+            ('eeeeeeeeeeeeeeeeeeeeee', 'eeeeeeeeeeeeeeeeeeeeeeeeeee')
+        ]:
+          pass
+
+        for sssssss, aaaaaaaaaa in [
+            ('ssssssssssssssssssss', 'sssssssssssssssssssssssss'),
+            ('nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn', 'nnnnnnnnnnnnnnnnnnnnnnnnn'),
+            ('pppppppppppppppppppppppppppp', 'pppppppppppppppppppppppppppppppp'),
+            ('wwwwwwwwwwwwwwwwwwww', 'wwwwwwwwwwwwwwwwwwwwwwwww'),
+            ('sssssssssssssssss', 'sssssssssssssssssssssss'),
+            ('ggggggggggggggggggggggg', 'gggggggggggggggggggggggggggg'),
+            ('ggggggggggggggggg', 'gggggggggggggggggggggg'),
+            ('eeeeeeeeeeeeeeeeeeeeee', 'eeeeeeeeeeeeeeeeeeeeeeeeeee')
+        ]:
+          pass
+
+        for sssssss, aaaaaaaaaa in [
+            ('ssssssssssssssssssss', 'sssssssssssssssssssssssss'),
+            ('nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn',
+             'nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn'),
+            ('pppppppppppppppppppppppppppp', 'pppppppppppppppppppppppppppppppp'),
+            ('wwwwwwwwwwwwwwwwwwww', 'wwwwwwwwwwwwwwwwwwwwwwwww'),
+            ('sssssssssssssssss', 'sssssssssssssssssssssss'),
+            ('ggggggggggggggggggggggg', 'gggggggggggggggggggggggggggg'),
+            ('ggggggggggggggggg', 'gggggggggggggggggggggg'),
+            ('eeeeeeeeeeeeeeeeeeeeee', 'eeeeeeeeeeeeeeeeeeeeeeeeeee'),
+        ]:
+          pass
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testB120771563(self):
-    code = """\
-class A:
-
-  def b():
-    d = {
-        "123456": [{
-            "12": "aa"
-        }, {
-            "12": "bb"
-        }, {
-            "12": "cc",
-            "1234567890": {
-                "1234567": [{
-                    "12": "dd",
-                    "12345": "text 1"
+    code = textwrap.dedent("""\
+        class A:
+
+          def b():
+            d = {
+                "123456": [{
+                    "12": "aa"
                 }, {
-                    "12": "ee",
-                    "12345": "text 2"
+                    "12": "bb"
+                }, {
+                    "12": "cc",
+                    "1234567890": {
+                        "1234567": [{
+                            "12": "dd",
+                            "12345": "text 1"
+                        }, {
+                            "12": "ee",
+                            "12345": "text 2"
+                        }]
+                    }
                 }]
             }
-        }]
-    }
-"""
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testB79462249(self):
-    code = """\
-foo.bar(baz, [
-    quux(thud=42),
-    norf,
-])
-foo.bar(baz, [
-    quux(),
-    norf,
-])
-foo.bar(baz, quux(thud=42), aaaaaaaaaaaaaaaaaaaaaa, bbbbbbbbbbbbbbbbbbbbb,
-        ccccccccccccccccccc)
-foo.bar(
-    baz,
-    quux(thud=42),
-    aaaaaaaaaaaaaaaaaaaaaa=1,
-    bbbbbbbbbbbbbbbbbbbbb=2,
-    ccccccccccccccccccc=3)
-"""
+    code = textwrap.dedent("""\
+        foo.bar(baz, [
+            quux(thud=42),
+            norf,
+        ])
+        foo.bar(baz, [
+            quux(),
+            norf,
+        ])
+        foo.bar(baz, quux(thud=42), aaaaaaaaaaaaaaaaaaaaaa, bbbbbbbbbbbbbbbbbbbbb,
+                ccccccccccccccccccc)
+        foo.bar(
+            baz,
+            quux(thud=42),
+            aaaaaaaaaaaaaaaaaaaaaa=1,
+            bbbbbbbbbbbbbbbbbbbbb=2,
+            ccccccccccccccccccc=3)
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testB113210278(self):
-    unformatted_code = """\
-def _():
-  aaaaaaaaaaa = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.cccccccccccccccccccccccccccc(\
-eeeeeeeeeeeeeeeeeeeeeeeeee.fffffffffffffffffffffffffffffffffffffff.\
-ggggggggggggggggggggggggggggggggg.hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh())
-"""  # noqa
-    expected_formatted_code = """\
-def _():
-  aaaaaaaaaaa = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.cccccccccccccccccccccccccccc(
-      eeeeeeeeeeeeeeeeeeeeeeeeee.fffffffffffffffffffffffffffffffffffffff
-      .ggggggggggggggggggggggggggggggggg.hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh())
-"""  # noqa
+    unformatted_code = textwrap.dedent("""\
+        def _():
+          aaaaaaaaaaa = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.cccccccccccccccccccccccccccc(\
+        eeeeeeeeeeeeeeeeeeeeeeeeee.fffffffffffffffffffffffffffffffffffffff.\
+        ggggggggggggggggggggggggggggggggg.hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh())
+    """)  # noqa
+    expected_formatted_code = textwrap.dedent("""\
+        def _():
+          aaaaaaaaaaa = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.cccccccccccccccccccccccccccc(
+              eeeeeeeeeeeeeeeeeeeeeeeeee.fffffffffffffffffffffffffffffffffffffff
+              .ggggggggggggggggggggggggggggggggg.hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh())
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testB77923341(self):
-    code = """\
-def f():
-  if (aaaaaaaaaaaaaa.bbbbbbbbbbbb.ccccc <= 0 and  # pytype: disable=attribute-error
-      ddddddddddd.eeeeeeeee == constants.FFFFFFFFFFFFFF):
-    raise "yo"
-"""  # noqa
+    code = textwrap.dedent("""\
+        def f():
+          if (aaaaaaaaaaaaaa.bbbbbbbbbbbb.ccccc <= 0 and  # pytype: disable=attribute-error
+              ddddddddddd.eeeeeeeee == constants.FFFFFFFFFFFFFF):
+            raise "yo"
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testB77329955(self):
-    code = """\
-class _():
-
-  @parameterized.named_parameters(
-      ('ReadyExpiredSuccess', True, True, True, None, None),
-      ('SpannerUpdateFails', True, False, True, None, None),
-      ('ReadyNotExpired', False, True, True, True, None),
-      # ('ReadyNotExpiredNotHealthy', False, True, True, False, True),
-      # ('ReadyNotExpiredNotHealthyErrorFails', False, True, True, False, False
-      # ('ReadyNotExpiredNotHealthyUpdateFails', False, False, True, False, True
-  )
-  def _():
-    pass
-"""
+    code = textwrap.dedent("""\
+        class _():
+
+          @parameterized.named_parameters(
+              ('ReadyExpiredSuccess', True, True, True, None, None),
+              ('SpannerUpdateFails', True, False, True, None, None),
+              ('ReadyNotExpired', False, True, True, True, None),
+              # ('ReadyNotExpiredNotHealthy', False, True, True, False, True),
+              # ('ReadyNotExpiredNotHealthyErrorFails', False, True, True, False, False
+              # ('ReadyNotExpiredNotHealthyUpdateFails', False, False, True, False, True
+          )
+          def _():
+            pass
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testB65197969(self):
-    unformatted_code = """\
-class _():
+    unformatted_code = textwrap.dedent("""\
+        class _():
 
-  def _():
-    return timedelta(seconds=max(float(time_scale), small_interval) *
-                   1.41 ** min(num_attempts, 9))
-"""
-    expected_formatted_code = """\
-class _():
+          def _():
+            return timedelta(seconds=max(float(time_scale), small_interval) *
+                           1.41 ** min(num_attempts, 9))
+    """)
+    expected_formatted_code = textwrap.dedent("""\
+        class _():
 
-  def _():
-    return timedelta(
-        seconds=max(float(time_scale), small_interval) *
-        1.41**min(num_attempts, 9))
-"""
+          def _():
+            return timedelta(
+                seconds=max(float(time_scale), small_interval) *
+                1.41**min(num_attempts, 9))
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testB65546221(self):
-    unformatted_code = """\
-SUPPORTED_PLATFORMS = (
-    "centos-6",
-    "centos-7",
-    "ubuntu-1204-precise",
-    "ubuntu-1404-trusty",
-    "ubuntu-1604-xenial",
-    "debian-7-wheezy",
-    "debian-8-jessie",
-    "debian-9-stretch",)
-"""
-    expected_formatted_code = """\
-SUPPORTED_PLATFORMS = (
-    "centos-6",
-    "centos-7",
-    "ubuntu-1204-precise",
-    "ubuntu-1404-trusty",
-    "ubuntu-1604-xenial",
-    "debian-7-wheezy",
-    "debian-8-jessie",
-    "debian-9-stretch",
-)
-"""
+    unformatted_code = textwrap.dedent("""\
+        SUPPORTED_PLATFORMS = (
+            "centos-6",
+            "centos-7",
+            "ubuntu-1204-precise",
+            "ubuntu-1404-trusty",
+            "ubuntu-1604-xenial",
+            "debian-7-wheezy",
+            "debian-8-jessie",
+            "debian-9-stretch",)
+    """)
+    expected_formatted_code = textwrap.dedent("""\
+        SUPPORTED_PLATFORMS = (
+            "centos-6",
+            "centos-7",
+            "ubuntu-1204-precise",
+            "ubuntu-1404-trusty",
+            "ubuntu-1604-xenial",
+            "debian-7-wheezy",
+            "debian-8-jessie",
+            "debian-9-stretch",
+        )
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testB30500455(self):
-    unformatted_code = """\
-INITIAL_SYMTAB = dict([(name, 'exception#' + name) for name in INITIAL_EXCEPTIONS
-] * [(name, 'type#' + name) for name in INITIAL_TYPES] + [
-    (name, 'function#' + name) for name in INITIAL_FUNCTIONS
-] + [(name, 'const#' + name) for name in INITIAL_CONSTS])
-"""  # noqa
-    expected_formatted_code = """\
-INITIAL_SYMTAB = dict(
-    [(name, 'exception#' + name) for name in INITIAL_EXCEPTIONS] *
-    [(name, 'type#' + name) for name in INITIAL_TYPES] +
-    [(name, 'function#' + name) for name in INITIAL_FUNCTIONS] +
-    [(name, 'const#' + name) for name in INITIAL_CONSTS])
-"""
+    unformatted_code = textwrap.dedent("""\
+        INITIAL_SYMTAB = dict([(name, 'exception#' + name) for name in INITIAL_EXCEPTIONS
+        ] * [(name, 'type#' + name) for name in INITIAL_TYPES] + [
+            (name, 'function#' + name) for name in INITIAL_FUNCTIONS
+        ] + [(name, 'const#' + name) for name in INITIAL_CONSTS])
+    """)  # noqa
+    expected_formatted_code = textwrap.dedent("""\
+        INITIAL_SYMTAB = dict(
+            [(name, 'exception#' + name) for name in INITIAL_EXCEPTIONS] *
+            [(name, 'type#' + name) for name in INITIAL_TYPES] +
+            [(name, 'function#' + name) for name in INITIAL_FUNCTIONS] +
+            [(name, 'const#' + name) for name in INITIAL_CONSTS])
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testB38343525(self):
-    code = """\
-# This does foo.
-@arg.String('some_path_to_a_file', required=True)
-# This does bar.
-@arg.String('some_path_to_a_file', required=True)
-def f():
-  print 1
-"""
+    code = textwrap.dedent("""\
+        # This does foo.
+        @arg.String('some_path_to_a_file', required=True)
+        # This does bar.
+        @arg.String('some_path_to_a_file', required=True)
+        def f():
+          print(1)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testB37099651(self):
-    unformatted_code = """\
-_MEMCACHE = lazy.MakeLazy(
-    # pylint: disable=g-long-lambda
-    lambda: function.call.mem.clients(FLAGS.some_flag_thingy, default_namespace=_LAZY_MEM_NAMESPACE, allow_pickle=True)
-    # pylint: enable=g-long-lambda
-)
-"""  # noqa
-    expected_formatted_code = """\
-_MEMCACHE = lazy.MakeLazy(
-    # pylint: disable=g-long-lambda
-    lambda: function.call.mem.clients(
-        FLAGS.some_flag_thingy,
-        default_namespace=_LAZY_MEM_NAMESPACE,
-        allow_pickle=True)
-    # pylint: enable=g-long-lambda
-)
-"""
+    unformatted_code = textwrap.dedent("""\
+        _MEMCACHE = lazy.MakeLazy(
+            # pylint: disable=g-long-lambda
+            lambda: function.call.mem.clients(FLAGS.some_flag_thingy, default_namespace=_LAZY_MEM_NAMESPACE, allow_pickle=True)
+            # pylint: enable=g-long-lambda
+        )
+    """)  # noqa
+    expected_formatted_code = textwrap.dedent("""\
+        _MEMCACHE = lazy.MakeLazy(
+            # pylint: disable=g-long-lambda
+            lambda: function.call.mem.clients(
+                FLAGS.some_flag_thingy,
+                default_namespace=_LAZY_MEM_NAMESPACE,
+                allow_pickle=True)
+            # pylint: enable=g-long-lambda
+        )
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testB33228502(self):
-    unformatted_code = """\
-def _():
-  success_rate_stream_table = module.Precompute(
-      query_function=module.DefineQueryFunction(
-          name='Response error ratio',
-          expression=((m.Fetch(
-                  m.Raw('monarch.BorgTask',
-                        '/corp/travel/trips2/dispatcher/email/response'),
-                  {'borg_job': module_config.job, 'metric:response_type': 'SUCCESS'}),
-               m.Fetch(m.Raw('monarch.BorgTask', '/corp/travel/trips2/dispatcher/email/response'), {'borg_job': module_config.job}))
-              | m.Window(m.Delta('1h'))
-              | m.Join('successes', 'total')
-              | m.Point(m.VAL['successes'] / m.VAL['total']))))
-"""  # noqa
-    expected_formatted_code = """\
-def _():
-  success_rate_stream_table = module.Precompute(
-      query_function=module.DefineQueryFunction(
-          name='Response error ratio',
-          expression=(
-              (m.Fetch(
-                  m.Raw('monarch.BorgTask',
-                        '/corp/travel/trips2/dispatcher/email/response'), {
-                            'borg_job': module_config.job,
-                            'metric:response_type': 'SUCCESS'
-                        }),
-               m.Fetch(
-                   m.Raw('monarch.BorgTask',
-                         '/corp/travel/trips2/dispatcher/email/response'),
-                   {'borg_job': module_config.job}))
-              | m.Window(m.Delta('1h'))
-              | m.Join('successes', 'total')
-              | m.Point(m.VAL['successes'] / m.VAL['total']))))
-"""
+    unformatted_code = textwrap.dedent("""\
+        def _():
+          success_rate_stream_table = module.Precompute(
+              query_function=module.DefineQueryFunction(
+                  name='Response error ratio',
+                  expression=((m.Fetch(
+                          m.Raw('monarch.BorgTask',
+                                '/corp/travel/trips2/dispatcher/email/response'),
+                          {'borg_job': module_config.job, 'metric:response_type': 'SUCCESS'}),
+                       m.Fetch(m.Raw('monarch.BorgTask', '/corp/travel/trips2/dispatcher/email/response'), {'borg_job': module_config.job}))
+                      | m.Window(m.Delta('1h'))
+                      | m.Join('successes', 'total')
+                      | m.Point(m.VAL['successes'] / m.VAL['total']))))
+    """)  # noqa
+    expected_formatted_code = textwrap.dedent("""\
+        def _():
+          success_rate_stream_table = module.Precompute(
+              query_function=module.DefineQueryFunction(
+                  name='Response error ratio',
+                  expression=(
+                      (m.Fetch(
+                          m.Raw('monarch.BorgTask',
+                                '/corp/travel/trips2/dispatcher/email/response'), {
+                                    'borg_job': module_config.job,
+                                    'metric:response_type': 'SUCCESS'
+                                }),
+                       m.Fetch(
+                           m.Raw('monarch.BorgTask',
+                                 '/corp/travel/trips2/dispatcher/email/response'),
+                           {'borg_job': module_config.job}))
+                      | m.Window(m.Delta('1h'))
+                      | m.Join('successes', 'total')
+                      | m.Point(m.VAL['successes'] / m.VAL['total']))))
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testB30394228(self):
-    code = """\
-class _():
-
-  def _(self):
-    return some.randome.function.calling(
-        wf, None, alert.Format(alert.subject, alert=alert, threshold=threshold),
-        alert.Format(alert.body, alert=alert, threshold=threshold),
-        alert.html_formatting)
-"""
+    code = textwrap.dedent("""\
+        class _():
+
+          def _(self):
+            return some.randome.function.calling(
+                wf, None, alert.Format(alert.subject, alert=alert, threshold=threshold),
+                alert.Format(alert.body, alert=alert, threshold=threshold),
+                alert.html_formatting)
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testB65246454(self):
-    unformatted_code = """\
-class _():
+    unformatted_code = textwrap.dedent("""\
+        class _():
 
-  def _(self):
-    self.assertEqual({i.id
-                      for i in successful_instances},
-                     {i.id
-                      for i in self._statuses.successful_instances})
-"""
-    expected_formatted_code = """\
-class _():
+          def _(self):
+            self.assertEqual({i.id
+                              for i in successful_instances},
+                             {i.id
+                              for i in self._statuses.successful_instances})
+    """)  # noqa
+    expected_formatted_code = textwrap.dedent("""\
+        class _():
 
-  def _(self):
-    self.assertEqual({i.id for i in successful_instances},
-                     {i.id for i in self._statuses.successful_instances})
-"""
+          def _(self):
+            self.assertEqual({i.id for i in successful_instances},
+                             {i.id for i in self._statuses.successful_instances})
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testB67935450(self):
-    unformatted_code = """\
-def _():
-  return (
-      (Gauge(
-          metric='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
-          group_by=group_by + ['metric:process_name'],
-          metric_filter={'metric:process_name': process_name_re}),
-       Gauge(
-           metric='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
-           group_by=group_by + ['metric:process_name'],
-           metric_filter={'metric:process_name': process_name_re}))
-      | expr.Join(
-          left_name='start', left_default=0, right_name='end', right_default=0)
-      | m.Point(
-          m.Cond(m.VAL['end'] != 0, m.VAL['end'], k.TimestampMicros() /
-                 1000000L) - m.Cond(m.VAL['start'] != 0, m.VAL['start'],
-                                    m.TimestampMicros() / 1000000L)))
-"""
-    expected_formatted_code = """\
-def _():
-  return (
-      (Gauge(
-          metric='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
-          group_by=group_by + ['metric:process_name'],
-          metric_filter={'metric:process_name': process_name_re}),
-       Gauge(
-           metric='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
-           group_by=group_by + ['metric:process_name'],
-           metric_filter={'metric:process_name': process_name_re}))
-      | expr.Join(
-          left_name='start', left_default=0, right_name='end', right_default=0)
-      | m.Point(
-          m.Cond(m.VAL['end'] != 0, m.VAL['end'],
-                 k.TimestampMicros() / 1000000L) -
-          m.Cond(m.VAL['start'] != 0, m.VAL['start'],
-                 m.TimestampMicros() / 1000000L)))
-"""
+    unformatted_code = textwrap.dedent("""\
+        def _():
+          return (
+              (Gauge(
+                  metric='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
+                  group_by=group_by + ['metric:process_name'],
+                  metric_filter={'metric:process_name': process_name_re}),
+               Gauge(
+                   metric='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
+                   group_by=group_by + ['metric:process_name'],
+                   metric_filter={'metric:process_name': process_name_re}))
+              | expr.Join(
+                  left_name='start', left_default=0, right_name='end', right_default=0)
+              | m.Point(
+                  m.Cond(m.VAL['end'] != 0, m.VAL['end'], k.TimestampMicros() /
+                         1000000L) - m.Cond(m.VAL['start'] != 0, m.VAL['start'],
+                                            m.TimestampMicros() / 1000000L)))
+    """)  # noqa
+    expected_formatted_code = textwrap.dedent("""\
+        def _():
+          return (
+              (Gauge(
+                  metric='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
+                  group_by=group_by + ['metric:process_name'],
+                  metric_filter={'metric:process_name': process_name_re}),
+               Gauge(
+                   metric='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
+                   group_by=group_by + ['metric:process_name'],
+                   metric_filter={'metric:process_name': process_name_re}))
+              | expr.Join(
+                  left_name='start', left_default=0, right_name='end', right_default=0)
+              | m.Point(
+                  m.Cond(m.VAL['end'] != 0, m.VAL['end'],
+                         k.TimestampMicros() / 1000000L) -
+                  m.Cond(m.VAL['start'] != 0, m.VAL['start'],
+                         m.TimestampMicros() / 1000000L)))
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testB66011084(self):
-    unformatted_code = """\
-X = {
-"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":  # Comment 1.
-([] if True else [ # Comment 2.
-    "bbbbbbbbbbbbbbbbbbb",  # Comment 3.
-    "cccccccccccccccccccccccc", # Comment 4.
-    "ddddddddddddddddddddddddd", # Comment 5.
-    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", # Comment 6.
-    "fffffffffffffffffffffffffffffff", # Comment 7.
-    "ggggggggggggggggggggggggggg", # Comment 8.
-    "hhhhhhhhhhhhhhhhhh",  # Comment 9.
-]),
-}
-"""
-    expected_formatted_code = """\
-X = {
-    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":  # Comment 1.
-        ([] if True else [  # Comment 2.
+    unformatted_code = textwrap.dedent("""\
+        X = {
+        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":  # Comment 1.
+        ([] if True else [ # Comment 2.
             "bbbbbbbbbbbbbbbbbbb",  # Comment 3.
-            "cccccccccccccccccccccccc",  # Comment 4.
-            "ddddddddddddddddddddddddd",  # Comment 5.
-            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",  # Comment 6.
-            "fffffffffffffffffffffffffffffff",  # Comment 7.
-            "ggggggggggggggggggggggggggg",  # Comment 8.
+            "cccccccccccccccccccccccc", # Comment 4.
+            "ddddddddddddddddddddddddd", # Comment 5.
+            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", # Comment 6.
+            "fffffffffffffffffffffffffffffff", # Comment 7.
+            "ggggggggggggggggggggggggggg", # Comment 8.
             "hhhhhhhhhhhhhhhhhh",  # Comment 9.
         ]),
-}
-"""
+        }
+    """)
+    expected_formatted_code = textwrap.dedent("""\
+        X = {
+            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":  # Comment 1.
+                ([] if True else [  # Comment 2.
+                    "bbbbbbbbbbbbbbbbbbb",  # Comment 3.
+                    "cccccccccccccccccccccccc",  # Comment 4.
+                    "ddddddddddddddddddddddddd",  # Comment 5.
+                    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",  # Comment 6.
+                    "fffffffffffffffffffffffffffffff",  # Comment 7.
+                    "ggggggggggggggggggggggggggg",  # Comment 8.
+                    "hhhhhhhhhhhhhhhhhh",  # Comment 9.
+                ]),
+        }
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testB67455376(self):
-    unformatted_code = """\
-sponge_ids.extend(invocation.id() for invocation in self._client.GetInvocationsByLabels(labels))
-"""  # noqa
-    expected_formatted_code = """\
-sponge_ids.extend(invocation.id()
-                  for invocation in self._client.GetInvocationsByLabels(labels))
-"""
+    unformatted_code = textwrap.dedent("""\
+        sponge_ids.extend(invocation.id() for invocation in self._client.GetInvocationsByLabels(labels))
+    """)  # noqa
+    expected_formatted_code = textwrap.dedent("""\
+        sponge_ids.extend(invocation.id()
+                          for invocation in self._client.GetInvocationsByLabels(labels))
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testB35210351(self):
-    unformatted_code = """\
-def _():
-  config.AnotherRuleThing(
-      'the_title_to_the_thing_here',
-      {'monitorname': 'firefly',
-       'service': ACCOUNTING_THING,
-       'severity': 'the_bug',
-       'monarch_module_name': alerts.TheLabel(qa_module_regexp, invert=True)},
-      fanout,
-      alerts.AlertUsToSomething(
-          GetTheAlertToIt('the_title_to_the_thing_here'),
-          GetNotificationTemplate('your_email_here')))
-"""
-    expected_formatted_code = """\
-def _():
-  config.AnotherRuleThing(
-      'the_title_to_the_thing_here', {
-          'monitorname': 'firefly',
-          'service': ACCOUNTING_THING,
-          'severity': 'the_bug',
-          'monarch_module_name': alerts.TheLabel(qa_module_regexp, invert=True)
-      }, fanout,
-      alerts.AlertUsToSomething(
-          GetTheAlertToIt('the_title_to_the_thing_here'),
-          GetNotificationTemplate('your_email_here')))
-"""
+    unformatted_code = textwrap.dedent("""\
+        def _():
+          config.AnotherRuleThing(
+              'the_title_to_the_thing_here',
+              {'monitorname': 'firefly',
+               'service': ACCOUNTING_THING,
+               'severity': 'the_bug',
+               'monarch_module_name': alerts.TheLabel(qa_module_regexp, invert=True)},
+              fanout,
+              alerts.AlertUsToSomething(
+                  GetTheAlertToIt('the_title_to_the_thing_here'),
+                  GetNotificationTemplate('your_email_here')))
+    """)  # noqa
+    expected_formatted_code = textwrap.dedent("""\
+        def _():
+          config.AnotherRuleThing(
+              'the_title_to_the_thing_here', {
+                  'monitorname': 'firefly',
+                  'service': ACCOUNTING_THING,
+                  'severity': 'the_bug',
+                  'monarch_module_name': alerts.TheLabel(qa_module_regexp, invert=True)
+              }, fanout,
+              alerts.AlertUsToSomething(
+                  GetTheAlertToIt('the_title_to_the_thing_here'),
+                  GetNotificationTemplate('your_email_here')))
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testB34774905(self):
-    unformatted_code = """\
-x=[VarExprType(ir_name=IrName( value='x',
-expr_type=UnresolvedAttrExprType( atom=UnknownExprType(), attr_name=IrName(
-    value='x', expr_type=UnknownExprType(), usage='UNKNOWN', fqn=None,
-    astn=None), usage='REF'), usage='ATTR', fqn='<attr>.x', astn=None))]
-"""
-    expected_formatted_code = """\
-x = [
-    VarExprType(
-        ir_name=IrName(
-            value='x',
-            expr_type=UnresolvedAttrExprType(
-                atom=UnknownExprType(),
-                attr_name=IrName(
+    unformatted_code = textwrap.dedent("""\
+        x=[VarExprType(ir_name=IrName( value='x',
+        expr_type=UnresolvedAttrExprType( atom=UnknownExprType(), attr_name=IrName(
+            value='x', expr_type=UnknownExprType(), usage='UNKNOWN', fqn=None,
+            astn=None), usage='REF'), usage='ATTR', fqn='<attr>.x', astn=None))]
+    """)  # noqa
+    expected_formatted_code = textwrap.dedent("""\
+        x = [
+            VarExprType(
+                ir_name=IrName(
                     value='x',
-                    expr_type=UnknownExprType(),
-                    usage='UNKNOWN',
-                    fqn=None,
-                    astn=None),
-                usage='REF'),
-            usage='ATTR',
-            fqn='<attr>.x',
-            astn=None))
-]
-"""
+                    expr_type=UnresolvedAttrExprType(
+                        atom=UnknownExprType(),
+                        attr_name=IrName(
+                            value='x',
+                            expr_type=UnknownExprType(),
+                            usage='UNKNOWN',
+                            fqn=None,
+                            astn=None),
+                        usage='REF'),
+                    usage='ATTR',
+                    fqn='<attr>.x',
+                    astn=None))
+        ]
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testB65176185(self):
-    code = """\
-xx = zip(*[(a, b) for (a, b, c) in yy])
-"""
+    code = textwrap.dedent("""\
+        xx = zip(*[(a, b) for (a, b, c) in yy])
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testB35210166(self):
-    unformatted_code = """\
-def _():
-  query = (
-      m.Fetch(n.Raw('monarch.BorgTask', '/proc/container/memory/usage'), { 'borg_user': borguser, 'borg_job': jobname })
-      | o.Window(m.Align('5m')) | p.GroupBy(['borg_user', 'borg_job', 'borg_cell'], q.Mean()))
-"""  # noqa
-    expected_formatted_code = """\
-def _():
-  query = (
-      m.Fetch(
-          n.Raw('monarch.BorgTask', '/proc/container/memory/usage'), {
-              'borg_user': borguser,
-              'borg_job': jobname
-          })
-      | o.Window(m.Align('5m'))
-      | p.GroupBy(['borg_user', 'borg_job', 'borg_cell'], q.Mean()))
-"""
+    unformatted_code = textwrap.dedent("""\
+        def _():
+          query = (
+              m.Fetch(n.Raw('monarch.BorgTask', '/proc/container/memory/usage'), { 'borg_user': borguser, 'borg_job': jobname })
+              | o.Window(m.Align('5m')) | p.GroupBy(['borg_user', 'borg_job', 'borg_cell'], q.Mean()))
+    """)  # noqa
+    expected_formatted_code = textwrap.dedent("""\
+        def _():
+          query = (
+              m.Fetch(
+                  n.Raw('monarch.BorgTask', '/proc/container/memory/usage'), {
+                      'borg_user': borguser,
+                      'borg_job': jobname
+                  })
+              | o.Window(m.Align('5m'))
+              | p.GroupBy(['borg_user', 'borg_job', 'borg_cell'], q.Mean()))
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testB32167774(self):
-    unformatted_code = """\
-X = (
-    'is_official',
-    'is_cover',
-    'is_remix',
-    'is_instrumental',
-    'is_live',
-    'has_lyrics',
-    'is_album',
-    'is_compilation',)
-"""
-    expected_formatted_code = """\
-X = (
-    'is_official',
-    'is_cover',
-    'is_remix',
-    'is_instrumental',
-    'is_live',
-    'has_lyrics',
-    'is_album',
-    'is_compilation',
-)
-"""
+    unformatted_code = textwrap.dedent("""\
+        X = (
+            'is_official',
+            'is_cover',
+            'is_remix',
+            'is_instrumental',
+            'is_live',
+            'has_lyrics',
+            'is_album',
+            'is_compilation',)
+    """)
+    expected_formatted_code = textwrap.dedent("""\
+        X = (
+            'is_official',
+            'is_cover',
+            'is_remix',
+            'is_instrumental',
+            'is_live',
+            'has_lyrics',
+            'is_album',
+            'is_compilation',
+        )
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testB66912275(self):
-    unformatted_code = """\
-def _():
-  with self.assertRaisesRegexp(errors.HttpError, 'Invalid'):
-    patch_op = api_client.forwardingRules().patch(
-        project=project_id,
-        region=region,
-        forwardingRule=rule_name,
-        body={'fingerprint': base64.urlsafe_b64encode('invalid_fingerprint')}).execute()
-"""  # noqa
-    expected_formatted_code = """\
-def _():
-  with self.assertRaisesRegexp(errors.HttpError, 'Invalid'):
-    patch_op = api_client.forwardingRules().patch(
-        project=project_id,
-        region=region,
-        forwardingRule=rule_name,
-        body={
-            'fingerprint': base64.urlsafe_b64encode('invalid_fingerprint')
-        }).execute()
-"""
+    unformatted_code = textwrap.dedent("""\
+        def _():
+          with self.assertRaisesRegexp(errors.HttpError, 'Invalid'):
+            patch_op = api_client.forwardingRules().patch(
+                project=project_id,
+                region=region,
+                forwardingRule=rule_name,
+                body={'fingerprint': base64.urlsafe_b64encode('invalid_fingerprint')}).execute()
+    """)  # noqa
+    expected_formatted_code = textwrap.dedent("""\
+        def _():
+          with self.assertRaisesRegexp(errors.HttpError, 'Invalid'):
+            patch_op = api_client.forwardingRules().patch(
+                project=project_id,
+                region=region,
+                forwardingRule=rule_name,
+                body={
+                    'fingerprint': base64.urlsafe_b64encode('invalid_fingerprint')
+                }).execute()
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testB67312284(self):
-    code = """\
-def _():
-  self.assertEqual(
-      [u'to be published 2', u'to be published 1', u'to be published 0'],
-      [el.text for el in page.first_column_tds])
-"""
+    code = textwrap.dedent("""\
+        def _():
+          self.assertEqual(
+              [u'to be published 2', u'to be published 1', u'to be published 0'],
+              [el.text for el in page.first_column_tds])
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testB65241516(self):
-    unformatted_code = """\
-checkpoint_files = gfile.Glob(os.path.join(TrainTraceDir(unit_key, "*", "*"), embedding_model.CHECKPOINT_FILENAME + "-*"))
-"""  # noqa
-    expected_formatted_code = """\
-checkpoint_files = gfile.Glob(
-    os.path.join(
-        TrainTraceDir(unit_key, "*", "*"),
-        embedding_model.CHECKPOINT_FILENAME + "-*"))
-"""
+    unformatted_code = textwrap.dedent("""\
+        checkpoint_files = gfile.Glob(os.path.join(TrainTraceDir(unit_key, "*", "*"), embedding_model.CHECKPOINT_FILENAME + "-*"))
+    """)  # noqa
+    expected_formatted_code = textwrap.dedent("""\
+        checkpoint_files = gfile.Glob(
+            os.path.join(
+                TrainTraceDir(unit_key, "*", "*"),
+                embedding_model.CHECKPOINT_FILENAME + "-*"))
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -857,26 +857,26 @@ checkpoint_files = gfile.Glob(
     code = textwrap.dedent("""\
         assert all(s not in (_SENTINEL, None) for s in nested_schemas
                   ), 'Nested schemas should never contain None/_SENTINEL'
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testB36806207(self):
-    code = """\
-def _():
-  linearity_data = [[row] for row in [
-      "%.1f mm" % (np.mean(linearity_values["pos_error"]) * 1000.0),
-      "%.1f mm" % (np.max(linearity_values["pos_error"]) * 1000.0),
-      "%.1f mm" % (np.mean(linearity_values["pos_error_chunk_mean"]) * 1000.0),
-      "%.1f mm" % (np.max(linearity_values["pos_error_chunk_max"]) * 1000.0),
-      "%.1f deg" % math.degrees(np.mean(linearity_values["rot_noise"])),
-      "%.1f deg" % math.degrees(np.max(linearity_values["rot_noise"])),
-      "%.1f deg" % math.degrees(np.mean(linearity_values["rot_drift"])),
-      "%.1f deg" % math.degrees(np.max(linearity_values["rot_drift"])),
-      "%.1f%%" % (np.max(linearity_values["pos_discontinuity"]) * 100.0),
-      "%.1f%%" % (np.max(linearity_values["rot_discontinuity"]) * 100.0)
-  ]]
-"""
+    code = textwrap.dedent("""\
+        def _():
+          linearity_data = [[row] for row in [
+              "%.1f mm" % (np.mean(linearity_values["pos_error"]) * 1000.0),
+              "%.1f mm" % (np.max(linearity_values["pos_error"]) * 1000.0),
+              "%.1f mm" % (np.mean(linearity_values["pos_error_chunk_mean"]) * 1000.0),
+              "%.1f mm" % (np.max(linearity_values["pos_error_chunk_max"]) * 1000.0),
+              "%.1f deg" % math.degrees(np.mean(linearity_values["rot_noise"])),
+              "%.1f deg" % math.degrees(np.max(linearity_values["rot_noise"])),
+              "%.1f deg" % math.degrees(np.mean(linearity_values["rot_drift"])),
+              "%.1f deg" % math.degrees(np.max(linearity_values["rot_drift"])),
+              "%.1f%%" % (np.max(linearity_values["pos_discontinuity"]) * 100.0),
+              "%.1f%%" % (np.max(linearity_values["rot_discontinuity"]) * 100.0)
+          ]]
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -890,7 +890,7 @@ def _():
                 _(ppppppppppppppppppppppppppppppppppppp),
                 *(qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq),
                 **(qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq))
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -903,7 +903,7 @@ def _():
                     ('/some/path/to/a/file/that/is/needed/by/this/process')
               }
           }
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         def _():
           X = {
@@ -912,7 +912,7 @@ def _():
                       ('/some/path/to/a/file/that/is/needed/by/this/process')
               }
           }
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -921,13 +921,13 @@ def _():
         def _():
           while ((not mpede_proc) or ((time_time() - last_modified) < FLAGS_boot_idle_timeout)):
             pass
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         def _():
           while ((not mpede_proc) or
                  ((time_time() - last_modified) < FLAGS_boot_idle_timeout)):
             pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -942,7 +942,7 @@ def _():
                             'read': 'name/some-type-of-very-long-name-for-reading-perms',
                             'modify': 'name/some-other-type-of-very-long-name-for-modifying'
                          })
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         def _():
           labelacl = Env(
@@ -954,18 +954,18 @@ def _():
                   'read': 'name/some-type-of-very-long-name-for-reading-perms',
                   'modify': 'name/some-other-type-of-very-long-name-for-modifying'
               })
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testB34682902(self):
     unformatted_code = textwrap.dedent("""\
         logging.info("Mean angular velocity norm: %.3f", np.linalg.norm(np.mean(ang_vel_arr, axis=0)))
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         logging.info("Mean angular velocity norm: %.3f",
                      np.linalg.norm(np.mean(ang_vel_arr, axis=0)))
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -975,13 +975,13 @@ def _():
           def _():
             hints.append(('hg tag -f -l -r %s %s # %s' % (short(ctx.node(
             )), candidatetag, firstline))[:78])
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         class _():
           def _():
             hints.append(('hg tag -f -l -r %s %s # %s' %
                           (short(ctx.node()), candidatetag, firstline))[:78])
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -1016,7 +1016,7 @@ def _():
                     'this is an entry',
             }
         }
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         environments = {
             'prod': {
@@ -1043,7 +1043,7 @@ def _():
                 '.....': 'this is an entry',
             }
         }
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -1057,7 +1057,7 @@ def _():
                 },
                 'order': 'ASCENDING'
             })
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1087,7 +1087,7 @@ def _():
                 'isnew': True,
                 'dirty': False,
             }
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1098,13 +1098,13 @@ def _():
             # Comment.
             'value'
         }
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         here_is_a_dict = {
             'key':  # Comment.
                 'value'
         }
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -1115,7 +1115,7 @@ def _():
             job_message.call not in ('*', call) or
             job_message.mall not in ('*', job_name)):
           return False
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1125,23 +1125,23 @@ def _():
 
           def __init__(self, metric, fields_cb=None):
             self._fields_cb = fields_cb or (lambda *unused_args, **unused_kwargs: {})
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testB31911533(self):
-    code = """\
-class _():
-
-  @parameterized.NamedParameters(
-      ('IncludingModInfoWithHeaderList', AAAA, aaaa),
-      ('IncludingModInfoWithoutHeaderList', BBBB, bbbbb),
-      ('ExcludingModInfoWithHeaderList', CCCCC, cccc),
-      ('ExcludingModInfoWithoutHeaderList', DDDDD, ddddd),
-  )
-  def _():
-    pass
-"""
+    code = textwrap.dedent("""\
+        class _():
+
+          @parameterized.NamedParameters(
+              ('IncludingModInfoWithHeaderList', AAAA, aaaa),
+              ('IncludingModInfoWithoutHeaderList', BBBB, bbbbb),
+              ('ExcludingModInfoWithHeaderList', CCCCC, cccc),
+              ('ExcludingModInfoWithoutHeaderList', DDDDD, ddddd),
+          )
+          def _():
+            pass
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1154,7 +1154,7 @@ class _():
 
           def xxxxx(self, yyyyy, zzzzzzzzzzzzzz=None):  # A normal comment that runs over the column limit.
             return 1
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         class _():
 
@@ -1166,7 +1166,7 @@ class _():
               yyyyy,
               zzzzzzzzzzzzzz=None):  # A normal comment that runs over the column limit.
             return 1
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -1174,13 +1174,13 @@ class _():
     unformatted_code = textwrap.dedent("""\
         {'1234567890123456789012345678901234567890123456789012345678901234567890':
              '1234567890123456789012345678901234567890'}
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         {
             '1234567890123456789012345678901234567890123456789012345678901234567890':
                 '1234567890123456789012345678901234567890'
         }
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -1190,7 +1190,7 @@ class _():
 
           def Function(self):
             thing.Scrape('/aaaaaaaaa/bbbbbbbbbb/ccccc/dddd/eeeeeeeeeeeeee/ffffffffffffff').AndReturn(42)
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         class Thing:
 
@@ -1198,7 +1198,7 @@ class _():
             thing.Scrape(
                 '/aaaaaaaaa/bbbbbbbbbb/ccccc/dddd/eeeeeeeeeeeeee/ffffffffffffff'
             ).AndReturn(42)
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -1211,7 +1211,7 @@ class _():
                   bbbbbbbbb.usage,
                   ccccccccc.within,
                   imports.ddddddddddddddddddd(name_item.ffffffffffffffff)))
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         def main(unused_argv):
           if True:
@@ -1219,7 +1219,7 @@ class _():
               aaaaaaaaaaa.comment('import-from[{}] {} {}'.format(
                   bbbbbbbbb.usage, ccccccccc.within,
                   imports.ddddddddddddddddddd(name_item.ffffffffffffffff)))
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -1228,12 +1228,12 @@ class _():
         def lulz():
           return (some_long_module_name.SomeLongClassName.
                   some_long_attribute_name.some_long_method_name())
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         def lulz():
           return (some_long_module_name.SomeLongClassName.some_long_attribute_name
                   .some_long_method_name())
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -1252,7 +1252,7 @@ class _():
                 'lllllllllllll': None,  # use the default
             }
         }
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
       def _():
         xxxxxxxxxxxxxxxxxxx = {
@@ -1269,7 +1269,7 @@ class _():
                 'lllllllllllll': None,  # use the default
             }
         }
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -1280,7 +1280,7 @@ class _():
           def _():
             self.assertFalse(
                 evaluation_runner.get_larps_in_eval_set('these_arent_the_larps'))
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1291,7 +1291,7 @@ class _():
           def __repr__(self):
             return '<session %s on %s>' % (
                 self._id, self._stub._stub.rpc_channel().target())  # pylint:disable=protected-access
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1304,7 +1304,7 @@ class _():
 
           # This is another comment
           foo()
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1316,7 +1316,7 @@ class _():
         # This is another comment
         elif True:
           foo()
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1325,14 +1325,14 @@ class _():
         def _():
           _xxxxxxxxxxxxxxx(aaaaaaaa, bbbbbbbbbbbbbb.cccccccccc[
               dddddddddddddddddddddddddddd.eeeeeeeeeeeeeeeeeeeeee.fffffffffffffffffffff])
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         def _():
           _xxxxxxxxxxxxxxx(
               aaaaaaaa,
               bbbbbbbbbbbbbb.cccccccccc[dddddddddddddddddddddddddddd
                                         .eeeeeeeeeeeeeeeeeeeeee.fffffffffffffffffffff])
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -1344,7 +1344,7 @@ class _():
         # Comment
         def foo():
           pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1359,7 +1359,7 @@ class _():
               mock.call(100,
                         start_cursor=cursor_2),
           ])
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         if True:
           query.fetch_page.assert_has_calls([
@@ -1367,7 +1367,7 @@ class _():
               mock.call(100, start_cursor=cursor_1),
               mock.call(100, start_cursor=cursor_2),
           ])
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -1381,7 +1381,7 @@ class _():
                  False:
                      self.bbb.cccccccccc(ddddddddddddddddddddddd.eeeeeeeeeeeeeeeeeeeeee)
                 })
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         if True:
           if True:
@@ -1391,7 +1391,7 @@ class _():
                 False:
                     self.bbb.cccccccccc(ddddddddddddddddddddddd.eeeeeeeeeeeeeeeeeeeeee)
             })
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -1399,13 +1399,13 @@ class _():
     unformatted_code = textwrap.dedent("""\
         def _():
           aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa = (self.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.cccccccccccccccccccccccccccccccccccc)
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         def _():
           aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa = (
               self.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
               .cccccccccccccccccccccccccccccccccccc)
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -1420,7 +1420,7 @@ class _():
                 'dddddddddddd': []
             }]
         }
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1429,7 +1429,7 @@ class _():
         aaaaaaaaa = set(bbbb.cccc
                         for ddd in eeeeee.fffffffffff.gggggggggggggggg
                         for cccc in ddd.specification)
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1441,7 +1441,7 @@ class _():
             self.bbbbbbb[0]['aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', {
                 'xxxxxx': 'yyyyyy'
             }] = cccccc.ddd('1m', '10x1+1')
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1449,7 +1449,7 @@ class _():
     code = textwrap.dedent("""\
         def f():
           ids = {u: i for u, i in zip(self.aaaaa, xrange(42, 42 + len(self.aaaaaa)))}
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1458,7 +1458,7 @@ class _():
         def ListArgs():
           FairlyLongMethodName([relatively_long_identifier_for_a_list],
                                another_argument_with_a_long_identifier)
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1470,7 +1470,7 @@ class _():
               'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa':
               '$bbbbbbbbbbbbbbbbbbbbbbbb',
           })
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         def foo():
           return collections.OrderedDict({
@@ -1478,7 +1478,7 @@ class _():
               'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa':
                   '$bbbbbbbbbbbbbbbbbbbbbbbb',
           })
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -1488,7 +1488,7 @@ class _():
             'materialize': lambda x: some_type_of_function('materialize ' + x.command_def),
             '#': lambda x: x  # do nothing
         })
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         APPARENT_ACTIONS = (
             'command_type',
@@ -1498,7 +1498,7 @@ class _():
                 '#':
                     lambda x: x  # do nothing
             })
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -1513,7 +1513,7 @@ class _():
                     "PPPPPPPPPPPPPPPPPPPPP":
                         FLAGS.aaaaaaaaaaaaaa + FLAGS.bbbbbbbbbbbbbbbbbbb,
                 })
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         def foo():
           if True:
@@ -1525,7 +1525,7 @@ class _():
                     "PPPPPPPPPPPPPPPPPPPPP":
                         FLAGS.aaaaaaaaaaaaaa + FLAGS.bbbbbbbbbbbbbbbbbbb,
                 })
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -1537,7 +1537,7 @@ class _():
           unused_error, result = server.Query(
               ['AA BBBB CCC DDD EEEEEEEE X YY ZZZZ FFF EEE AAAAAAAA'],
               aaaaaaaaaaa=True, bbbbbbbb=None)
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
       class A(object):
 
@@ -1564,7 +1564,7 @@ class _():
                     'wiz': {'account': 'wiz',
                             'lines': 'l8'}
                 })
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         class F():
 
@@ -1584,7 +1584,7 @@ class _():
                         'lines': 'l8'
                     }
                 })
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -1593,13 +1593,13 @@ class _():
         def foo():
           if True:
             return (struct.pack('aaaa', bbbbbbbbbb, ccccccccccccccc, dddddddd) + eeeeeee)
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         def foo():
           if True:
             return (struct.pack('aaaa', bbbbbbbbbb, ccccccccccccccc, dddddddd) +
                     eeeeeee)
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -1608,7 +1608,7 @@ class _():
         class A(object):
           def xxxxxxxxx(self, aaaaaaa, bbbbbbb=ccccccccccc, dddddd=300, eeeeeeeeeeeeee=None, fffffffffffffff=0):
             pass
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         class A(object):
 
@@ -1619,7 +1619,7 @@ class _():
                         eeeeeeeeeeeeee=None,
                         fffffffffffffff=0):
             pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -1628,14 +1628,14 @@ class _():
         class F():
           def functioni(self, aaaaaaa, bbbbbbb, cccccc, dddddddddddddd, eeeeeeeeeeeeeee):
             pass
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         class F():
 
           def functioni(self, aaaaaaa, bbbbbbb, cccccc, dddddddddddddd,
                         eeeeeeeeeeeeeee):
             pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -1660,7 +1660,7 @@ class _():
                    | m.ggggggg(bbbbbbbbbbbbbbb))
                   | m.jjjj()
                   | m.ppppp(m.vvv[0] + m.vvv[1]))
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1678,7 +1678,7 @@ class _():
                      | m.ggggggg(self.gggggggg))
                     | m.jjjj()
                     | m.ppppp(m.VAL[0] / m.VAL[1]))
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1686,11 +1686,11 @@ class _():
     unformatted_code = textwrap.dedent("""\
         from a_very_long_or_indented_module_name_yada_yada import (long_argument_1,
                                                                    long_argument_2)
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         from a_very_long_or_indented_module_name_yada_yada import (
             long_argument_1, long_argument_2)
-        """)
+    """)
 
     try:
       style.SetGlobalStyle(
@@ -1719,7 +1719,7 @@ class _():
                     and self.gggggg == other.gggggg and self.hhh == other.hhh
                     and len(self.iiiiiiii) == len(other.iiiiiiii)
                     and all(jjjjjjj in other.iiiiiiii for jjjjjjj in self.iiiiiiii))
-        """)  # noqa
+    """)  # noqa
 
     try:
       style.SetGlobalStyle(
@@ -1736,13 +1736,13 @@ class _():
         def f():
           if True:
             aaaaaa.bbbbbbbbbbbbbbbbbbbb[-1].cccccccccccccc.ddd().eeeeeeee(ffffffffffffff)
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         def f():
           if True:
             aaaaaa.bbbbbbbbbbbbbbbbbbbb[-1].cccccccccccccc.ddd().eeeeeeee(
                 ffffffffffffff)
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -1754,7 +1754,7 @@ class _():
                 'xxx': '%s/cccccc/ddddddddddddddddddd.jar' %
                        (eeeeee.FFFFFFFFFFFFFFFFFF),
             }
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         def main(unused_argv):
           if True:
@@ -1762,7 +1762,7 @@ class _():
                 'xxx':
                     '%s/cccccc/ddddddddddddddddddd.jar' % (eeeeee.FFFFFFFFFFFFFFFFFF),
             }
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -1771,7 +1771,7 @@ class _():
         def myfunc_1():
           myarray = numpy.zeros((2, 2, 2))
           print(myarray[:, 1, :])
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1785,7 +1785,7 @@ class _():
                                       'dddddddddddddddddddddddddddddddddddddddddd',
             }
         }
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1797,7 +1797,7 @@ class _():
             # Comment about second list item
             'Second item',
         ]
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1817,7 +1817,7 @@ class _():
                 ],
             },
         }
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1834,7 +1834,7 @@ class _():
                           class_0_count=class_0_count,
                           class_1_name=self.class_1_name,
                           class_1_count=class_1_count))
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1843,7 +1843,7 @@ class _():
         if True:
           aaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbb(
               'ccccccccccc', ddddddddd='eeeee').fffffffff([ggggggggggggggggggggg])
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1857,7 +1857,7 @@ class _():
                     xxxxxxxxxxxx.yyyyyyyyyyyyyy.zzzzzzzz,
                     xxxxxxxxxxxx.yyyyyyyyyyyyyy.zzzzzzzz):
                   continue
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1867,7 +1867,7 @@ class _():
           if (aaaaaaaaaaaaaaa.start >= aaaaaaaaaaaaaaa.end or
               bbbbbbbbbbbbbbb.start >= bbbbbbbbbbbbbbb.end):
             return False
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1879,7 +1879,7 @@ class _():
                 if b: continue
                 if c: break
             return 0
-        """)
+    """)
 
     try:
       style.SetGlobalStyle(style.CreatePEP8Style())
@@ -1893,7 +1893,7 @@ class _():
     code = textwrap.dedent("""\
         a = {1, 2, 3}[x]
         b = {'foo': 42, 'bar': 37}['foo']
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1907,7 +1907,7 @@ class _():
                 fffffffffff=(aaaaaaa.bbbbbbbb.ccccccc.dddddddddddddddddddd
                              .Mmmmmmmmmmmmmmmmmm(-1, 'permission error'))):
               self.assertRaises(nnnnnnnnnnnnnnnn.ooooo, ppppp.qqqqqqqqqqqqqqqqq)
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         class Foo(object):
 
@@ -1918,7 +1918,7 @@ class _():
                     aaaaaaa.bbbbbbbb.ccccccc.dddddddddddddddddddd.Mmmmmmmmmmmmmmmmmm(
                         -1, 'permission error'))):
               self.assertRaises(nnnnnnnnnnnnnnnn.ooooo, ppppp.qqqqqqqqqqqqqqqqq)
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -1927,19 +1927,19 @@ class _():
         method.Set(
             'long argument goes here that causes the line to break',
             lambda arg2=0.5: arg2)
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testB19073499(self):
-    code = """\
-instance = (
-    aaaaaaa.bbbbbbb().ccccccccccccccccc().ddddddddddd({
-        'aa': 'context!'
-    }).eeeeeeeeeeeeeeeeeee({  # Inline comment about why fnord has the value 6.
-        'fnord': 6
-    }))
-"""
+    code = textwrap.dedent("""\
+        instance = (
+            aaaaaaa.bbbbbbb().ccccccccccccccccc().ddddddddddd({
+                'aa': 'context!'
+            }).eeeeeeeeeeeeeeeeeee({  # Inline comment about why fnord has the value 6.
+                'fnord': 6
+            }))
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1949,7 +1949,7 @@ instance = (
           if True:
             self._Test(aaaa, bbbbbbb.cccccccccc, dddddddd, eeeeeeeeeee,
                        [ffff, ggggggggggg, hhhhhhhhhhhh, iiiiii, jjjj])
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1967,7 +1967,7 @@ instance = (
                     'kkkkkkkkkkkk': kkkkkkkkkkkk,
                 },
                 llllllllll=mmmmmm.nnnnnnnnnnnnnnnn)
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1986,7 +1986,7 @@ instance = (
           # Line two.
         elif False:
           pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -1997,7 +1997,7 @@ instance = (
             # Next comment
             'YYYYYYYYYYYYYYYY': ['zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz'],
         }
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -2006,12 +2006,12 @@ instance = (
         if True:
           self.assertLess(abs(time.time()-aaaa.bbbbbbbbbbb(
                               datetime.datetime.now())), 1)
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         if True:
           self.assertLess(
               abs(time.time() - aaaa.bbbbbbbbbbb(datetime.datetime.now())), 1)
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -2020,16 +2020,15 @@ instance = (
         def f():
           if True:
             if True:
-              return aaaa.bbbbbbbbb(ccccccc=dddddddddddddd({('eeee', \
-'ffffffff'): str(j)}))
-        """)
+              return aaaa.bbbbbbbbb(ccccccc=dddddddddddddd({('eeee', 'ffffffff'): str(j)}))
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         def f():
           if True:
             if True:
               return aaaa.bbbbbbbbb(
                   ccccccc=dddddddddddddd({('eeee', 'ffffffff'): str(j)}))
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -2044,7 +2043,7 @@ instance = (
                                         "eeeeeeeee ffffffffff"
                                        ), "rb") as gggggggggggggggggggg:
                 print(gggggggggggggggggggg)
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         class aaaaaaaaaaaaaa(object):
 
@@ -2054,7 +2053,7 @@ instance = (
                   os.path.join(aaaaa.bbbbb.ccccccccccc, DDDDDDDDDDDDDDD,
                                "eeeeeeeee ffffffffff"), "rb") as gggggggggggggggggggg:
                 print(gggggggggggggggggggg)
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -2069,7 +2068,7 @@ instance = (
               'BBB': 1.0,
                 'DDDDDDDD': 0.4811
                                       }
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         '''blah......'''
 
@@ -2081,7 +2080,7 @@ instance = (
               'BBB': 1.0,
               'DDDDDDDD': 0.4811
           }
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -2092,13 +2091,13 @@ instance = (
                                                       eeeeeeeee=self.fffffffffffff
                                                       )as gggg:
             pass
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         if True:
           with aaaaaaaaaaaaaa.bbbbbbbbbbbbb.ccccccc(
               ddddddddddddd, eeeeeeeee=self.fffffffffffff) as gggg:
             pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -2107,7 +2106,7 @@ instance = (
         def foo(self):
          def bar(my_dict_name):
           self.my_dict_name['foo-bar-baz-biz-boo-baa-baa'].IncrementBy.assert_called_once_with('foo_bar_baz_boo')
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         def foo(self):
 
@@ -2115,7 +2114,7 @@ instance = (
             self.my_dict_name[
                 'foo-bar-baz-biz-boo-baa-baa'].IncrementBy.assert_called_once_with(
                     'foo_bar_baz_boo')
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -2125,7 +2124,7 @@ instance = (
           if 1:
             for row in AAAA:
               self.create(aaaaaaaa="/aaa/bbbb/cccc/dddddd/eeeeeeeeeeeeeeeeeeeeeeeeee/%s" % row [0].replace(".foo", ".bar"), aaaaa=bbb[1], ccccc=bbb[2], dddd=bbb[3], eeeeeeeeeee=[s.strip() for s in bbb[4].split(",")], ffffffff=[s.strip() for s in bbb[5].split(",")], gggggg=bbb[6])
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         if 1:
           if 1:
@@ -2139,7 +2138,7 @@ instance = (
                   eeeeeeeeeee=[s.strip() for s in bbb[4].split(",")],
                   ffffffff=[s.strip() for s in bbb[5].split(",")],
                   gggggg=bbb[6])
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -2152,7 +2151,7 @@ instance = (
           bad_slice = map(math.sqrt, an_array_with_an_exceedingly_long_name[:ARBITRARY_CONSTANT_A])
           a_long_name_slicing = an_array_with_an_exceedingly_long_name[:ARBITRARY_CONSTANT_A]
           bad_slice = ("I am a crazy, no good, string what's too long, etc." + " no really ")[:ARBITRARY_CONSTANT_A]
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         def main(unused_argv):
           ARBITRARY_CONSTANT_A = 10
@@ -2164,36 +2163,36 @@ instance = (
                                                                        ARBITRARY_CONSTANT_A]
           bad_slice = ("I am a crazy, no good, string what's too long, etc." +
                        " no really ")[:ARBITRARY_CONSTANT_A]
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testB15597568(self):
-    unformatted_code = """\
-if True:
-  if True:
-    if True:
-      print(("Return code was %d" + (", and the process timed out." if did_time_out else ".")) % errorcode)
-"""  # noqa
-    expected_formatted_code = """\
-if True:
-  if True:
-    if True:
-      print(("Return code was %d" +
-             (", and the process timed out." if did_time_out else ".")) %
-            errorcode)
-"""
+    unformatted_code = textwrap.dedent("""\
+        if True:
+          if True:
+            if True:
+              print(("Return code was %d" + (", and the process timed out." if did_time_out else ".")) % errorcode)
+    """)  # noqa
+    expected_formatted_code = textwrap.dedent("""\
+        if True:
+          if True:
+            if True:
+              print(("Return code was %d" +
+                     (", and the process timed out." if did_time_out else ".")) %
+                    errorcode)
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testB15542157(self):
     unformatted_code = textwrap.dedent("""\
         aaaaaaaaaaaa = bbbb.ccccccccccccccc(dddddd.eeeeeeeeeeeeee, ffffffffffffffffff, gggggg.hhhhhhhhhhhhhhhhh)
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         aaaaaaaaaaaa = bbbb.ccccccccccccccc(dddddd.eeeeeeeeeeeeee, ffffffffffffffffff,
                                             gggggg.hhhhhhhhhhhhhhhhh)
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -2213,7 +2212,7 @@ if True:
                      iiiiiiiiiiiiiiiiiii.jjjjjjjjjj.kkkkkkk,
                      lllll.mm),
                  nnnnnnnnnn=ooooooo.pppppppppp)
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         if aaaaaaa.bbbbbbbbbb:
           cccccc.dddddddddd(eeeeeeeeeee=fffffffffffff.gggggggggggggggggg)
@@ -2221,29 +2220,29 @@ if True:
             # This is a comment in the middle of it all.
             kkkkkkk.llllllllll.mmmmmmmmmmmmm = True
           if (aaaaaa.bbbbb.ccccccccccccc != ddddddd.eeeeeeeeee.fffffffffffff or
-              eeeeee.fffff.ggggggggggggggggggggggggggg() !=
-              hhhhhhh.iiiiiiiiii.jjjjjjjjjjjj):
+              eeeeee.fffff.ggggggggggggggggggggggggggg()
+              != hhhhhhh.iiiiiiiiii.jjjjjjjjjjjj):
             aaaaaaaa.bbbbbbbbbbbb(
                 aaaaaa.bbbbb.cc,
                 dddddddddddd=eeeeeeeeeeeeeeeeeee.fffffffffffffffff(
                     gggggg.hh, iiiiiiiiiiiiiiiiiii.jjjjjjjjjj.kkkkkkk, lllll.mm),
                 nnnnnnnnnn=ooooooo.pppppppppp)
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testB14468247(self):
-    unformatted_code = """\
-call(a=1,
-    b=2,
-)
-"""
-    expected_formatted_code = """\
-call(
-    a=1,
-    b=2,
-)
-"""
+    unformatted_code = textwrap.dedent("""\
+        call(a=1,
+            b=2,
+        )
+    """)
+    expected_formatted_code = textwrap.dedent("""\
+        call(
+            a=1,
+            b=2,
+        )
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -2251,12 +2250,12 @@ call(
     unformatted_code = textwrap.dedent("""\
         def foo1(parameter_1, parameter_2, parameter_3, parameter_4, \
 parameter_5, parameter_6): pass
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         def foo1(parameter_1, parameter_2, parameter_3, parameter_4, parameter_5,
                  parameter_6):
           pass
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -2264,11 +2263,11 @@ parameter_5, parameter_6): pass
     unformatted_code = textwrap.dedent("""\
         self.aaaaaaaaaaa(  # A comment in the middle of it all.
                948.0/3600, self.bbb.ccccccccccccccccccccc(dddddddddddddddd.eeee, True))
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         self.aaaaaaaaaaa(  # A comment in the middle of it all.
             948.0 / 3600, self.bbb.ccccccccccccccccccccc(dddddddddddddddd.eeee, True))
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -2277,49 +2276,49 @@ parameter_5, parameter_6): pass
             DC_1, (CL - 50, CL), AAAAAAAA, BBBBBBBBBBBBBBBB, 98.0,
             CCCCCCC).ddddddddd(  # Look! A comment is here.
                 AAAAAAAA - (20 * 60 - 5))
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
     unformatted_code = textwrap.dedent("""\
         aaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbb.ccccccccccccccccccccccccc().dddddddddddddddddddddddddd(1, 2, 3, 4)
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         aaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbb.ccccccccccccccccccccccccc(
         ).dddddddddddddddddddddddddd(1, 2, 3, 4)
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
     unformatted_code = textwrap.dedent("""\
         aaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbb.ccccccccccccccccccccccccc(x).dddddddddddddddddddddddddd(1, 2, 3, 4)
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         aaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbb.ccccccccccccccccccccccccc(
             x).dddddddddddddddddddddddddd(1, 2, 3, 4)
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
     unformatted_code = textwrap.dedent("""\
         aaaaaaaaaaaaaaaaaaaaaaaa(xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx).dddddddddddddddddddddddddd(1, 2, 3, 4)
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         aaaaaaaaaaaaaaaaaaaaaaaa(
             xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx).dddddddddddddddddddddddddd(1, 2, 3, 4)
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
     unformatted_code = textwrap.dedent("""\
         aaaaaaaaaaaaaaaaaaaaaaaa().bbbbbbbbbbbbbbbbbbbbbbbb().ccccccccccccccccccc().\
 dddddddddddddddddd().eeeeeeeeeeeeeeeeeeeee().fffffffffffffffff().gggggggggggggggggg()
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         aaaaaaaaaaaaaaaaaaaaaaaa().bbbbbbbbbbbbbbbbbbbbbbbb().ccccccccccccccccccc(
         ).dddddddddddddddddd().eeeeeeeeeeeeeeeeeeeee().fffffffffffffffff(
         ).gggggggggggggggggg()
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -2337,11 +2336,11 @@ dddddddddddddddddd().eeeeeeeeeeeeeeeeeeeee().fffffffffffffffff().ggggggggggggggg
             expand_text % {
                 'creator': creator
             })
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         shelf_renderer.expand_text = text.translate_to_unicode(expand_text %
                                                                {'creator': creator})
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
diff --git a/yapftests/reformatter_facebook_test.py b/yapftests/reformatter_facebook_test.py
index c61f32b..dfb87d3 100644
--- a/yapftests/reformatter_facebook_test.py
+++ b/yapftests/reformatter_facebook_test.py
@@ -33,11 +33,11 @@ class TestsForFacebookStyle(yapf_test_helper.YAPFTest):
         def overly_long_function_name(
           just_one_arg, **kwargs):
           pass
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         def overly_long_function_name(just_one_arg, **kwargs):
             pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -47,13 +47,13 @@ class TestsForFacebookStyle(yapf_test_helper.YAPFTest):
           first_argument_on_the_same_line,
           second_argument_makes_the_line_too_long):
           pass
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         def overly_long_function_name(
             first_argument_on_the_same_line, second_argument_makes_the_line_too_long
         ):
             pass
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -62,14 +62,13 @@ class TestsForFacebookStyle(yapf_test_helper.YAPFTest):
         def overly_long_function_name(a, b, c, d, e, f, g, h, i, j, k, l, m,
           n, o, p, q, r, s, t, u, v, w, x, y, z):
           pass
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         def overly_long_function_name(
-            a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, \
-v, w, x, y, z
+            a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z
         ):
             pass
-        """)
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -81,7 +80,7 @@ v, w, x, y, z
           # comment about the second argument
           second_argument_makes_the_line_too_long):
           pass
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         def overly_long_function_name(
             # comment about the first argument
@@ -90,7 +89,7 @@ v, w, x, y, z
             second_argument_makes_the_line_too_long
         ):
             pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -102,7 +101,7 @@ v, w, x, y, z
             SOME_CONSTANT_NUMBER2,
             SOME_CONSTANT_NUMBER3,
         )
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -121,7 +120,7 @@ v, w, x, y, z
             IOError, OSError, LookupError, RuntimeError, OverflowError,
         ) as exception:
             pass
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         try:
             pass
@@ -140,7 +139,7 @@ v, w, x, y, z
             OverflowError,
         ) as exception:
             pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -151,7 +150,7 @@ v, w, x, y, z
             pass
         except (IOError, OSError, LookupError, RuntimeError, OverflowError) as exception:
             pass
-        """)  # noqa
+    """)  # noqa
     pass1_code = textwrap.dedent("""\
         try:
             pass
@@ -159,7 +158,7 @@ v, w, x, y, z
             IOError, OSError, LookupError, RuntimeError, OverflowError
         ) as exception:
             pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(pass0_code)
     self.assertCodeEqual(pass1_code, reformatter.Reformat(llines))
 
@@ -170,7 +169,7 @@ v, w, x, y, z
             IOError, OSError, LookupError, RuntimeError, OverflowError
         ) as exception:
             pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(pass1_code)
     self.assertCodeEqual(pass2_code, reformatter.Reformat(llines))
 
@@ -183,7 +182,7 @@ v, w, x, y, z
                        self.foobars.counters['db.cheeses'] != 1 or
                        self.foobars.counters['db.marshmellow_skins'] != 1):
                         pass
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         if True:
             if True:
@@ -193,7 +192,7 @@ v, w, x, y, z
                         self.foobars.counters['db.marshmellow_skins'] != 1
                     ):
                         pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -201,13 +200,13 @@ v, w, x, y, z
     unformatted_code = textwrap.dedent("""\
         if True:
             self.assertEqual(result.reason_not_added, "current preflight is still running")
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         if True:
             self.assertEqual(
                 result.reason_not_added, "current preflight is still running"
             )
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -220,7 +219,7 @@ v, w, x, y, z
                     if clues_lists:
                        return cls.single_constraint_not(clues_lists, effect, constraints[0], constraint_manager)
 
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         class Foo:
             class Bar:
@@ -230,7 +229,7 @@ v, w, x, y, z
                         return cls.single_constraint_not(
                             clues_lists, effect, constraints[0], constraint_manager
                         )
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -241,7 +240,7 @@ v, w, x, y, z
                 cls.effect_clues = {
                     'effect': Clue((cls.effect_time, 'apache_host'), effect_line, 40)
                 }
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -283,7 +282,7 @@ v, w, x, y, z
                     ('localhost', os.path.join(path, 'node_1.log'), super_parser),
                     ('localhost', os.path.join(path, 'node_2.log'), super_parser)
                 ]
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         class Foo():
             def _pack_results_for_constraint_or():
@@ -319,7 +318,7 @@ v, w, x, y, z
                     ('localhost', os.path.join(path, 'node_1.log'), super_parser),
                     ('localhost', os.path.join(path, 'node_2.log'), super_parser)
                 ]
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -331,7 +330,7 @@ v, w, x, y, z
                     effect_line_offset, line_content,
                     LineSource('localhost', xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx)
                 )
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -345,7 +344,7 @@ v, w, x, y, z
                         self.foobars.counters['db.marshmellow_skins'] != 1
                     ):
                         pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -361,7 +360,7 @@ v, w, x, y, z
                         (2, 20, 200),
                     ]
                 )
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -374,7 +373,7 @@ v, w, x, y, z
                     (clue for clue in combination if not clue == Verifier.UNMATCHED),
                     constraints, InvestigationResult.OR
                 )
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(code)
     reformatted_code = reformatter.Reformat(llines)
     self.assertCodeEqual(code, reformatted_code)
@@ -396,7 +395,7 @@ v, w, x, y, z
 
 
         print(foo())
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         def foo():
             if 0:
@@ -408,22 +407,22 @@ v, w, x, y, z
 
 
         print(foo())
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testIfStmtClosingBracket(self):
-    unformatted_code = """\
-if (isinstance(value  , (StopIteration  , StopAsyncIteration  )) and exc.__cause__ is value_asdfasdfasdfasdfsafsafsafdasfasdfs):
-    return False
-"""  # noqa
-    expected_formatted_code = """\
-if (
-    isinstance(value, (StopIteration, StopAsyncIteration)) and
-    exc.__cause__ is value_asdfasdfasdfasdfsafsafsafdasfasdfs
-):
-    return False
-"""
+    unformatted_code = textwrap.dedent("""\
+        if (isinstance(value  , (StopIteration  , StopAsyncIteration  )) and exc.__cause__ is value_asdfasdfasdfasdfsafsafsafdasfasdfs):
+            return False
+    """)  # noqa
+    expected_formatted_code = textwrap.dedent("""\
+        if (
+            isinstance(value, (StopIteration, StopAsyncIteration)) and
+            exc.__cause__ is value_asdfasdfasdfasdfsafsafsafdasfasdfs
+        ):
+            return False
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
diff --git a/yapftests/reformatter_pep8_test.py b/yapftests/reformatter_pep8_test.py
index acc218d..1cf7820 100644
--- a/yapftests/reformatter_pep8_test.py
+++ b/yapftests/reformatter_pep8_test.py
@@ -16,7 +16,6 @@
 import textwrap
 import unittest
 
-from yapf.yapflib import py3compat
 from yapf.yapflib import reformatter
 from yapf.yapflib import style
 
@@ -33,11 +32,11 @@ class TestsForPEP8Style(yapf_test_helper.YAPFTest):
     unformatted_code = textwrap.dedent("""\
         if a+b:
           pass
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         if a + b:
             pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -46,7 +45,7 @@ class TestsForPEP8Style(yapf_test_helper.YAPFTest):
         if True: a = 42
         elif False: b = 42
         else: c = 42
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -55,13 +54,13 @@ class TestsForPEP8Style(yapf_test_helper.YAPFTest):
         class Foo:
           def joe():
             pass
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         class Foo:
 
             def joe():
                 pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -74,7 +73,7 @@ class TestsForPEP8Style(yapf_test_helper.YAPFTest):
                 """Override in subclass"""
             def is_running(self):
                 return self.running
-        ''')
+    ''')
     expected_formatted_code = textwrap.dedent('''\
         class TestClass:
 
@@ -86,7 +85,7 @@ class TestsForPEP8Style(yapf_test_helper.YAPFTest):
 
             def is_running(self):
                 return self.running
-        ''')
+    ''')
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -94,11 +93,11 @@ class TestsForPEP8Style(yapf_test_helper.YAPFTest):
     unformatted_code = textwrap.dedent("""\
         if a+b: # comment
           pass
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         if a + b:  # comment
             pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -107,10 +106,10 @@ class TestsForPEP8Style(yapf_test_helper.YAPFTest):
         a = (
             1,
         )
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         a = (1, )
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -120,7 +119,7 @@ class TestsForPEP8Style(yapf_test_helper.YAPFTest):
             if str(geom.geom_type).upper(
             ) != self.geom_type and not self.geom_type == 'GEOMETRY':
                 ror(code='om_type')
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -132,7 +131,7 @@ class TestsForPEP8Style(yapf_test_helper.YAPFTest):
                 zzzzz = '%s-%s'.ww(xxxxxxxxxxxxxxxxxxxxxxxxxx + 1, xxxxxxxxxxxxxxxxx.yyy + 1)
                 zzzzz = '%s-%s' % (xxxxxxxxxxxxxxxxxxxxxxx + 1, xxxxxxxxxxxxxxxxxxxxx + 1)
                 zzzzz = '%s-%s'.ww(xxxxxxxxxxxxxxxxxxxxxxx + 1, xxxxxxxxxxxxxxxxxxxxx + 1)
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         def f():
             if True:
@@ -144,7 +143,7 @@ class TestsForPEP8Style(yapf_test_helper.YAPFTest):
                                    xxxxxxxxxxxxxxxxxxxxx + 1)
                 zzzzz = '%s-%s'.ww(xxxxxxxxxxxxxxxxxxxxxxx + 1,
                                    xxxxxxxxxxxxxxxxxxxxx + 1)
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -153,14 +152,14 @@ class TestsForPEP8Style(yapf_test_helper.YAPFTest):
         TEST_LIST = ('foo', 'bar',  # first comment
                      'baz'  # second comment
                     )
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         TEST_LIST = (
             'foo',
             'bar',  # first comment
             'baz'  # second comment
         )
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -172,7 +171,7 @@ class TestsForPEP8Style(yapf_test_helper.YAPFTest):
                    xxxxxxxxxxxxxxxxxxxx(yyyyyyyyyyyyy[zzzzz].aaaaaaaa[0]) == 'bbbbbbb'
                   ):
               pass
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         def f():
 
@@ -181,7 +180,7 @@ class TestsForPEP8Style(yapf_test_helper.YAPFTest):
                        and xxxxxxxxxxxxxxxxxxxx(
                            yyyyyyyyyyyyy[zzzzz].aaaaaaaa[0]) == 'bbbbbbb'):
                     pass
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -189,12 +188,12 @@ class TestsForPEP8Style(yapf_test_helper.YAPFTest):
     unformatted_code = textwrap.dedent("""\
         if True:
           runtime_mins = (program_end_time - program_start_time).total_seconds() / 60.0
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         if True:
             runtime_mins = (program_end_time -
                             program_start_time).total_seconds() / 60.0
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -212,7 +211,7 @@ class TestsForPEP8Style(yapf_test_helper.YAPFTest):
 
             for connection in itertools.chain(branch.contact, branch.address, morestuff.andmore.andmore.andmore.andmore.andmore.andmore.andmore):
                 dosomething(connection)
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         if (aaaaaaaaaaaaaa + bbbbbbbbbbbbbbbb == ccccccccccccccccc and xxxxxxxxxxxxx
                 or yyyyyyyyyyyyyyyyy):
@@ -233,7 +232,7 @@ class TestsForPEP8Style(yapf_test_helper.YAPFTest):
                     branch.contact, branch.address,
                     morestuff.andmore.andmore.andmore.andmore.andmore.andmore.andmore):
                 dosomething(connection)
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -250,7 +249,7 @@ class TestsForPEP8Style(yapf_test_helper.YAPFTest):
                           update.message.supergroup_chat_created or update.message.channel_chat_created
                           or update.message.migrate_to_chat_id or update.message.migrate_from_chat_id or
                           update.message.pinned_message)
-          """)  # noqa
+      """)  # noqa
       expected_formatted_code = textwrap.dedent("""\
           def foo():
               return bool(
@@ -263,7 +262,7 @@ class TestsForPEP8Style(yapf_test_helper.YAPFTest):
                   or update.message.migrate_to_chat_id
                   or update.message.migrate_from_chat_id
                   or update.message.pinned_message)
-          """)  # noqa
+      """)  # noqa
       llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
       self.assertCodeEqual(expected_formatted_code,
                            reformatter.Reformat(llines))
@@ -275,13 +274,13 @@ class TestsForPEP8Style(yapf_test_helper.YAPFTest):
         if True:
             if True:
                 keys.append(aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)  # may be unassigned.
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         if True:
             if True:
                 keys.append(
                     aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)  # may be unassigned.
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -293,14 +292,14 @@ class TestsForPEP8Style(yapf_test_helper.YAPFTest):
       unformatted_code = textwrap.dedent("""\
           a_very_long_function_name(long_argument_name_1=1, long_argument_name_2=2,
                                     long_argument_name_3=3, long_argument_name_4=4)
-          """)  # noqa
+      """)  # noqa
       expected_formatted_code = textwrap.dedent("""\
           a_very_long_function_name(
               long_argument_name_1=1,
               long_argument_name_2=2,
               long_argument_name_3=3,
               long_argument_name_4=4)
-          """)
+      """)
       llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
       self.assertCodeEqual(expected_formatted_code,
                            reformatter.Reformat(llines))
@@ -311,12 +310,12 @@ class TestsForPEP8Style(yapf_test_helper.YAPFTest):
     unformatted_code = textwrap.dedent("""\
         def foo():
             df = df[(df['campaign_status'] == 'LIVE') & (df['action_status'] == 'LIVE')]
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         def foo():
             df = df[(df['campaign_status'] == 'LIVE')
                     & (df['action_status'] == 'LIVE')]
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -326,7 +325,7 @@ class TestsForPEP8Style(yapf_test_helper.YAPFTest):
         DJANGO_TEMPLATES_OPTIONS = {"context_processors": [],}
         x = ["context_processors"]
         x = ["context_processors",]
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         DJANGO_TEMPLATES_OPTIONS = {"context_processors": []}
         DJANGO_TEMPLATES_OPTIONS = {
@@ -336,7 +335,7 @@ class TestsForPEP8Style(yapf_test_helper.YAPFTest):
         x = [
             "context_processors",
         ]
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -346,7 +345,7 @@ class TestsForPEP8Style(yapf_test_helper.YAPFTest):
 
             def a(): return a(
              aaaaaaaaaa=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)
-        """)
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         class a():
 
@@ -354,7 +353,7 @@ class TestsForPEP8Style(yapf_test_helper.YAPFTest):
                 return a(
                     aaaaaaaaaa=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 )
-        """)
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -364,13 +363,13 @@ class TestsForPEP8Style(yapf_test_helper.YAPFTest):
           pass
         if -3 < x < 3:
           pass
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         if not -3 < x < 3:
             pass
         if -3 < x < 3:
             pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -390,7 +389,7 @@ class TestsForPEP8Style(yapf_test_helper.YAPFTest):
               'description': _("Lorem ipsum dolor met sit amet elit, si vis pacem para bellum "
                                "elites nihi very long string."),
           }
-          """)  # noqa
+      """)  # noqa
       expected_formatted_code = textwrap.dedent("""\
           some_dict = {
               'title': _("I am example data"),
@@ -399,21 +398,21 @@ class TestsForPEP8Style(yapf_test_helper.YAPFTest):
                   "elites nihi very long string."
               ),
           }
-          """)  # noqa
+      """)  # noqa
       llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
       self.assertCodeEqual(expected_formatted_code,
                            reformatter.Reformat(llines))
 
       unformatted_code = textwrap.dedent("""\
           X = {'a': 1, 'b': 2, 'key': this_is_a_function_call_that_goes_over_the_column_limit_im_pretty_sure()}
-          """)  # noqa
+      """)  # noqa
       expected_formatted_code = textwrap.dedent("""\
           X = {
               'a': 1,
               'b': 2,
               'key': this_is_a_function_call_that_goes_over_the_column_limit_im_pretty_sure()
           }
-          """)  # noqa
+      """)  # noqa
       llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
       self.assertCodeEqual(expected_formatted_code,
                            reformatter.Reformat(llines))
@@ -423,7 +422,7 @@ class TestsForPEP8Style(yapf_test_helper.YAPFTest):
               'category': category,
               'role': forms.ModelChoiceField(label=_("Role"), required=False, queryset=category_roles, initial=selected_role, empty_label=_("No access"),),
           }
-          """)  # noqa
+      """)  # noqa
       expected_formatted_code = textwrap.dedent("""\
           attrs = {
               'category': category,
@@ -435,7 +434,7 @@ class TestsForPEP8Style(yapf_test_helper.YAPFTest):
                   empty_label=_("No access"),
               ),
           }
-          """)
+      """)
       llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
       self.assertCodeEqual(expected_formatted_code,
                            reformatter.Reformat(llines))
@@ -446,7 +445,7 @@ class TestsForPEP8Style(yapf_test_helper.YAPFTest):
               required=False,
               help_text=_("Optional CSS class used to customize this category appearance from templates."),
           )
-          """)  # noqa
+      """)  # noqa
       expected_formatted_code = textwrap.dedent("""\
           css_class = forms.CharField(
               label=_("CSS class"),
@@ -455,7 +454,7 @@ class TestsForPEP8Style(yapf_test_helper.YAPFTest):
                   "Optional CSS class used to customize this category appearance from templates."
               ),
           )
-          """)  # noqa
+      """)  # noqa
       llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
       self.assertCodeEqual(expected_formatted_code,
                            reformatter.Reformat(llines))
@@ -463,59 +462,59 @@ class TestsForPEP8Style(yapf_test_helper.YAPFTest):
       style.SetGlobalStyle(style.CreatePEP8Style())
 
   def testBitwiseOperandSplitting(self):
-    unformatted_code = """\
-def _():
-    include_values = np.where(
-                (cdffile['Quality_Flag'][:] >= 5) & (
-                cdffile['Day_Night_Flag'][:] == 1) & (
-                cdffile['Longitude'][:] >= select_lon - radius) & (
-                cdffile['Longitude'][:] <= select_lon + radius) & (
-                cdffile['Latitude'][:] >= select_lat - radius) & (
-                cdffile['Latitude'][:] <= select_lat + radius))
-"""
-    expected_code = """\
-def _():
-    include_values = np.where(
-        (cdffile['Quality_Flag'][:] >= 5) & (cdffile['Day_Night_Flag'][:] == 1)
-        & (cdffile['Longitude'][:] >= select_lon - radius)
-        & (cdffile['Longitude'][:] <= select_lon + radius)
-        & (cdffile['Latitude'][:] >= select_lat - radius)
-        & (cdffile['Latitude'][:] <= select_lat + radius))
-"""
+    unformatted_code = textwrap.dedent("""\
+        def _():
+            include_values = np.where(
+                        (cdffile['Quality_Flag'][:] >= 5) & (
+                        cdffile['Day_Night_Flag'][:] == 1) & (
+                        cdffile['Longitude'][:] >= select_lon - radius) & (
+                        cdffile['Longitude'][:] <= select_lon + radius) & (
+                        cdffile['Latitude'][:] >= select_lat - radius) & (
+                        cdffile['Latitude'][:] <= select_lat + radius))
+    """)  # noqa
+    expected_code = textwrap.dedent("""\
+        def _():
+            include_values = np.where(
+                (cdffile['Quality_Flag'][:] >= 5) & (cdffile['Day_Night_Flag'][:] == 1)
+                & (cdffile['Longitude'][:] >= select_lon - radius)
+                & (cdffile['Longitude'][:] <= select_lon + radius)
+                & (cdffile['Latitude'][:] >= select_lat - radius)
+                & (cdffile['Latitude'][:] <= select_lat + radius))
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertEqual(expected_code, reformatter.Reformat(llines))
 
   def testNoBlankLinesOnlyForFirstNestedObject(self):
-    unformatted_code = '''\
-class Demo:
-    """
-    Demo docs
-    """
-    def foo(self):
-        """
-        foo docs
-        """
-    def bar(self):
-        """
-        bar docs
-        """
-'''
-    expected_code = '''\
-class Demo:
-    """
-    Demo docs
-    """
-
-    def foo(self):
-        """
-        foo docs
-        """
-
-    def bar(self):
-        """
-        bar docs
-        """
-'''
+    unformatted_code = textwrap.dedent('''\
+        class Demo:
+            """
+            Demo docs
+            """
+            def foo(self):
+                """
+                foo docs
+                """
+            def bar(self):
+                """
+                bar docs
+                """
+    ''')
+    expected_code = textwrap.dedent('''\
+        class Demo:
+            """
+            Demo docs
+            """
+
+            def foo(self):
+                """
+                foo docs
+                """
+
+            def bar(self):
+                """
+                bar docs
+                """
+    ''')
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertEqual(expected_code, reformatter.Reformat(llines))
 
@@ -525,15 +524,15 @@ class Demo:
           style.CreateStyleFromConfig(
               '{based_on_style: pep8, split_before_arithmetic_operator: true}'))
 
-      unformatted_code = """\
-def _():
-    raise ValueError('This is a long message that ends with an argument: ' + str(42))
-"""  # noqa
-      expected_formatted_code = """\
-def _():
-    raise ValueError('This is a long message that ends with an argument: '
-                     + str(42))
-"""
+      unformatted_code = textwrap.dedent("""\
+        def _():
+            raise ValueError('This is a long message that ends with an argument: ' + str(42))
+      """)  # noqa
+      expected_formatted_code = textwrap.dedent("""\
+        def _():
+            raise ValueError('This is a long message that ends with an argument: '
+                             + str(42))
+      """)  # noqa
       llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
       self.assertCodeEqual(expected_formatted_code,
                            reformatter.Reformat(llines))
@@ -541,16 +540,16 @@ def _():
       style.SetGlobalStyle(style.CreatePEP8Style())
 
   def testListSplitting(self):
-    unformatted_code = """\
-foo([(1,1), (1,1), (1,1), (1,1), (1,1), (1,1), (1,1),
-     (1,1), (1,1), (1,1), (1,1), (1,1), (1,1), (1,1),
-     (1,10), (1,11), (1, 10), (1,11), (10,11)])
-"""
-    expected_code = """\
-foo([(1, 1), (1, 1), (1, 1), (1, 1), (1, 1), (1, 1), (1, 1), (1, 1), (1, 1),
-     (1, 1), (1, 1), (1, 1), (1, 1), (1, 1), (1, 10), (1, 11), (1, 10),
-     (1, 11), (10, 11)])
-"""
+    unformatted_code = textwrap.dedent("""\
+        foo([(1,1), (1,1), (1,1), (1,1), (1,1), (1,1), (1,1),
+             (1,1), (1,1), (1,1), (1,1), (1,1), (1,1), (1,1),
+             (1,10), (1,11), (1, 10), (1,11), (10,11)])
+    """)
+    expected_code = textwrap.dedent("""\
+        foo([(1, 1), (1, 1), (1, 1), (1, 1), (1, 1), (1, 1), (1, 1), (1, 1), (1, 1),
+             (1, 1), (1, 1), (1, 1), (1, 1), (1, 1), (1, 10), (1, 11), (1, 10),
+             (1, 11), (10, 11)])
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_code, reformatter.Reformat(llines))
 
@@ -561,34 +560,34 @@ foo([(1, 1), (1, 1), (1, 1), (1, 1), (1, 1), (1, 1), (1, 1), (1, 1), (1, 1),
               '{based_on_style: pep8, '
               'blank_line_before_nested_class_or_def: false}'))
 
-      unformatted_code = '''\
-def normal_function():
-    """Return the nested function."""
+      unformatted_code = textwrap.dedent('''\
+        def normal_function():
+            """Return the nested function."""
 
-    def nested_function():
-        """Do nothing just nest within."""
+            def nested_function():
+                """Do nothing just nest within."""
 
-        @nested(klass)
-        class nested_class():
-            pass
+                @nested(klass)
+                class nested_class():
+                    pass
 
-        pass
-
-    return nested_function
-'''
-      expected_formatted_code = '''\
-def normal_function():
-    """Return the nested function."""
-    def nested_function():
-        """Do nothing just nest within."""
-        @nested(klass)
-        class nested_class():
-            pass
+                pass
+
+            return nested_function
+      ''')
+      expected_formatted_code = textwrap.dedent('''\
+        def normal_function():
+            """Return the nested function."""
+            def nested_function():
+                """Do nothing just nest within."""
+                @nested(klass)
+                class nested_class():
+                    pass
 
-        pass
+                pass
 
-    return nested_function
-'''
+            return nested_function
+      ''')
       llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
       self.assertCodeEqual(expected_formatted_code,
                            reformatter.Reformat(llines))
@@ -597,29 +596,29 @@ def normal_function():
 
   def testParamListIndentationCollision1(self):
     unformatted_code = textwrap.dedent("""\
-class _():
-
-    def __init__(self, title: Optional[str], diffs: Collection[BinaryDiff] = (), charset: Union[Type[AsciiCharset], Type[LineCharset]] = AsciiCharset, preprocess: Callable[[str], str] = identity,
-            # TODO(somebody): Make this a Literal type.
-            justify: str = 'rjust'):
-        self._cs = charset
-        self._preprocess = preprocess
-        """)  # noqa
+        class _():
+
+            def __init__(self, title: Optional[str], diffs: Collection[BinaryDiff] = (), charset: Union[Type[AsciiCharset], Type[LineCharset]] = AsciiCharset, preprocess: Callable[[str], str] = identity,
+                    # TODO(somebody): Make this a Literal type.
+                    justify: str = 'rjust'):
+                self._cs = charset
+                self._preprocess = preprocess
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
-class _():
-
-    def __init__(
-            self,
-            title: Optional[str],
-            diffs: Collection[BinaryDiff] = (),
-            charset: Union[Type[AsciiCharset],
-                           Type[LineCharset]] = AsciiCharset,
-            preprocess: Callable[[str], str] = identity,
-            # TODO(somebody): Make this a Literal type.
-            justify: str = 'rjust'):
-        self._cs = charset
-        self._preprocess = preprocess
-        """)
+        class _():
+
+            def __init__(
+                    self,
+                    title: Optional[str],
+                    diffs: Collection[BinaryDiff] = (),
+                    charset: Union[Type[AsciiCharset],
+                                   Type[LineCharset]] = AsciiCharset,
+                    preprocess: Callable[[str], str] = identity,
+                    # TODO(somebody): Make this a Literal type.
+                    justify: str = 'rjust'):
+                self._cs = charset
+                self._preprocess = preprocess
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -628,7 +627,7 @@ class _():
         def simple_pass_function_with_an_extremely_long_name_and_some_arguments(
                 argument0, argument1):
             pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -646,7 +645,7 @@ class _():
             arg2,
         ):
             pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
@@ -654,40 +653,22 @@ class _():
     unformatted_code = textwrap.dedent("""\
         _ = (klsdfjdklsfjksdlfjdklsfjdslkfjsdkl is not ksldfjsdklfjdklsfjdklsfjdklsfjdsklfjdklsfj)
         _ = (klsdfjdklsfjksdlfjdklsfjdslkfjsdkl not in {ksldfjsdklfjdklsfjdklsfjdklsfjdsklfjdklsfj})
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         _ = (klsdfjdklsfjksdlfjdklsfjdslkfjsdkl
              is not ksldfjsdklfjdklsfjdklsfjdklsfjdsklfjdklsfj)
         _ = (klsdfjdklsfjksdlfjdklsfjdslkfjsdkl
              not in {ksldfjsdklfjdklsfjdklsfjdklsfjdsklfjdklsfj})
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
-  @unittest.skipUnless(not py3compat.PY3, 'Requires Python 2.7')
-  def testAsyncAsNonKeyword(self):
-    # In Python 2, async may be used as a non-keyword identifier.
-    code = textwrap.dedent("""\
-        from util import async
-
-
-        class A(object):
-
-            def foo(self):
-                async.run()
-
-            def bar(self):
-                pass
-        """)
-    llines = yapf_test_helper.ParseAndUnwrap(code)
-    self.assertCodeEqual(code, reformatter.Reformat(llines, verify=False))
-
   def testStableInlinedDictionaryFormatting(self):
     unformatted_code = textwrap.dedent("""\
         def _():
             url = "http://{0}/axis-cgi/admin/param.cgi?{1}".format(
                 value, urllib.urlencode({'action': 'update', 'parameter': value}))
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         def _():
             url = "http://{0}/axis-cgi/admin/param.cgi?{1}".format(
@@ -695,7 +676,7 @@ class _():
                     'action': 'update',
                     'parameter': value
                 }))
-        """)
+    """)
 
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     reformatted_code = reformatter.Reformat(llines)
@@ -705,114 +686,16 @@ class _():
     reformatted_code = reformatter.Reformat(llines)
     self.assertCodeEqual(expected_formatted_code, reformatted_code)
 
-  @unittest.skipUnless(py3compat.PY36, 'Requires Python 3.6')
-  def testSpaceBetweenColonAndElipses(self):
-    style.SetGlobalStyle(style.CreatePEP8Style())
-    code = textwrap.dedent("""\
-      class MyClass(ABC):
-
-          place: ...
-    """)
-    llines = yapf_test_helper.ParseAndUnwrap(code)
-    self.assertCodeEqual(code, reformatter.Reformat(llines, verify=False))
-
-  @unittest.skipUnless(py3compat.PY36, 'Requires Python 3.6')
-  def testSpaceBetweenDictColonAndElipses(self):
-    style.SetGlobalStyle(style.CreatePEP8Style())
-    unformatted_code = textwrap.dedent("""\
-      {0:"...", 1:...}
-    """)
-    expected_formatted_code = textwrap.dedent("""\
-      {0: "...", 1: ...}
-    """)
-
-    llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
-    self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
-
 
 class TestsForSpacesInsideBrackets(yapf_test_helper.YAPFTest):
   """Test the SPACE_INSIDE_BRACKETS style option."""
   unformatted_code = textwrap.dedent("""\
-    foo()
-    foo(1)
-    foo(1,2)
-    foo((1,))
-    foo((1, 2))
-    foo((1, 2,))
-    foo(bar['baz'][0])
-    set1 = {1, 2, 3}
-    dict1 = {1: 1, foo: 2, 3: bar}
-    dict2 = {
-        1: 1,
-        foo: 2,
-        3: bar,
-    }
-    dict3[3][1][get_index(*args,**kwargs)]
-    dict4[3][1][get_index(**kwargs)]
-    x = dict5[4](foo(*args))
-    a = list1[:]
-    b = list2[slice_start:]
-    c = list3[slice_start:slice_end]
-    d = list4[slice_start:slice_end:]
-    e = list5[slice_start:slice_end:slice_step]
-    # Print gets special handling
-    print(set2)
-    compound = ((10+3)/(5-2**(6+x)))
-    string_idx = "mystring"[3]
-    """)
-
-  def testEnabled(self):
-    style.SetGlobalStyle(
-        style.CreateStyleFromConfig('{space_inside_brackets: True}'))
-
-    expected_formatted_code = textwrap.dedent("""\
-      foo()
-      foo( 1 )
-      foo( 1, 2 )
-      foo( ( 1, ) )
-      foo( ( 1, 2 ) )
-      foo( (
-          1,
-          2,
-      ) )
-      foo( bar[ 'baz' ][ 0 ] )
-      set1 = { 1, 2, 3 }
-      dict1 = { 1: 1, foo: 2, 3: bar }
-      dict2 = {
-          1: 1,
-          foo: 2,
-          3: bar,
-      }
-      dict3[ 3 ][ 1 ][ get_index( *args, **kwargs ) ]
-      dict4[ 3 ][ 1 ][ get_index( **kwargs ) ]
-      x = dict5[ 4 ]( foo( *args ) )
-      a = list1[ : ]
-      b = list2[ slice_start: ]
-      c = list3[ slice_start:slice_end ]
-      d = list4[ slice_start:slice_end: ]
-      e = list5[ slice_start:slice_end:slice_step ]
-      # Print gets special handling
-      print( set2 )
-      compound = ( ( 10 + 3 ) / ( 5 - 2**( 6 + x ) ) )
-      string_idx = "mystring"[ 3 ]
-      """)
-
-    llines = yapf_test_helper.ParseAndUnwrap(self.unformatted_code)
-    self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
-
-  def testDefault(self):
-    style.SetGlobalStyle(style.CreatePEP8Style())
-
-    expected_formatted_code = textwrap.dedent("""\
       foo()
       foo(1)
-      foo(1, 2)
-      foo((1, ))
+      foo(1,2)
+      foo((1,))
       foo((1, 2))
-      foo((
-          1,
-          2,
-      ))
+      foo((1, 2,))
       foo(bar['baz'][0])
       set1 = {1, 2, 3}
       dict1 = {1: 1, foo: 2, 3: bar}
@@ -821,7 +704,7 @@ class TestsForSpacesInsideBrackets(yapf_test_helper.YAPFTest):
           foo: 2,
           3: bar,
       }
-      dict3[3][1][get_index(*args, **kwargs)]
+      dict3[3][1][get_index(*args,**kwargs)]
       dict4[3][1][get_index(**kwargs)]
       x = dict5[4](foo(*args))
       a = list1[:]
@@ -831,99 +714,136 @@ class TestsForSpacesInsideBrackets(yapf_test_helper.YAPFTest):
       e = list5[slice_start:slice_end:slice_step]
       # Print gets special handling
       print(set2)
-      compound = ((10 + 3) / (5 - 2**(6 + x)))
+      compound = ((10+3)/(5-2**(6+x)))
       string_idx = "mystring"[3]
-      """)
-
-    llines = yapf_test_helper.ParseAndUnwrap(self.unformatted_code)
-    self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
+  """)
 
-  @unittest.skipUnless(py3compat.PY36, 'Requires Python 3.6')
-  def testAwait(self):
+  def testEnabled(self):
     style.SetGlobalStyle(
         style.CreateStyleFromConfig('{space_inside_brackets: True}'))
-    unformatted_code = textwrap.dedent("""\
-      import asyncio
-      import time
-
-      @print_args
-      async def slow_operation():
-        await asyncio.sleep(1)
-        # print("Slow operation {} complete".format(n))
-        async def main():
-          start = time.time()
-          if (await get_html()):
-            pass
-      """)
+
     expected_formatted_code = textwrap.dedent("""\
-      import asyncio
-      import time
+        foo()
+        foo( 1 )
+        foo( 1, 2 )
+        foo( ( 1, ) )
+        foo( ( 1, 2 ) )
+        foo( (
+            1,
+            2,
+        ) )
+        foo( bar[ 'baz' ][ 0 ] )
+        set1 = { 1, 2, 3 }
+        dict1 = { 1: 1, foo: 2, 3: bar }
+        dict2 = {
+            1: 1,
+            foo: 2,
+            3: bar,
+        }
+        dict3[ 3 ][ 1 ][ get_index( *args, **kwargs ) ]
+        dict4[ 3 ][ 1 ][ get_index( **kwargs ) ]
+        x = dict5[ 4 ]( foo( *args ) )
+        a = list1[ : ]
+        b = list2[ slice_start: ]
+        c = list3[ slice_start:slice_end ]
+        d = list4[ slice_start:slice_end: ]
+        e = list5[ slice_start:slice_end:slice_step ]
+        # Print gets special handling
+        print( set2 )
+        compound = ( ( 10 + 3 ) / ( 5 - 2**( 6 + x ) ) )
+        string_idx = "mystring"[ 3 ]
+   """)
 
+    llines = yapf_test_helper.ParseAndUnwrap(self.unformatted_code)
+    self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
-      @print_args
-      async def slow_operation():
-          await asyncio.sleep( 1 )
+  def testDefault(self):
+    style.SetGlobalStyle(style.CreatePEP8Style())
 
-          # print("Slow operation {} complete".format(n))
-          async def main():
-              start = time.time()
-              if ( await get_html() ):
-                  pass
-      """)
-    llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
+    expected_formatted_code = textwrap.dedent("""\
+        foo()
+        foo(1)
+        foo(1, 2)
+        foo((1, ))
+        foo((1, 2))
+        foo((
+            1,
+            2,
+        ))
+        foo(bar['baz'][0])
+        set1 = {1, 2, 3}
+        dict1 = {1: 1, foo: 2, 3: bar}
+        dict2 = {
+            1: 1,
+            foo: 2,
+            3: bar,
+        }
+        dict3[3][1][get_index(*args, **kwargs)]
+        dict4[3][1][get_index(**kwargs)]
+        x = dict5[4](foo(*args))
+        a = list1[:]
+        b = list2[slice_start:]
+        c = list3[slice_start:slice_end]
+        d = list4[slice_start:slice_end:]
+        e = list5[slice_start:slice_end:slice_step]
+        # Print gets special handling
+        print(set2)
+        compound = ((10 + 3) / (5 - 2**(6 + x)))
+        string_idx = "mystring"[3]
+    """)
+
+    llines = yapf_test_helper.ParseAndUnwrap(self.unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
 
 class TestsForSpacesAroundSubscriptColon(yapf_test_helper.YAPFTest):
   """Test the SPACES_AROUND_SUBSCRIPT_COLON style option."""
   unformatted_code = textwrap.dedent("""\
-    a = list1[ : ]
-    b = list2[ slice_start: ]
-    c = list3[ slice_start:slice_end ]
-    d = list4[ slice_start:slice_end: ]
-    e = list5[ slice_start:slice_end:slice_step ]
-    a1 = list1[ : ]
-    b1 = list2[ 1: ]
-    c1 = list3[ 1:20 ]
-    d1 = list4[ 1:20: ]
-    e1 = list5[ 1:20:3 ]
+      a = list1[ : ]
+      b = list2[ slice_start: ]
+      c = list3[ slice_start:slice_end ]
+      d = list4[ slice_start:slice_end: ]
+      e = list5[ slice_start:slice_end:slice_step ]
+      a1 = list1[ : ]
+      b1 = list2[ 1: ]
+      c1 = list3[ 1:20 ]
+      d1 = list4[ 1:20: ]
+      e1 = list5[ 1:20:3 ]
   """)
 
   def testEnabled(self):
     style.SetGlobalStyle(
         style.CreateStyleFromConfig('{spaces_around_subscript_colon: True}'))
     expected_formatted_code = textwrap.dedent("""\
-      a = list1[:]
-      b = list2[slice_start :]
-      c = list3[slice_start : slice_end]
-      d = list4[slice_start : slice_end :]
-      e = list5[slice_start : slice_end : slice_step]
-      a1 = list1[:]
-      b1 = list2[1 :]
-      c1 = list3[1 : 20]
-      d1 = list4[1 : 20 :]
-      e1 = list5[1 : 20 : 3]
+        a = list1[:]
+        b = list2[slice_start :]
+        c = list3[slice_start : slice_end]
+        d = list4[slice_start : slice_end :]
+        e = list5[slice_start : slice_end : slice_step]
+        a1 = list1[:]
+        b1 = list2[1 :]
+        c1 = list3[1 : 20]
+        d1 = list4[1 : 20 :]
+        e1 = list5[1 : 20 : 3]
     """)
     llines = yapf_test_helper.ParseAndUnwrap(self.unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testWithSpaceInsideBrackets(self):
     style.SetGlobalStyle(
-        style.CreateStyleFromConfig('{'
-                                    'spaces_around_subscript_colon: true, '
-                                    'space_inside_brackets: true,'
-                                    '}'))
+        style.CreateStyleFromConfig('{spaces_around_subscript_colon: true, '
+                                    'space_inside_brackets: true,}'))
     expected_formatted_code = textwrap.dedent("""\
-      a = list1[ : ]
-      b = list2[ slice_start : ]
-      c = list3[ slice_start : slice_end ]
-      d = list4[ slice_start : slice_end : ]
-      e = list5[ slice_start : slice_end : slice_step ]
-      a1 = list1[ : ]
-      b1 = list2[ 1 : ]
-      c1 = list3[ 1 : 20 ]
-      d1 = list4[ 1 : 20 : ]
-      e1 = list5[ 1 : 20 : 3 ]
+        a = list1[ : ]
+        b = list2[ slice_start : ]
+        c = list3[ slice_start : slice_end ]
+        d = list4[ slice_start : slice_end : ]
+        e = list5[ slice_start : slice_end : slice_step ]
+        a1 = list1[ : ]
+        b1 = list2[ 1 : ]
+        c1 = list3[ 1 : 20 ]
+        d1 = list4[ 1 : 20 : ]
+        e1 = list5[ 1 : 20 : 3 ]
     """)
     llines = yapf_test_helper.ParseAndUnwrap(self.unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
@@ -931,16 +851,16 @@ class TestsForSpacesAroundSubscriptColon(yapf_test_helper.YAPFTest):
   def testDefault(self):
     style.SetGlobalStyle(style.CreatePEP8Style())
     expected_formatted_code = textwrap.dedent("""\
-      a = list1[:]
-      b = list2[slice_start:]
-      c = list3[slice_start:slice_end]
-      d = list4[slice_start:slice_end:]
-      e = list5[slice_start:slice_end:slice_step]
-      a1 = list1[:]
-      b1 = list2[1:]
-      c1 = list3[1:20]
-      d1 = list4[1:20:]
-      e1 = list5[1:20:3]
+        a = list1[:]
+        b = list2[slice_start:]
+        c = list3[slice_start:slice_end]
+        d = list4[slice_start:slice_end:]
+        e = list5[slice_start:slice_end:slice_step]
+        a1 = list1[:]
+        b1 = list2[1:]
+        c1 = list3[1:20]
+        d1 = list4[1:20:]
+        e1 = list5[1:20:3]
     """)
     llines = yapf_test_helper.ParseAndUnwrap(self.unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
diff --git a/yapftests/reformatter_python3_test.py b/yapftests/reformatter_python3_test.py
index b5d68e8..f5741b3 100644
--- a/yapftests/reformatter_python3_test.py
+++ b/yapftests/reformatter_python3_test.py
@@ -17,14 +17,12 @@ import sys
 import textwrap
 import unittest
 
-from yapf.yapflib import py3compat
 from yapf.yapflib import reformatter
 from yapf.yapflib import style
 
 from yapftests import yapf_test_helper
 
 
-@unittest.skipUnless(py3compat.PY3, 'Requires Python 3')
 class TestsForPython3Code(yapf_test_helper.YAPFTest):
   """Test a few constructs that are new Python 3 syntax."""
 
@@ -36,14 +34,14 @@ class TestsForPython3Code(yapf_test_helper.YAPFTest):
     unformatted_code = textwrap.dedent("""\
         def x(aaaaaaaaaaaaaaa:int,bbbbbbbbbbbbbbbb:str,ccccccccccccccc:dict,eeeeeeeeeeeeee:set={1, 2, 3})->bool:
           pass
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         def x(aaaaaaaaaaaaaaa: int,
               bbbbbbbbbbbbbbbb: str,
               ccccccccccccccc: dict,
               eeeeeeeeeeeeee: set = {1, 2, 3}) -> bool:
             pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -51,12 +49,12 @@ class TestsForPython3Code(yapf_test_helper.YAPFTest):
     unformatted_code = textwrap.dedent("""\
         def func(arg=long_function_call_that_pushes_the_line_over_eighty_characters()) -> ReturnType:
           pass
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         def func(arg=long_function_call_that_pushes_the_line_over_eighty_characters()
                  ) -> ReturnType:
             pass
-        """)  # noqa
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -64,27 +62,10 @@ class TestsForPython3Code(yapf_test_helper.YAPFTest):
     unformatted_code = textwrap.dedent("""\
         def foo(a, *, kw):
           return a+kw
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         def foo(a, *, kw):
             return a + kw
-        """)
-    llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
-    self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
-
-  @unittest.skipUnless(py3compat.PY36, 'Requires Python 3.6')
-  def testPEP448ParameterExpansion(self):
-    unformatted_code = textwrap.dedent("""\
-    { ** x }
-    {   **{}   }
-    { **{   **x },  **x }
-    {'a': 1,   **kw , 'b':3,  **kw2   }
-    """)
-    expected_formatted_code = textwrap.dedent("""\
-    {**x}
-    {**{}}
-    {**{**x}, **x}
-    {'a': 1, **kw, 'b': 3, **kw2}
     """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
@@ -93,11 +74,11 @@ class TestsForPython3Code(yapf_test_helper.YAPFTest):
     unformatted_code = textwrap.dedent("""\
         def foo(a: list, b: "bar") -> dict:
           return a+b
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         def foo(a: list, b: "bar") -> dict:
             return a + b
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -108,8 +89,6 @@ class TestsForPython3Code(yapf_test_helper.YAPFTest):
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testAsyncFunctions(self):
-    if sys.version_info[1] < 5:
-      return
     code = textwrap.dedent("""\
         import asyncio
         import time
@@ -125,17 +104,17 @@ class TestsForPython3Code(yapf_test_helper.YAPFTest):
             start = time.time()
             if (await get_html()):
                 pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
-    self.assertCodeEqual(code, reformatter.Reformat(llines, verify=False))
+    self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testNoSpacesAroundPowerOperator(self):
     unformatted_code = textwrap.dedent("""\
         a**b
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         a ** b
-        """)
+    """)
 
     try:
       style.SetGlobalStyle(
@@ -151,10 +130,10 @@ class TestsForPython3Code(yapf_test_helper.YAPFTest):
   def testSpacesAroundDefaultOrNamedAssign(self):
     unformatted_code = textwrap.dedent("""\
         f(a=5)
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         f(a = 5)
-        """)
+    """)
 
     try:
       style.SetGlobalStyle(
@@ -176,7 +155,7 @@ class TestsForPython3Code(yapf_test_helper.YAPFTest):
 
         def foo2(x: 'int' =42):
             pass
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         def foo(x: int = 42):
             pass
@@ -184,30 +163,28 @@ class TestsForPython3Code(yapf_test_helper.YAPFTest):
 
         def foo2(x: 'int' = 42):
             pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testMatrixMultiplication(self):
     unformatted_code = textwrap.dedent("""\
         a=b@c
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         a = b @ c
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testNoneKeyword(self):
-    code = """\
-None.__ne__()
-"""
+    code = textwrap.dedent("""\
+        None.__ne__()
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testAsyncWithPrecedingComment(self):
-    if sys.version_info[1] < 5:
-      return
     unformatted_code = textwrap.dedent("""\
         import asyncio
 
@@ -217,7 +194,7 @@ None.__ne__()
 
         async def foo():
             pass
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         import asyncio
 
@@ -229,111 +206,102 @@ None.__ne__()
 
         async def foo():
             pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testAsyncFunctionsNested(self):
-    if sys.version_info[1] < 5:
-      return
     code = textwrap.dedent("""\
         async def outer():
 
             async def inner():
                 pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testKeepTypesIntact(self):
-    if sys.version_info[1] < 5:
-      return
     unformatted_code = textwrap.dedent("""\
         def _ReduceAbstractContainers(
             self, *args: Optional[automation_converter.PyiCollectionAbc]) -> List[
                 automation_converter.PyiCollectionAbc]:
             pass
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         def _ReduceAbstractContainers(
             self, *args: Optional[automation_converter.PyiCollectionAbc]
         ) -> List[automation_converter.PyiCollectionAbc]:
             pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testContinuationIndentWithAsync(self):
-    if sys.version_info[1] < 5:
-      return
     unformatted_code = textwrap.dedent("""\
         async def start_websocket():
             async with session.ws_connect(
                 r"ws://a_really_long_long_long_long_long_long_url") as ws:
                 pass
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         async def start_websocket():
             async with session.ws_connect(
                     r"ws://a_really_long_long_long_long_long_long_url") as ws:
                 pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testSplittingArguments(self):
-    if sys.version_info[1] < 5:
-      return
-
-    unformatted_code = """\
-async def open_file(file, mode='r', buffering=-1, encoding=None, errors=None, newline=None, closefd=True, opener=None):
-    pass
-
-async def run_sync_in_worker_thread(sync_fn, *args, cancellable=False, limiter=None):
-    pass
-
-def open_file(file, mode='r', buffering=-1, encoding=None, errors=None, newline=None, closefd=True, opener=None):
-    pass
-
-def run_sync_in_worker_thread(sync_fn, *args, cancellable=False, limiter=None):
-    pass
-"""  # noqa
-    expected_formatted_code = """\
-async def open_file(
-    file,
-    mode='r',
-    buffering=-1,
-    encoding=None,
-    errors=None,
-    newline=None,
-    closefd=True,
-    opener=None
-):
-    pass
-
-
-async def run_sync_in_worker_thread(
-    sync_fn, *args, cancellable=False, limiter=None
-):
-    pass
-
-
-def open_file(
-    file,
-    mode='r',
-    buffering=-1,
-    encoding=None,
-    errors=None,
-    newline=None,
-    closefd=True,
-    opener=None
-):
-    pass
-
-
-def run_sync_in_worker_thread(sync_fn, *args, cancellable=False, limiter=None):
-    pass
-"""
+    unformatted_code = textwrap.dedent("""\
+        async def open_file(file, mode='r', buffering=-1, encoding=None, errors=None, newline=None, closefd=True, opener=None):
+            pass
+
+        async def run_sync_in_worker_thread(sync_fn, *args, cancellable=False, limiter=None):
+            pass
+
+        def open_file(file, mode='r', buffering=-1, encoding=None, errors=None, newline=None, closefd=True, opener=None):
+            pass
+
+        def run_sync_in_worker_thread(sync_fn, *args, cancellable=False, limiter=None):
+            pass
+    """)  # noqa
+    expected_formatted_code = textwrap.dedent("""\
+        async def open_file(
+            file,
+            mode='r',
+            buffering=-1,
+            encoding=None,
+            errors=None,
+            newline=None,
+            closefd=True,
+            opener=None
+        ):
+            pass
+
+
+        async def run_sync_in_worker_thread(
+            sync_fn, *args, cancellable=False, limiter=None
+        ):
+            pass
+
+
+        def open_file(
+            file,
+            mode='r',
+            buffering=-1,
+            encoding=None,
+            errors=None,
+            newline=None,
+            closefd=True,
+            opener=None
+        ):
+            pass
+
+
+        def run_sync_in_worker_thread(sync_fn, *args, cancellable=False, limiter=None):
+            pass
+    """)  # noqa
 
     try:
       style.SetGlobalStyle(
@@ -352,99 +320,89 @@ def run_sync_in_worker_thread(sync_fn, *args, cancellable=False, limiter=None):
       style.SetGlobalStyle(style.CreatePEP8Style())
 
   def testDictUnpacking(self):
-    if sys.version_info[1] < 5:
-      return
-    unformatted_code = """\
-class Foo:
-    def foo(self):
-        foofoofoofoofoofoofoofoo('foofoofoofoofoo', {
-
-            'foo': 'foo',
-
-            **foofoofoo
-        })
-"""
-    expected_formatted_code = """\
-class Foo:
-
-    def foo(self):
-        foofoofoofoofoofoofoofoo('foofoofoofoofoo', {
-            'foo': 'foo',
-            **foofoofoo
-        })
-"""
+    unformatted_code = textwrap.dedent("""\
+        class Foo:
+            def foo(self):
+                foofoofoofoofoofoofoofoo('foofoofoofoofoo', {
+
+                    'foo': 'foo',
+
+                    **foofoofoo
+                })
+    """)
+    expected_formatted_code = textwrap.dedent("""\
+        class Foo:
+
+            def foo(self):
+                foofoofoofoofoofoofoofoo('foofoofoofoofoo', {
+                    'foo': 'foo',
+                    **foofoofoo
+                })
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
   def testMultilineFormatString(self):
-    if sys.version_info[1] < 6:
-      return
-    code = """\
-# yapf: disable
-(f'''
-  ''')
-# yapf: enable
-"""
     # https://github.com/google/yapf/issues/513
+    code = textwrap.dedent("""\
+        # yapf: disable
+        (f'''
+          ''')
+        # yapf: enable
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testEllipses(self):
-    if sys.version_info[1] < 6:
-      return
-    code = """\
-def dirichlet(x12345678901234567890123456789012345678901234567890=...) -> None:
-    return
-"""
     # https://github.com/google/yapf/issues/533
+    code = textwrap.dedent("""\
+        def dirichlet(x12345678901234567890123456789012345678901234567890=...) -> None:
+            return
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testFunctionTypedReturnNextLine(self):
-    code = """\
-def _GenerateStatsEntries(
-    process_id: Text,
-    timestamp: Optional[ffffffff.FFFFFFFFFFF] = None
-) -> Sequence[ssssssssssss.SSSSSSSSSSSSSSS]:
-    pass
-"""
+    code = textwrap.dedent("""\
+        def _GenerateStatsEntries(
+            process_id: Text,
+            timestamp: Optional[ffffffff.FFFFFFFFFFF] = None
+        ) -> Sequence[ssssssssssss.SSSSSSSSSSSSSSS]:
+            pass
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testFunctionTypedReturnSameLine(self):
-    code = """\
-def rrrrrrrrrrrrrrrrrrrrrr(
-        ccccccccccccccccccccccc: Tuple[Text, Text]) -> List[Tuple[Text, Text]]:
-    pass
-"""
+    code = textwrap.dedent("""\
+        def rrrrrrrrrrrrrrrrrrrrrr(
+                ccccccccccccccccccccccc: Tuple[Text, Text]) -> List[Tuple[Text, Text]]:
+            pass
+    """)  # noqa
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testAsyncForElseNotIndentedInsideBody(self):
-    if sys.version_info[1] < 5:
-      return
     code = textwrap.dedent("""\
-    async def fn():
-        async for message in websocket:
-            for i in range(10):
-                pass
+        async def fn():
+            async for message in websocket:
+                for i in range(10):
+                    pass
+                else:
+                    pass
             else:
                 pass
-        else:
-            pass
     """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
 
   def testForElseInAsyncNotMixedWithAsyncFor(self):
-    if sys.version_info[1] < 5:
-      return
     code = textwrap.dedent("""\
-    async def fn():
-        for i in range(10):
-            pass
-        else:
-            pass
+        async def fn():
+            for i in range(10):
+                pass
+            else:
+                pass
     """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self.assertCodeEqual(code, reformatter.Reformat(llines))
@@ -454,7 +412,7 @@ def rrrrrrrrrrrrrrrrrrrrrr(
         def raw_message(  # pylint: disable=too-many-arguments
                     self, text, user_id=1000, chat_type='private', forward_date=None, forward_from=None):
                 pass
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         def raw_message(  # pylint: disable=too-many-arguments
                 self,
@@ -464,10 +422,148 @@ def rrrrrrrrrrrrrrrrrrrrrr(
                 forward_date=None,
                 forward_from=None):
             pass
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
+  def testTypeHintedYieldExpression(self):
+    # https://github.com/google/yapf/issues/1092
+    code = textwrap.dedent("""\
+       def my_coroutine():
+           x: int = yield
+    """)
+    llines = yapf_test_helper.ParseAndUnwrap(code)
+    self.assertCodeEqual(code, reformatter.Reformat(llines))
+
+  def testSyntaxMatch(self):
+    # https://github.com/google/yapf/issues/1045
+    # https://github.com/google/yapf/issues/1085
+    unformatted_code = textwrap.dedent("""\
+        a=3
+        b=0
+        match a :
+            case 0 :
+                b=1
+            case _	:
+                b=2
+    """)
+    expected_formatted_code = textwrap.dedent("""\
+        a = 3
+        b = 0
+        match a:
+            case 0:
+                b = 1
+            case _:
+                b = 2
+    """)
+    llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
+    self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
+
+  def testParenthsizedContextManager(self):
+    # https://github.com/google/yapf/issues/1064
+    unformatted_code = textwrap.dedent("""\
+        def test_copy_dimension(self):
+            with (Dataset() as target_ds,
+                  Dataset() as source_ds):
+                do_something
+    """)
+    expected_formatted_code = textwrap.dedent("""\
+        def test_copy_dimension(self):
+            with (Dataset() as target_ds, Dataset() as source_ds):
+                do_something
+    """)
+    llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
+    self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
+
+  def testUnpackedTuple(self):
+    # https://github.com/google/yapf/issues/830
+    # https://github.com/google/yapf/issues/1060
+    unformatted_code = textwrap.dedent("""\
+        def a():
+          t = (2,3)
+          for i in range(5):
+            yield i,*t
+    """)
+    expected_formatted_code = textwrap.dedent("""\
+        def a():
+            t = (2, 3)
+            for i in range(5):
+                yield i, *t
+    """)
+    llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
+    self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
+
+  def testTypedTuple(self):
+    # https://github.com/google/yapf/issues/412
+    # https://github.com/google/yapf/issues/1058
+    code = textwrap.dedent("""\
+        t: tuple = 1, 2
+        args = tuple(x for x in [2], )
+    """)
+    llines = yapf_test_helper.ParseAndUnwrap(code)
+    self.assertCodeEqual(code, reformatter.Reformat(llines))
+
+  def testWalrusOperator(self):
+    # https://github.com/google/yapf/issues/894
+    unformatted_code = textwrap.dedent("""\
+        import os
+        a=[1,2,3,4]
+        if (n:=len(a))>2:
+            print()
+    """)
+    expected_formatted_code = textwrap.dedent("""\
+        import os
+
+        a = [1, 2, 3, 4]
+        if (n := len(a)) > 2:
+            print()
+    """)
+    llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
+    self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
+
+  def testCondAssign(self):
+    # https://github.com/google/yapf/issues/856
+    unformatted_code = textwrap.dedent("""\
+        def json(self) -> JSONTask:
+                result: JSONTask = {
+                    "id": self.id,
+                    "text": self.text,
+                    "status": self.status,
+                    "last_mod": self.last_mod_time
+                }
+                for i in "parent_id", "deadline", "reminder":
+                    if x := getattr(self , i):
+                        result[i] = x  # type: ignore
+                return result
+    """)
+    expected_formatted_code = textwrap.dedent("""\
+        def json(self) -> JSONTask:
+            result: JSONTask = {
+                "id": self.id,
+                "text": self.text,
+                "status": self.status,
+                "last_mod": self.last_mod_time
+            }
+            for i in "parent_id", "deadline", "reminder":
+                if x := getattr(self, i):
+                    result[i] = x  # type: ignore
+            return result
+    """)
+    llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
+    self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
+
+  def testCopyDictionary(self):
+    # https://github.com/google/yapf/issues/233
+    # https://github.com/google/yapf/issues/402
+    code = textwrap.dedent("""\
+        a_dict = {'key': 'value'}
+        a_dict_copy = {**a_dict}
+        print('a_dict:', a_dict)
+        print('a_dict_copy:', a_dict_copy)
+    """)
+    llines = yapf_test_helper.ParseAndUnwrap(code)
+    self.assertCodeEqual(code, reformatter.Reformat(llines))
+
 
 if __name__ == '__main__':
   unittest.main()
diff --git a/yapftests/reformatter_style_config_test.py b/yapftests/reformatter_style_config_test.py
index c5726cb..6458a0a 100644
--- a/yapftests/reformatter_style_config_test.py
+++ b/yapftests/reformatter_style_config_test.py
@@ -30,14 +30,14 @@ class TestsForStyleConfig(yapf_test_helper.YAPFTest):
   def testSetGlobalStyle(self):
     try:
       style.SetGlobalStyle(style.CreateYapfStyle())
-      unformatted_code = textwrap.dedent(u"""\
+      unformatted_code = textwrap.dedent("""\
           for i in range(5):
            print('bar')
-          """)
-      expected_formatted_code = textwrap.dedent(u"""\
+      """)
+      expected_formatted_code = textwrap.dedent("""\
           for i in range(5):
             print('bar')
-          """)
+      """)
       llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
       self.assertCodeEqual(expected_formatted_code,
                            reformatter.Reformat(llines))
@@ -45,14 +45,14 @@ class TestsForStyleConfig(yapf_test_helper.YAPFTest):
       style.SetGlobalStyle(style.CreatePEP8Style())
       style.DEFAULT_STYLE = self.current_style
 
-    unformatted_code = textwrap.dedent(u"""\
+    unformatted_code = textwrap.dedent("""\
         for i in range(5):
          print('bar')
-        """)
-    expected_formatted_code = textwrap.dedent(u"""\
+    """)
+    expected_formatted_code = textwrap.dedent("""\
         for i in range(5):
             print('bar')
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
     self.assertCodeEqual(expected_formatted_code, reformatter.Reformat(llines))
 
@@ -65,11 +65,11 @@ class TestsForStyleConfig(yapf_test_helper.YAPFTest):
       unformatted_code = textwrap.dedent("""\
           a = 1+2 * 3 - 4 / 5
           b = '0' * 1
-          """)
+      """)
       expected_formatted_code = textwrap.dedent("""\
           a = 1 + 2*3 - 4/5
           b = '0'*1
-          """)
+      """)
 
       llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
       self.assertCodeEqual(expected_formatted_code,
@@ -97,7 +97,7 @@ class TestsForStyleConfig(yapf_test_helper.YAPFTest):
           i = 1 * 2 / 3 * 4
           j = (1 * 2 - 3) + 4
           k = (1 * 2 * 3) + (4 * 5 * 6 * 7 * 8)
-          """)
+      """)
       expected_formatted_code = textwrap.dedent("""\
           1 + 2
           (1+2) * (3 - (4/5))
@@ -112,7 +112,7 @@ class TestsForStyleConfig(yapf_test_helper.YAPFTest):
           i = 1 * 2 / 3 * 4
           j = (1*2 - 3) + 4
           k = (1*2*3) + (4*5*6*7*8)
-          """)
+      """)
 
       llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
       self.assertCodeEqual(expected_formatted_code,
@@ -155,7 +155,7 @@ class TestsForStyleConfig(yapf_test_helper.YAPFTest):
 
           plt.plot(veryverylongvariablename, veryverylongvariablename, marker="x",
                    color="r")
-          """)  # noqa
+      """)  # noqa
       llines = yapf_test_helper.ParseAndUnwrap(formatted_code)
       self.assertCodeEqual(formatted_code, reformatter.Reformat(llines))
     finally:
@@ -186,7 +186,7 @@ class TestsForStyleConfig(yapf_test_helper.YAPFTest):
                    veryverylongvariablename,
                    marker="x",
                    color="r")
-          """)
+      """)
       llines = yapf_test_helper.ParseAndUnwrap(formatted_code)
       self.assertCodeEqual(formatted_code, reformatter.Reformat(llines))
     finally:
diff --git a/yapftests/reformatter_verify_test.py b/yapftests/reformatter_verify_test.py
deleted file mode 100644
index 33ba3a6..0000000
--- a/yapftests/reformatter_verify_test.py
+++ /dev/null
@@ -1,100 +0,0 @@
-# Copyright 2016 Google Inc. All Rights Reserved.
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#     http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-"""Tests for yapf.reformatter."""
-
-import textwrap
-import unittest
-
-from yapf.yapflib import py3compat
-from yapf.yapflib import reformatter
-from yapf.yapflib import style
-from yapf.yapflib import verifier
-
-from yapftests import yapf_test_helper
-
-
-@unittest.skipIf(py3compat.PY3, 'Requires Python 2')
-class TestVerifyNoVerify(yapf_test_helper.YAPFTest):
-
-  @classmethod
-  def setUpClass(cls):
-    style.SetGlobalStyle(style.CreatePEP8Style())
-
-  def testVerifyException(self):
-    unformatted_code = textwrap.dedent("""\
-        class ABC(metaclass=type):
-          pass
-        """)
-    llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
-    with self.assertRaises(verifier.InternalError):
-      reformatter.Reformat(llines, verify=True)
-    reformatter.Reformat(llines)  # verify should be False by default.
-
-  def testNoVerify(self):
-    unformatted_code = textwrap.dedent("""\
-        class ABC(metaclass=type):
-          pass
-        """)
-    expected_formatted_code = textwrap.dedent("""\
-        class ABC(metaclass=type):
-            pass
-        """)
-    llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
-    self.assertCodeEqual(expected_formatted_code,
-                         reformatter.Reformat(llines, verify=False))
-
-  def testVerifyFutureImport(self):
-    unformatted_code = textwrap.dedent("""\
-        from __future__ import print_function
-
-        def call_my_function(the_function):
-          the_function("hi")
-
-        if __name__ == "__main__":
-          call_my_function(print)
-        """)
-    llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
-    with self.assertRaises(verifier.InternalError):
-      reformatter.Reformat(llines, verify=True)
-
-    expected_formatted_code = textwrap.dedent("""\
-        from __future__ import print_function
-
-
-        def call_my_function(the_function):
-            the_function("hi")
-
-
-        if __name__ == "__main__":
-            call_my_function(print)
-        """)
-    llines = yapf_test_helper.ParseAndUnwrap(unformatted_code)
-    self.assertCodeEqual(expected_formatted_code,
-                         reformatter.Reformat(llines, verify=False))
-
-  def testContinuationLineShouldBeDistinguished(self):
-    code = textwrap.dedent("""\
-        class Foo(object):
-
-            def bar(self):
-                if self.solo_generator_that_is_long is None and len(
-                        self.generators + self.next_batch) == 1:
-                    pass
-        """)
-    llines = yapf_test_helper.ParseAndUnwrap(code)
-    self.assertCodeEqual(code, reformatter.Reformat(llines, verify=False))
-
-
-if __name__ == '__main__':
-  unittest.main()
diff --git a/yapftests/split_penalty_test.py b/yapftests/split_penalty_test.py
index 4d55129..dd5d059 100644
--- a/yapftests/split_penalty_test.py
+++ b/yapftests/split_penalty_test.py
@@ -17,11 +17,11 @@ import sys
 import textwrap
 import unittest
 
-from lib2to3 import pytree
+from yapf_third_party._ylib2to3 import pytree
 
-from yapf.yapflib import pytree_utils
-from yapf.yapflib import pytree_visitor
-from yapf.yapflib import split_penalty
+from yapf.pytree import pytree_utils
+from yapf.pytree import pytree_visitor
+from yapf.pytree import split_penalty
 from yapf.yapflib import style
 
 from yapftests import yapf_test_helper
@@ -80,10 +80,10 @@ class SplitPenaltyTest(yapf_test_helper.YAPFTest):
 
   def testUnbreakable(self):
     # Test function definitions.
-    code = textwrap.dedent(r"""
-      def foo(x):
-        pass
-      """)
+    code = textwrap.dedent("""\
+        def foo(x):
+          pass
+    """)
     tree = self._ParseAndComputePenalties(code)
     self._CheckPenalties(tree, [
         ('def', None),
@@ -96,10 +96,10 @@ class SplitPenaltyTest(yapf_test_helper.YAPFTest):
     ])
 
     # Test function definition with trailing comment.
-    code = textwrap.dedent(r"""
-      def foo(x):  # trailing comment
-        pass
-      """)
+    code = textwrap.dedent("""\
+        def foo(x):  # trailing comment
+          pass
+    """)
     tree = self._ParseAndComputePenalties(code)
     self._CheckPenalties(tree, [
         ('def', None),
@@ -112,12 +112,12 @@ class SplitPenaltyTest(yapf_test_helper.YAPFTest):
     ])
 
     # Test class definitions.
-    code = textwrap.dedent(r"""
-      class A:
-        pass
-      class B(A):
-        pass
-      """)
+    code = textwrap.dedent("""\
+        class A:
+          pass
+        class B(A):
+          pass
+    """)
     tree = self._ParseAndComputePenalties(code)
     self._CheckPenalties(tree, [
         ('class', None),
@@ -134,9 +134,9 @@ class SplitPenaltyTest(yapf_test_helper.YAPFTest):
     ])
 
     # Test lambda definitions.
-    code = textwrap.dedent(r"""
-      lambda a, b: None
-      """)
+    code = textwrap.dedent("""\
+        lambda a, b: None
+    """)
     tree = self._ParseAndComputePenalties(code)
     self._CheckPenalties(tree, [
         ('lambda', None),
@@ -148,9 +148,9 @@ class SplitPenaltyTest(yapf_test_helper.YAPFTest):
     ])
 
     # Test dotted names.
-    code = textwrap.dedent(r"""
-      import a.b.c
-      """)
+    code = textwrap.dedent("""\
+        import a.b.c
+    """)
     tree = self._ParseAndComputePenalties(code)
     self._CheckPenalties(tree, [
         ('import', None),
@@ -163,12 +163,12 @@ class SplitPenaltyTest(yapf_test_helper.YAPFTest):
 
   def testStronglyConnected(self):
     # Test dictionary keys.
-    code = textwrap.dedent(r"""
-      a = {
-          'x': 42,
-          y(lambda a: 23): 37,
-      }
-      """)
+    code = textwrap.dedent("""\
+        a = {
+            'x': 42,
+            y(lambda a: 23): 37,
+        }
+    """)
     tree = self._ParseAndComputePenalties(code)
     self._CheckPenalties(tree, [
         ('a', None),
@@ -192,9 +192,9 @@ class SplitPenaltyTest(yapf_test_helper.YAPFTest):
     ])
 
     # Test list comprehension.
-    code = textwrap.dedent(r"""
-      [a for a in foo if a.x == 37]
-      """)
+    code = textwrap.dedent("""\
+        [a for a in foo if a.x == 37]
+    """)
     tree = self._ParseAndComputePenalties(code)
     self._CheckPenalties(tree, [
         ('[', None),
@@ -213,7 +213,9 @@ class SplitPenaltyTest(yapf_test_helper.YAPFTest):
     ])
 
   def testFuncCalls(self):
-    code = 'foo(1, 2, 3)\n'
+    code = textwrap.dedent("""\
+        foo(1, 2, 3)
+    """)
     tree = self._ParseAndComputePenalties(code)
     self._CheckPenalties(tree, [
         ('foo', None),
@@ -227,7 +229,9 @@ class SplitPenaltyTest(yapf_test_helper.YAPFTest):
     ])
 
     # Now a method call, which has more than one trailer
-    code = 'foo.bar.baz(1, 2, 3)\n'
+    code = textwrap.dedent("""\
+        foo.bar.baz(1, 2, 3)
+    """)
     tree = self._ParseAndComputePenalties(code)
     self._CheckPenalties(tree, [
         ('foo', None),
@@ -245,7 +249,9 @@ class SplitPenaltyTest(yapf_test_helper.YAPFTest):
     ])
 
     # Test single generator argument.
-    code = 'max(i for i in xrange(10))\n'
+    code = textwrap.dedent("""\
+        max(i for i in xrange(10))
+    """)
     tree = self._ParseAndComputePenalties(code)
     self._CheckPenalties(tree, [
         ('max', None),
diff --git a/yapftests/style_test.py b/yapftests/style_test.py
index 8a37f95..64e64a5 100644
--- a/yapftests/style_test.py
+++ b/yapftests/style_test.py
@@ -136,55 +136,55 @@ class StyleFromFileTest(yapf_test_helper.YAPFTest):
     shutil.rmtree(cls.test_tmpdir)
 
   def testDefaultBasedOnStyle(self):
-    cfg = textwrap.dedent(u'''\
+    cfg = textwrap.dedent("""\
         [style]
         continuation_indent_width = 20
-        ''')
+    """)
     with utils.TempFileContents(self.test_tmpdir, cfg) as filepath:
       cfg = style.CreateStyleFromConfig(filepath)
       self.assertTrue(_LooksLikePEP8Style(cfg))
       self.assertEqual(cfg['CONTINUATION_INDENT_WIDTH'], 20)
 
   def testDefaultBasedOnPEP8Style(self):
-    cfg = textwrap.dedent(u'''\
+    cfg = textwrap.dedent("""\
         [style]
         based_on_style = pep8
         continuation_indent_width = 40
-        ''')
+    """)
     with utils.TempFileContents(self.test_tmpdir, cfg) as filepath:
       cfg = style.CreateStyleFromConfig(filepath)
       self.assertTrue(_LooksLikePEP8Style(cfg))
       self.assertEqual(cfg['CONTINUATION_INDENT_WIDTH'], 40)
 
   def testDefaultBasedOnGoogleStyle(self):
-    cfg = textwrap.dedent(u'''\
+    cfg = textwrap.dedent("""\
         [style]
         based_on_style = google
         continuation_indent_width = 20
-        ''')
+    """)
     with utils.TempFileContents(self.test_tmpdir, cfg) as filepath:
       cfg = style.CreateStyleFromConfig(filepath)
       self.assertTrue(_LooksLikeGoogleStyle(cfg))
       self.assertEqual(cfg['CONTINUATION_INDENT_WIDTH'], 20)
 
   def testDefaultBasedOnFacebookStyle(self):
-    cfg = textwrap.dedent(u'''\
+    cfg = textwrap.dedent("""\
         [style]
         based_on_style = facebook
         continuation_indent_width = 20
-        ''')
+    """)
     with utils.TempFileContents(self.test_tmpdir, cfg) as filepath:
       cfg = style.CreateStyleFromConfig(filepath)
       self.assertTrue(_LooksLikeFacebookStyle(cfg))
       self.assertEqual(cfg['CONTINUATION_INDENT_WIDTH'], 20)
 
   def testBoolOptionValue(self):
-    cfg = textwrap.dedent(u'''\
+    cfg = textwrap.dedent("""\
         [style]
         based_on_style = pep8
         SPLIT_BEFORE_NAMED_ASSIGNS=False
         split_before_logical_operator = true
-        ''')
+    """)
     with utils.TempFileContents(self.test_tmpdir, cfg) as filepath:
       cfg = style.CreateStyleFromConfig(filepath)
       self.assertTrue(_LooksLikePEP8Style(cfg))
@@ -192,11 +192,11 @@ class StyleFromFileTest(yapf_test_helper.YAPFTest):
       self.assertEqual(cfg['SPLIT_BEFORE_LOGICAL_OPERATOR'], True)
 
   def testStringListOptionValue(self):
-    cfg = textwrap.dedent(u'''\
+    cfg = textwrap.dedent("""\
         [style]
         based_on_style = pep8
         I18N_FUNCTION_CALL = N_, V_, T_
-        ''')
+    """)
     with utils.TempFileContents(self.test_tmpdir, cfg) as filepath:
       cfg = style.CreateStyleFromConfig(filepath)
       self.assertTrue(_LooksLikePEP8Style(cfg))
@@ -208,32 +208,27 @@ class StyleFromFileTest(yapf_test_helper.YAPFTest):
       style.CreateStyleFromConfig('/8822/xyznosuchfile')
 
   def testErrorNoStyleSection(self):
-    cfg = textwrap.dedent(u'''\
+    cfg = textwrap.dedent("""\
         [s]
         indent_width=2
-        ''')
+    """)
     with utils.TempFileContents(self.test_tmpdir, cfg) as filepath:
       with self.assertRaisesRegex(style.StyleConfigError,
                                   'Unable to find section'):
         style.CreateStyleFromConfig(filepath)
 
   def testErrorUnknownStyleOption(self):
-    cfg = textwrap.dedent(u'''\
+    cfg = textwrap.dedent("""\
         [style]
         indent_width=2
         hummus=2
-        ''')
+    """)
     with utils.TempFileContents(self.test_tmpdir, cfg) as filepath:
       with self.assertRaisesRegex(style.StyleConfigError,
                                   'Unknown style option'):
         style.CreateStyleFromConfig(filepath)
 
   def testPyprojectTomlNoYapfSection(self):
-    try:
-      import toml
-    except ImportError:
-      return
-
     filepath = os.path.join(self.test_tmpdir, 'pyproject.toml')
     _ = open(filepath, 'w')
     with self.assertRaisesRegex(style.StyleConfigError,
@@ -241,16 +236,12 @@ class StyleFromFileTest(yapf_test_helper.YAPFTest):
       style.CreateStyleFromConfig(filepath)
 
   def testPyprojectTomlParseYapfSection(self):
-    try:
-      import toml
-    except ImportError:
-      return
 
-    cfg = textwrap.dedent(u'''\
+    cfg = textwrap.dedent("""\
         [tool.yapf]
         based_on_style = "pep8"
         continuation_indent_width = 40
-        ''')
+    """)
     filepath = os.path.join(self.test_tmpdir, 'pyproject.toml')
     with open(filepath, 'w') as f:
       f.write(cfg)
@@ -300,14 +291,14 @@ class StyleFromCommandLine(yapf_test_helper.YAPFTest):
 
   def testDefaultBasedOnStyleNotStrict(self):
     cfg = style.CreateStyleFromConfig(
-        '{based_on_style : pep8'
-        ' ,indent_width=2'
+        '{based_on_style : pep8,'
+        ' indent_width=2'
         ' blank_line_before_nested_class_or_def:True}')
     self.assertTrue(_LooksLikePEP8Style(cfg))
     self.assertEqual(cfg['INDENT_WIDTH'], 2)
 
   def testDefaultBasedOnExplicitlyUnicodeTypeString(self):
-    cfg = style.CreateStyleFromConfig(u'{}')
+    cfg = style.CreateStyleFromConfig('{}')
     self.assertIsInstance(cfg, dict)
 
   def testDefaultBasedOnDetaultTypeString(self):
diff --git a/yapftests/subtype_assigner_test.py b/yapftests/subtype_assigner_test.py
index 145a96e..01b3710 100644
--- a/yapftests/subtype_assigner_test.py
+++ b/yapftests/subtype_assigner_test.py
@@ -16,8 +16,8 @@
 import textwrap
 import unittest
 
+from yapf.pytree import pytree_utils
 from yapf.yapflib import format_token
-from yapf.yapflib import pytree_utils
 from yapf.yapflib import subtypes
 
 from yapftests import yapf_test_helper
@@ -45,10 +45,10 @@ class SubtypeAssignerTest(yapf_test_helper.YAPFTest):
 
   def testFuncDefDefaultAssign(self):
     self.maxDiff = None  # pylint: disable=invalid-name
-    code = textwrap.dedent(r"""
+    code = textwrap.dedent("""\
         def foo(a=37, *b, **c):
           return -x[:42]
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self._CheckFormatTokenSubtypes(llines, [
         [
@@ -106,9 +106,9 @@ class SubtypeAssignerTest(yapf_test_helper.YAPFTest):
     ])
 
   def testFuncCallWithDefaultAssign(self):
-    code = textwrap.dedent(r"""
+    code = textwrap.dedent("""\
         foo(x, a='hello world')
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self._CheckFormatTokenSubtypes(llines, [
         [
@@ -130,10 +130,77 @@ class SubtypeAssignerTest(yapf_test_helper.YAPFTest):
     ])
 
   def testSetComprehension(self):
+    code = textwrap.dedent("""\
+        def foo(value):
+          return {value.lower()}
+    """)
+    llines = yapf_test_helper.ParseAndUnwrap(code)
+    self._CheckFormatTokenSubtypes(llines, [
+        [
+            ('def', {subtypes.NONE}),
+            ('foo', {subtypes.FUNC_DEF}),
+            ('(', {subtypes.NONE}),
+            ('value', {
+                subtypes.NONE,
+                subtypes.PARAMETER_START,
+                subtypes.PARAMETER_STOP,
+            }),
+            (')', {subtypes.NONE}),
+            (':', {subtypes.NONE}),
+        ],
+        [
+            ('return', {subtypes.NONE}),
+            ('{', {subtypes.NONE}),
+            ('value', {subtypes.NONE}),
+            ('.', {subtypes.NONE}),
+            ('lower', {subtypes.NONE}),
+            ('(', {subtypes.NONE}),
+            (')', {subtypes.NONE}),
+            ('}', {subtypes.NONE}),
+        ],
+    ])
+
     code = textwrap.dedent("""\
         def foo(strs):
           return {s.lower() for s in strs}
-        """)
+    """)
+    llines = yapf_test_helper.ParseAndUnwrap(code)
+    self._CheckFormatTokenSubtypes(llines, [
+        [
+            ('def', {subtypes.NONE}),
+            ('foo', {subtypes.FUNC_DEF}),
+            ('(', {subtypes.NONE}),
+            ('strs', {
+                subtypes.NONE,
+                subtypes.PARAMETER_START,
+                subtypes.PARAMETER_STOP,
+            }),
+            (')', {subtypes.NONE}),
+            (':', {subtypes.NONE}),
+        ],
+        [
+            ('return', {subtypes.NONE}),
+            ('{', {subtypes.NONE}),
+            ('s', {subtypes.COMP_EXPR}),
+            ('.', {subtypes.COMP_EXPR}),
+            ('lower', {subtypes.COMP_EXPR}),
+            ('(', {subtypes.COMP_EXPR}),
+            (')', {subtypes.COMP_EXPR}),
+            ('for', {
+                subtypes.DICT_SET_GENERATOR,
+                subtypes.COMP_FOR,
+            }),
+            ('s', {subtypes.COMP_FOR}),
+            ('in', {subtypes.COMP_FOR}),
+            ('strs', {subtypes.COMP_FOR}),
+            ('}', {subtypes.NONE}),
+        ],
+    ])
+
+    code = textwrap.dedent("""\
+        def foo(strs):
+          return {s + s.lower() for s in strs}
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self._CheckFormatTokenSubtypes(llines, [
         [
@@ -152,6 +219,8 @@ class SubtypeAssignerTest(yapf_test_helper.YAPFTest):
             ('return', {subtypes.NONE}),
             ('{', {subtypes.NONE}),
             ('s', {subtypes.COMP_EXPR}),
+            ('+', {subtypes.BINARY_OPERATOR, subtypes.COMP_EXPR}),
+            ('s', {subtypes.COMP_EXPR}),
             ('.', {subtypes.COMP_EXPR}),
             ('lower', {subtypes.COMP_EXPR}),
             ('(', {subtypes.COMP_EXPR}),
@@ -167,10 +236,180 @@ class SubtypeAssignerTest(yapf_test_helper.YAPFTest):
         ],
     ])
 
+    code = textwrap.dedent("""\
+        def foo(strs):
+          return {c.lower() for s in strs for c in s}
+    """)
+    llines = yapf_test_helper.ParseAndUnwrap(code)
+    self._CheckFormatTokenSubtypes(llines, [
+        [
+            ('def', {subtypes.NONE}),
+            ('foo', {subtypes.FUNC_DEF}),
+            ('(', {subtypes.NONE}),
+            ('strs', {
+                subtypes.NONE,
+                subtypes.PARAMETER_START,
+                subtypes.PARAMETER_STOP,
+            }),
+            (')', {subtypes.NONE}),
+            (':', {subtypes.NONE}),
+        ],
+        [
+            ('return', {subtypes.NONE}),
+            ('{', {subtypes.NONE}),
+            ('c', {subtypes.COMP_EXPR}),
+            ('.', {subtypes.COMP_EXPR}),
+            ('lower', {subtypes.COMP_EXPR}),
+            ('(', {subtypes.COMP_EXPR}),
+            (')', {subtypes.COMP_EXPR}),
+            ('for', {
+                subtypes.DICT_SET_GENERATOR,
+                subtypes.COMP_FOR,
+                subtypes.COMP_EXPR,
+            }),
+            ('s', {subtypes.COMP_FOR, subtypes.COMP_EXPR}),
+            ('in', {subtypes.COMP_FOR, subtypes.COMP_EXPR}),
+            ('strs', {subtypes.COMP_FOR, subtypes.COMP_EXPR}),
+            ('for', {
+                subtypes.DICT_SET_GENERATOR,
+                subtypes.COMP_FOR,
+            }),
+            ('c', {subtypes.COMP_FOR}),
+            ('in', {subtypes.COMP_FOR}),
+            ('s', {subtypes.COMP_FOR}),
+            ('}', {subtypes.NONE}),
+        ],
+    ])
+
+  def testDictComprehension(self):
+    code = textwrap.dedent("""\
+        def foo(value):
+          return {value: value.lower()}
+    """)
+    llines = yapf_test_helper.ParseAndUnwrap(code)
+    self._CheckFormatTokenSubtypes(llines, [
+        [
+            ('def', {subtypes.NONE}),
+            ('foo', {subtypes.FUNC_DEF}),
+            ('(', {subtypes.NONE}),
+            ('value', {
+                subtypes.NONE,
+                subtypes.PARAMETER_START,
+                subtypes.PARAMETER_STOP,
+            }),
+            (')', {subtypes.NONE}),
+            (':', {subtypes.NONE}),
+        ],
+        [
+            ('return', {subtypes.NONE}),
+            ('{', {subtypes.NONE}),
+            ('value', {subtypes.DICTIONARY_KEY, subtypes.DICTIONARY_KEY_PART}),
+            (':', {subtypes.NONE}),
+            ('value', {subtypes.DICTIONARY_VALUE}),
+            ('.', {subtypes.NONE}),
+            ('lower', {subtypes.NONE}),
+            ('(', {subtypes.NONE}),
+            (')', {subtypes.NONE}),
+            ('}', {subtypes.NONE}),
+        ],
+    ])
+
+    code = textwrap.dedent("""\
+        def foo(strs):
+          return {s: s.lower() for s in strs}
+    """)
+    llines = yapf_test_helper.ParseAndUnwrap(code)
+    self._CheckFormatTokenSubtypes(llines, [
+        [
+            ('def', {subtypes.NONE}),
+            ('foo', {subtypes.FUNC_DEF}),
+            ('(', {subtypes.NONE}),
+            ('strs', {
+                subtypes.NONE,
+                subtypes.PARAMETER_START,
+                subtypes.PARAMETER_STOP,
+            }),
+            (')', {subtypes.NONE}),
+            (':', {subtypes.NONE}),
+        ],
+        [
+            ('return', {subtypes.NONE}),
+            ('{', {subtypes.NONE}),
+            ('s', {
+                subtypes.DICTIONARY_KEY, subtypes.DICTIONARY_KEY_PART,
+                subtypes.COMP_EXPR
+            }),
+            (':', {subtypes.COMP_EXPR}),
+            ('s', {subtypes.DICTIONARY_VALUE, subtypes.COMP_EXPR}),
+            ('.', {subtypes.COMP_EXPR}),
+            ('lower', {subtypes.COMP_EXPR}),
+            ('(', {subtypes.COMP_EXPR}),
+            (')', {subtypes.COMP_EXPR}),
+            ('for', {
+                subtypes.DICT_SET_GENERATOR,
+                subtypes.COMP_FOR,
+            }),
+            ('s', {subtypes.COMP_FOR}),
+            ('in', {subtypes.COMP_FOR}),
+            ('strs', {subtypes.COMP_FOR}),
+            ('}', {subtypes.NONE}),
+        ],
+    ])
+
+    code = textwrap.dedent("""\
+        def foo(strs):
+          return {c: c.lower() for s in strs for c in s}
+    """)
+    llines = yapf_test_helper.ParseAndUnwrap(code)
+    self._CheckFormatTokenSubtypes(llines, [
+        [
+            ('def', {subtypes.NONE}),
+            ('foo', {subtypes.FUNC_DEF}),
+            ('(', {subtypes.NONE}),
+            ('strs', {
+                subtypes.NONE,
+                subtypes.PARAMETER_START,
+                subtypes.PARAMETER_STOP,
+            }),
+            (')', {subtypes.NONE}),
+            (':', {subtypes.NONE}),
+        ],
+        [
+            ('return', {subtypes.NONE}),
+            ('{', {subtypes.NONE}),
+            ('c', {
+                subtypes.DICTIONARY_KEY, subtypes.DICTIONARY_KEY_PART,
+                subtypes.COMP_EXPR
+            }),
+            (':', {subtypes.COMP_EXPR}),
+            ('c', {subtypes.DICTIONARY_VALUE, subtypes.COMP_EXPR}),
+            ('.', {subtypes.COMP_EXPR}),
+            ('lower', {subtypes.COMP_EXPR}),
+            ('(', {subtypes.COMP_EXPR}),
+            (')', {subtypes.COMP_EXPR}),
+            ('for', {
+                subtypes.DICT_SET_GENERATOR,
+                subtypes.COMP_FOR,
+                subtypes.COMP_EXPR,
+            }),
+            ('s', {subtypes.COMP_FOR, subtypes.COMP_EXPR}),
+            ('in', {subtypes.COMP_FOR, subtypes.COMP_EXPR}),
+            ('strs', {subtypes.COMP_FOR, subtypes.COMP_EXPR}),
+            ('for', {
+                subtypes.DICT_SET_GENERATOR,
+                subtypes.COMP_FOR,
+            }),
+            ('c', {subtypes.COMP_FOR}),
+            ('in', {subtypes.COMP_FOR}),
+            ('s', {subtypes.COMP_FOR}),
+            ('}', {subtypes.NONE}),
+        ],
+    ])
+
   def testUnaryNotOperator(self):
     code = textwrap.dedent("""\
         not a
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self._CheckFormatTokenSubtypes(llines, [[('not', {subtypes.UNARY_OPERATOR}),
                                              ('a', {subtypes.NONE})]])
@@ -207,7 +446,7 @@ class SubtypeAssignerTest(yapf_test_helper.YAPFTest):
   def testArithmeticOperators(self):
     code = textwrap.dedent("""\
         x = ((a + (b - 3) * (1 % c) @ d) / 3) // 1
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self._CheckFormatTokenSubtypes(llines, [
         [
@@ -248,7 +487,7 @@ class SubtypeAssignerTest(yapf_test_helper.YAPFTest):
   def testSubscriptColon(self):
     code = textwrap.dedent("""\
         x[0:42:1]
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self._CheckFormatTokenSubtypes(llines, [
         [
@@ -266,7 +505,7 @@ class SubtypeAssignerTest(yapf_test_helper.YAPFTest):
   def testFunctionCallWithStarExpression(self):
     code = textwrap.dedent("""\
         [a, *b]
-        """)
+    """)
     llines = yapf_test_helper.ParseAndUnwrap(code)
     self._CheckFormatTokenSubtypes(llines, [
         [
diff --git a/yapftests/utils.py b/yapftests/utils.py
index 268b8c4..e91752b 100644
--- a/yapftests/utils.py
+++ b/yapftests/utils.py
@@ -52,11 +52,6 @@ def NamedTempFile(mode='w+b',
                   dirname=None,
                   text=False):
   """Context manager creating a new temporary file in text mode."""
-  if sys.version_info < (3, 5):  # covers also python 2
-    if suffix is None:
-      suffix = ''
-    if prefix is None:
-      prefix = 'tmp'
   (fd, fname) = tempfile.mkstemp(
       suffix=suffix, prefix=prefix, dir=dirname, text=text)
   f = io.open(
diff --git a/yapftests/yapf_test.py b/yapftests/yapf_test.py
index 2330f4e..a9ca011 100644
--- a/yapftests/yapf_test.py
+++ b/yapftests/yapf_test.py
@@ -23,21 +23,18 @@ import sys
 import tempfile
 import textwrap
 import unittest
+from io import StringIO
 
-from lib2to3.pgen2 import tokenize
+from yapf_third_party._ylib2to3.pgen2 import tokenize
 
 from yapf.yapflib import errors
-from yapf.yapflib import py3compat
 from yapf.yapflib import style
 from yapf.yapflib import yapf_api
 
 from yapftests import utils
 from yapftests import yapf_test_helper
 
-ROOT_DIR = os.path.dirname(os.path.abspath(os.path.dirname(__file__)))
-
-# Verification is turned off by default, but want to enable it for testing.
-YAPF_BINARY = [sys.executable, '-m', 'yapf', '--verify', '--no-local-style']
+YAPF_BINARY = [sys.executable, '-m', 'yapf', '--no-local-style']
 
 
 class FormatCodeTest(yapf_test_helper.YAPFTest):
@@ -50,7 +47,7 @@ class FormatCodeTest(yapf_test_helper.YAPFTest):
   def testSimple(self):
     unformatted_code = textwrap.dedent("""\
         print('foo')
-        """)
+    """)
     self._Check(unformatted_code, unformatted_code)
 
   def testNoEndingNewline(self):
@@ -60,17 +57,11 @@ class FormatCodeTest(yapf_test_helper.YAPFTest):
     expected_formatted_code = textwrap.dedent("""\
         if True:
           pass
-        """)
-    self._Check(unformatted_code, expected_formatted_code)
-
-  @unittest.skipUnless(py3compat.PY36, 'Requires Python 3.6')
-  def testPrintAfterPeriod(self):
-    unformatted_code = textwrap.dedent("""a.print\n""")
-    expected_formatted_code = textwrap.dedent("""a.print\n""")
+    """)
     self._Check(unformatted_code, expected_formatted_code)
 
 
-class FormatFileTest(unittest.TestCase):
+class FormatFileTest(yapf_test_helper.YAPFTest):
 
   def setUp(self):  # pylint: disable=g-missing-super-call
     self.test_tmpdir = tempfile.mkdtemp()
@@ -78,29 +69,19 @@ class FormatFileTest(unittest.TestCase):
   def tearDown(self):  # pylint: disable=g-missing-super-call
     shutil.rmtree(self.test_tmpdir)
 
-  def assertCodeEqual(self, expected_code, code):
-    if code != expected_code:
-      msg = 'Code format mismatch:\n'
-      msg += 'Expected:\n >'
-      msg += '\n > '.join(expected_code.splitlines())
-      msg += '\nActual:\n >'
-      msg += '\n > '.join(code.splitlines())
-      # TODO(sbc): maybe using difflib here to produce easy to read deltas?
-      self.fail(msg)
-
   def testFormatFile(self):
-    unformatted_code = textwrap.dedent(u"""\
+    unformatted_code = textwrap.dedent("""\
         if True:
          pass
-        """)
-    expected_formatted_code_pep8 = textwrap.dedent(u"""\
+    """)
+    expected_formatted_code_pep8 = textwrap.dedent("""\
         if True:
             pass
-        """)
-    expected_formatted_code_yapf = textwrap.dedent(u"""\
+    """)
+    expected_formatted_code_yapf = textwrap.dedent("""\
         if True:
           pass
-        """)
+    """)
     with utils.TempFileContents(self.test_tmpdir, unformatted_code) as filepath:
       formatted_code, _, _ = yapf_api.FormatFile(filepath, style_config='pep8')
       self.assertCodeEqual(expected_formatted_code_pep8, formatted_code)
@@ -109,28 +90,28 @@ class FormatFileTest(unittest.TestCase):
       self.assertCodeEqual(expected_formatted_code_yapf, formatted_code)
 
   def testDisableLinesPattern(self):
-    unformatted_code = textwrap.dedent(u"""\
+    unformatted_code = textwrap.dedent("""\
         if a:    b
 
         # yapf: disable
         if f:    g
 
         if h:    i
-        """)
-    expected_formatted_code = textwrap.dedent(u"""\
+    """)
+    expected_formatted_code = textwrap.dedent("""\
         if a: b
 
         # yapf: disable
         if f:    g
 
         if h:    i
-        """)
+    """)
     with utils.TempFileContents(self.test_tmpdir, unformatted_code) as filepath:
       formatted_code, _, _ = yapf_api.FormatFile(filepath, style_config='pep8')
       self.assertCodeEqual(expected_formatted_code, formatted_code)
 
   def testDisableAndReenableLinesPattern(self):
-    unformatted_code = textwrap.dedent(u"""\
+    unformatted_code = textwrap.dedent("""\
         if a:    b
 
         # yapf: disable
@@ -138,8 +119,8 @@ class FormatFileTest(unittest.TestCase):
         # yapf: enable
 
         if h:    i
-        """)
-    expected_formatted_code = textwrap.dedent(u"""\
+    """)
+    expected_formatted_code = textwrap.dedent("""\
         if a: b
 
         # yapf: disable
@@ -147,13 +128,36 @@ class FormatFileTest(unittest.TestCase):
         # yapf: enable
 
         if h: i
-        """)
+    """)
+    with utils.TempFileContents(self.test_tmpdir, unformatted_code) as filepath:
+      formatted_code, _, _ = yapf_api.FormatFile(filepath, style_config='pep8')
+      self.assertCodeEqual(expected_formatted_code, formatted_code)
+
+  def testFmtOnOff(self):
+    unformatted_code = textwrap.dedent("""\
+        if a:    b
+
+        # fmt: off
+        if f:    g
+        # fmt: on
+
+        if h:    i
+    """)
+    expected_formatted_code = textwrap.dedent("""\
+        if a: b
+
+        # fmt: off
+        if f:    g
+        # fmt: on
+
+        if h: i
+    """)
     with utils.TempFileContents(self.test_tmpdir, unformatted_code) as filepath:
       formatted_code, _, _ = yapf_api.FormatFile(filepath, style_config='pep8')
       self.assertCodeEqual(expected_formatted_code, formatted_code)
 
   def testDisablePartOfMultilineComment(self):
-    unformatted_code = textwrap.dedent(u"""\
+    unformatted_code = textwrap.dedent("""\
         if a:    b
 
         # This is a multiline comment that disables YAPF.
@@ -163,9 +167,8 @@ class FormatFileTest(unittest.TestCase):
         # This is a multiline comment that enables YAPF.
 
         if h:    i
-        """)
-
-    expected_formatted_code = textwrap.dedent(u"""\
+    """)
+    expected_formatted_code = textwrap.dedent("""\
         if a: b
 
         # This is a multiline comment that disables YAPF.
@@ -175,12 +178,12 @@ class FormatFileTest(unittest.TestCase):
         # This is a multiline comment that enables YAPF.
 
         if h: i
-        """)
+    """)
     with utils.TempFileContents(self.test_tmpdir, unformatted_code) as filepath:
       formatted_code, _, _ = yapf_api.FormatFile(filepath, style_config='pep8')
       self.assertCodeEqual(expected_formatted_code, formatted_code)
 
-    code = textwrap.dedent(u"""\
+    code = textwrap.dedent("""\
       def foo_function():
           # some comment
           # yapf: disable
@@ -191,46 +194,46 @@ class FormatFileTest(unittest.TestCase):
           )
 
           # yapf: enable
-      """)
+    """)
     with utils.TempFileContents(self.test_tmpdir, code) as filepath:
       formatted_code, _, _ = yapf_api.FormatFile(filepath, style_config='pep8')
       self.assertCodeEqual(code, formatted_code)
 
   def testEnabledDisabledSameComment(self):
-    code = textwrap.dedent(u"""\
+    code = textwrap.dedent("""\
         # yapf: disable
         a(bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb, ccccccccccccccccccccccccccccccc, ddddddddddddddddddddddd, eeeeeeeeeeeeeeeeeeeeeeeeeee)
         # yapf: enable
         # yapf: disable
         a(bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb, ccccccccccccccccccccccccccccccc, ddddddddddddddddddddddd, eeeeeeeeeeeeeeeeeeeeeeeeeee)
         # yapf: enable
-        """)  # noqa
+    """)  # noqa
     with utils.TempFileContents(self.test_tmpdir, code) as filepath:
       formatted_code, _, _ = yapf_api.FormatFile(filepath, style_config='pep8')
       self.assertCodeEqual(code, formatted_code)
 
   def testFormatFileLinesSelection(self):
-    unformatted_code = textwrap.dedent(u"""\
+    unformatted_code = textwrap.dedent("""\
         if a:    b
 
         if f:    g
 
         if h:    i
-        """)
-    expected_formatted_code_lines1and2 = textwrap.dedent(u"""\
+    """)
+    expected_formatted_code_lines1and2 = textwrap.dedent("""\
         if a: b
 
         if f:    g
 
         if h:    i
-        """)
-    expected_formatted_code_lines3 = textwrap.dedent(u"""\
+    """)
+    expected_formatted_code_lines3 = textwrap.dedent("""\
         if a:    b
 
         if f: g
 
         if h:    i
-        """)
+    """)
     with utils.TempFileContents(self.test_tmpdir, unformatted_code) as filepath:
       formatted_code, _, _ = yapf_api.FormatFile(
           filepath, style_config='pep8', lines=[(1, 2)])
@@ -240,25 +243,22 @@ class FormatFileTest(unittest.TestCase):
       self.assertCodeEqual(expected_formatted_code_lines3, formatted_code)
 
   def testFormatFileDiff(self):
-    unformatted_code = textwrap.dedent(u"""\
+    unformatted_code = textwrap.dedent("""\
         if True:
          pass
-        """)
+    """)
     with utils.TempFileContents(self.test_tmpdir, unformatted_code) as filepath:
       diff, _, _ = yapf_api.FormatFile(filepath, print_diff=True)
-      self.assertIn(u'+  pass', diff)
+      self.assertIn('+  pass', diff)
 
   def testFormatFileInPlace(self):
-    unformatted_code = u'True==False\n'
-    formatted_code = u'True == False\n'
+    unformatted_code = 'True==False\n'
+    formatted_code = 'True == False\n'
     with utils.TempFileContents(self.test_tmpdir, unformatted_code) as filepath:
       result, _, _ = yapf_api.FormatFile(filepath, in_place=True)
       self.assertEqual(result, None)
       with open(filepath) as fd:
-        if sys.version_info[0] <= 2:
-          self.assertCodeEqual(formatted_code, fd.read().decode('ascii'))
-        else:
-          self.assertCodeEqual(formatted_code, fd.read())
+        self.assertCodeEqual(formatted_code, fd.read())
 
       self.assertRaises(
           ValueError,
@@ -268,45 +268,43 @@ class FormatFileTest(unittest.TestCase):
           print_diff=True)
 
   def testNoFile(self):
-    stream = py3compat.StringIO()
-    handler = logging.StreamHandler(stream)
-    logger = logging.getLogger('mylogger')
-    logger.addHandler(handler)
-    self.assertRaises(
-        IOError, yapf_api.FormatFile, 'not_a_file.py', logger=logger.error)
-    self.assertEqual(stream.getvalue(),
-                     "[Errno 2] No such file or directory: 'not_a_file.py'\n")
+    with self.assertRaises(IOError) as context:
+      yapf_api.FormatFile('not_a_file.py')
+
+    self.assertEqual(
+        str(context.exception),
+        "[Errno 2] No such file or directory: 'not_a_file.py'")
 
   def testCommentsUnformatted(self):
-    code = textwrap.dedent(u"""\
+    code = textwrap.dedent("""\
         foo = [# A list of things
                # bork
             'one',
             # quark
             'two'] # yapf: disable
-        """)
+    """)
     with utils.TempFileContents(self.test_tmpdir, code) as filepath:
       formatted_code, _, _ = yapf_api.FormatFile(filepath, style_config='pep8')
       self.assertCodeEqual(code, formatted_code)
 
   def testDisabledHorizontalFormattingOnNewLine(self):
-    code = textwrap.dedent(u"""\
+    code = textwrap.dedent("""\
         # yapf: disable
         a = [
         1]
         # yapf: enable
-        """)
+    """)
     with utils.TempFileContents(self.test_tmpdir, code) as filepath:
       formatted_code, _, _ = yapf_api.FormatFile(filepath, style_config='pep8')
       self.assertCodeEqual(code, formatted_code)
 
   def testSplittingSemicolonStatements(self):
-    unformatted_code = textwrap.dedent(u"""\
+    unformatted_code = textwrap.dedent("""\
         def f():
           x = y + 42 ; z = n * 42
           if True: a += 1 ; b += 1; c += 1
-        """)
-    expected_formatted_code = textwrap.dedent(u"""\
+    """)
+    expected_formatted_code = textwrap.dedent("""\
         def f():
             x = y + 42
             z = n * 42
@@ -314,40 +312,40 @@ class FormatFileTest(unittest.TestCase):
                 a += 1
                 b += 1
                 c += 1
-        """)
+    """)
     with utils.TempFileContents(self.test_tmpdir, unformatted_code) as filepath:
       formatted_code, _, _ = yapf_api.FormatFile(filepath, style_config='pep8')
       self.assertCodeEqual(expected_formatted_code, formatted_code)
 
   def testSemicolonStatementsDisabled(self):
-    unformatted_code = textwrap.dedent(u"""\
+    unformatted_code = textwrap.dedent("""\
         def f():
           x = y + 42 ; z = n * 42  # yapf: disable
           if True: a += 1 ; b += 1; c += 1
-        """)
-    expected_formatted_code = textwrap.dedent(u"""\
+    """)
+    expected_formatted_code = textwrap.dedent("""\
         def f():
             x = y + 42 ; z = n * 42  # yapf: disable
             if True:
                 a += 1
                 b += 1
                 c += 1
-        """)
+    """)
     with utils.TempFileContents(self.test_tmpdir, unformatted_code) as filepath:
       formatted_code, _, _ = yapf_api.FormatFile(filepath, style_config='pep8')
       self.assertCodeEqual(expected_formatted_code, formatted_code)
 
   def testDisabledSemiColonSeparatedStatements(self):
-    code = textwrap.dedent(u"""\
+    code = textwrap.dedent("""\
         # yapf: disable
         if True: a ; b
-        """)
+    """)
     with utils.TempFileContents(self.test_tmpdir, code) as filepath:
       formatted_code, _, _ = yapf_api.FormatFile(filepath, style_config='pep8')
       self.assertCodeEqual(code, formatted_code)
 
   def testDisabledMultilineStringInDictionary(self):
-    code = textwrap.dedent(u"""\
+    code = textwrap.dedent("""\
         # yapf: disable
 
         A = [
@@ -360,13 +358,13 @@ class FormatFileTest(unittest.TestCase):
         ''',
             },
         ]
-        """)
+    """)
     with utils.TempFileContents(self.test_tmpdir, code) as filepath:
       formatted_code, _, _ = yapf_api.FormatFile(filepath, style_config='yapf')
       self.assertCodeEqual(code, formatted_code)
 
   def testDisabledWithPrecedingText(self):
-    code = textwrap.dedent(u"""\
+    code = textwrap.dedent("""\
         # TODO(fix formatting): yapf: disable
 
         A = [
@@ -379,19 +377,19 @@ class FormatFileTest(unittest.TestCase):
         ''',
             },
         ]
-        """)
+    """)
     with utils.TempFileContents(self.test_tmpdir, code) as filepath:
       formatted_code, _, _ = yapf_api.FormatFile(filepath, style_config='yapf')
       self.assertCodeEqual(code, formatted_code)
 
   def testCRLFLineEnding(self):
-    code = u'class _():\r\n  pass\r\n'
+    code = 'class _():\r\n  pass\r\n'
     with utils.TempFileContents(self.test_tmpdir, code) as filepath:
       formatted_code, _, _ = yapf_api.FormatFile(filepath, style_config='yapf')
       self.assertCodeEqual(code, formatted_code)
 
 
-class CommandLineTest(unittest.TestCase):
+class CommandLineTest(yapf_test_helper.YAPFTest):
   """Test how calling yapf from the command line acts."""
 
   @classmethod
@@ -430,27 +428,15 @@ class CommandLineTest(unittest.TestCase):
     self.assertEqual(stderrdata, b'')
     self.assertMultiLineEqual(reformatted_code.decode('utf-8'), expected)
 
-  @unittest.skipUnless(py3compat.PY36, 'Requires Python 3.6')
-  def testUnicodeEncodingPipedToFile(self):
-    unformatted_code = textwrap.dedent(u"""\
-        def foo():
-            print('⇒')
-        """)
-    with utils.NamedTempFile(
-        dirname=self.test_tmpdir, suffix='.py') as (out, _):
-      with utils.TempFileContents(
-          self.test_tmpdir, unformatted_code, suffix='.py') as filepath:
-        subprocess.check_call(YAPF_BINARY + ['--diff', filepath], stdout=out)
-
   def testInPlaceReformatting(self):
-    unformatted_code = textwrap.dedent(u"""\
+    unformatted_code = textwrap.dedent("""\
         def foo():
           x = 37
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         def foo():
             x = 37
-        """)
+    """)
     with utils.TempFileContents(
         self.test_tmpdir, unformatted_code, suffix='.py') as filepath:
       p = subprocess.Popen(YAPF_BINARY + ['--in-place', filepath])
@@ -460,8 +446,8 @@ class CommandLineTest(unittest.TestCase):
     self.assertEqual(reformatted_code, expected_formatted_code)
 
   def testInPlaceReformattingBlank(self):
-    unformatted_code = u'\n\n'
-    expected_formatted_code = u'\n'
+    unformatted_code = '\n\n'
+    expected_formatted_code = '\n'
     with utils.TempFileContents(
         self.test_tmpdir, unformatted_code, suffix='.py') as filepath:
       p = subprocess.Popen(YAPF_BINARY + ['--in-place', filepath])
@@ -470,9 +456,34 @@ class CommandLineTest(unittest.TestCase):
         reformatted_code = fd.read()
     self.assertEqual(reformatted_code, expected_formatted_code)
 
+  def testInPlaceReformattingWindowsNewLine(self):
+    unformatted_code = '\r\n\r\n'
+    expected_formatted_code = '\r\n'
+    with utils.TempFileContents(
+        self.test_tmpdir, unformatted_code, suffix='.py') as filepath:
+      p = subprocess.Popen(YAPF_BINARY + ['--in-place', filepath])
+      p.wait()
+      with io.open(filepath, mode='r', encoding='utf-8', newline='') as fd:
+        reformatted_code = fd.read()
+    self.assertEqual(reformatted_code, expected_formatted_code)
+
+  def testInPlaceReformattingNoNewLine(self):
+    unformatted_code = textwrap.dedent('def foo(): x = 37')
+    expected_formatted_code = textwrap.dedent("""\
+        def foo():
+            x = 37
+    """)
+    with utils.TempFileContents(
+        self.test_tmpdir, unformatted_code, suffix='.py') as filepath:
+      p = subprocess.Popen(YAPF_BINARY + ['--in-place', filepath])
+      p.wait()
+      with io.open(filepath, mode='r', newline='') as fd:
+        reformatted_code = fd.read()
+    self.assertEqual(reformatted_code, expected_formatted_code)
+
   def testInPlaceReformattingEmpty(self):
-    unformatted_code = u''
-    expected_formatted_code = u''
+    unformatted_code = ''
+    expected_formatted_code = ''
     with utils.TempFileContents(
         self.test_tmpdir, unformatted_code, suffix='.py') as filepath:
       p = subprocess.Popen(YAPF_BINARY + ['--in-place', filepath])
@@ -481,35 +492,45 @@ class CommandLineTest(unittest.TestCase):
         reformatted_code = fd.read()
     self.assertEqual(reformatted_code, expected_formatted_code)
 
+  def testPrintModified(self):
+    for unformatted_code, has_change in [('1==2', True), ('1 == 2', False)]:
+      with utils.TempFileContents(
+          self.test_tmpdir, unformatted_code, suffix='.py') as filepath:
+        output = subprocess.check_output(
+            YAPF_BINARY + ['--in-place', '--print-modified', filepath],
+            text=True)
+        check = self.assertIn if has_change else self.assertNotIn
+        check(f'Formatted {filepath}', output)
+
   def testReadFromStdin(self):
     unformatted_code = textwrap.dedent("""\
         def foo():
           x = 37
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         def foo():
             x = 37
-        """)
+    """)
     self.assertYapfReformats(unformatted_code, expected_formatted_code)
 
   def testReadFromStdinWithEscapedStrings(self):
     unformatted_code = textwrap.dedent("""\
         s =   "foo\\nbar"
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         s = "foo\\nbar"
-        """)
+    """)
     self.assertYapfReformats(unformatted_code, expected_formatted_code)
 
   def testSetYapfStyle(self):
     unformatted_code = textwrap.dedent("""\
         def foo(): # trail
             x = 37
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         def foo():  # trail
           x = 37
-        """)
+    """)
     self.assertYapfReformats(
         unformatted_code,
         expected_formatted_code,
@@ -519,16 +540,16 @@ class CommandLineTest(unittest.TestCase):
     unformatted_code = textwrap.dedent("""\
         def foo(): # trail
             x = 37
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         def foo():    # trail
           x = 37
-        """)
-    style_file = textwrap.dedent(u'''\
+    """)
+    style_file = textwrap.dedent("""\
         [style]
         based_on_style = yapf
         spaces_before_comment = 4
-        ''')
+    """)
     with utils.TempFileContents(self.test_tmpdir, style_file) as stylepath:
       self.assertYapfReformats(
           unformatted_code,
@@ -539,15 +560,15 @@ class CommandLineTest(unittest.TestCase):
     unformatted_code = textwrap.dedent("""\
         a_very_long_statement_that_extends_way_beyond # Comment
         short # This is a shorter statement
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         a_very_long_statement_that_extends_way_beyond # Comment
         short                                         # This is a shorter statement
-        """)  # noqa
-    style_file = textwrap.dedent(u'''\
+    """)  # noqa
+    style_file = textwrap.dedent("""\
         [style]
         spaces_before_comment = 15, 20
-        ''')
+    """)
     with utils.TempFileContents(self.test_tmpdir, style_file) as stylepath:
       self.assertYapfReformats(
           unformatted_code,
@@ -557,19 +578,19 @@ class CommandLineTest(unittest.TestCase):
   def testReadSingleLineCodeFromStdin(self):
     unformatted_code = textwrap.dedent("""\
         if True: pass
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         if True: pass
-        """)
+    """)
     self.assertYapfReformats(unformatted_code, expected_formatted_code)
 
   def testEncodingVerification(self):
-    unformatted_code = textwrap.dedent(u"""\
+    unformatted_code = textwrap.dedent("""\
         '''The module docstring.'''
         # -*- coding: utf-8 -*-
         def f():
             x = 37
-        """)
+    """)
 
     with utils.NamedTempFile(
         suffix='.py', dirname=self.test_tmpdir) as (out, _):
@@ -602,7 +623,7 @@ class CommandLineTest(unittest.TestCase):
         def g():
             if (xxxxxxxxxxxx.yyyyyyyy(zzzzzzzzzzzzz[0]) == 'aaaaaaaaaaa' and xxxxxxxxxxxx.yyyyyyyy(zzzzzzzzzzzzz[0].mmmmmmmm[0]) == 'bbbbbbb'):
                 pass
-        """)  # noqa
+    """)  # noqa
     # TODO(ambv): the `expected_formatted_code` here is not PEP8 compliant,
     # raising "E129 visually indented line with same indent as next logical
     # line" with flake8.
@@ -618,14 +639,14 @@ class CommandLineTest(unittest.TestCase):
         # Comment
         def some_func(x):
             x = ["badly" , "formatted","line" ]
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         import sys
 
         # Comment
         def some_func(x):
             x = ["badly", "formatted", "line"]
-        """)
+    """)
     self.assertYapfReformats(
         unformatted_code,
         expected_formatted_code,
@@ -642,7 +663,7 @@ class CommandLineTest(unittest.TestCase):
             if (xxxxxxxxxxxx.yyyyyyyy(zzzzzzzzzzzzz[0]) == 'aaaaaaaaaaa' and xxxxxxxxxxxx.yyyyyyyy(zzzzzzzzzzzzz[0].mmmmmmmm[0]) == 'bbbbbbb'):
                 pass
         # yapf: enable
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         def h():
             if (xxxxxxxxxxxx.yyyyyyyy(zzzzzzzzzzzzz[0]) == 'aaaaaaaaaaa' and
@@ -655,7 +676,7 @@ class CommandLineTest(unittest.TestCase):
             if (xxxxxxxxxxxx.yyyyyyyy(zzzzzzzzzzzzz[0]) == 'aaaaaaaaaaa' and xxxxxxxxxxxx.yyyyyyyy(zzzzzzzzzzzzz[0].mmmmmmmm[0]) == 'bbbbbbb'):
                 pass
         # yapf: enable
-        """)  # noqa
+    """)  # noqa
     self.assertYapfReformats(unformatted_code, expected_formatted_code)
 
   def testReformattingSkippingToEndOfFile(self):
@@ -675,7 +696,7 @@ class CommandLineTest(unittest.TestCase):
                        xxxxxxxxxxxxxxxxxxxxx(yyyyyyyyyyyyy[zzzzz].aaaaaaaa[0]) ==
                        'bbbbbbb'):
                     pass
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         def h():
             if (xxxxxxxxxxxx.yyyyyyyy(zzzzzzzzzzzzz[0]) == 'aaaaaaaaaaa' and
@@ -694,7 +715,7 @@ class CommandLineTest(unittest.TestCase):
                        xxxxxxxxxxxxxxxxxxxxx(yyyyyyyyyyyyy[zzzzz].aaaaaaaa[0]) ==
                        'bbbbbbb'):
                     pass
-        """)  # noqa
+    """)  # noqa
     self.assertYapfReformats(unformatted_code, expected_formatted_code)
 
   def testReformattingSkippingSingleLine(self):
@@ -706,7 +727,7 @@ class CommandLineTest(unittest.TestCase):
         def g():
             if (xxxxxxxxxxxx.yyyyyyyy(zzzzzzzzzzzzz[0]) == 'aaaaaaaaaaa' and xxxxxxxxxxxx.yyyyyyyy(zzzzzzzzzzzzz[0].mmmmmmmm[0]) == 'bbbbbbb'):  # yapf: disable
                 pass
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         def h():
             if (xxxxxxxxxxxx.yyyyyyyy(zzzzzzzzzzzzz[0]) == 'aaaaaaaaaaa' and
@@ -717,7 +738,7 @@ class CommandLineTest(unittest.TestCase):
         def g():
             if (xxxxxxxxxxxx.yyyyyyyy(zzzzzzzzzzzzz[0]) == 'aaaaaaaaaaa' and xxxxxxxxxxxx.yyyyyyyy(zzzzzzzzzzzzz[0].mmmmmmmm[0]) == 'bbbbbbb'):  # yapf: disable
                 pass
-        """)  # noqa
+    """)  # noqa
     self.assertYapfReformats(unformatted_code, expected_formatted_code)
 
   def testDisableWholeDataStructure(self):
@@ -726,13 +747,13 @@ class CommandLineTest(unittest.TestCase):
             'hello',
             'world',
         ])  # yapf: disable
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         A = set([
             'hello',
             'world',
         ])  # yapf: disable
-        """)
+    """)
     self.assertYapfReformats(unformatted_code, expected_formatted_code)
 
   def testDisableButAdjustIndentations(self):
@@ -742,14 +763,14 @@ class CommandLineTest(unittest.TestCase):
           def testUnbreakable(self):
             self._CheckPenalties(tree, [
             ])  # yapf: disable
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         class SplitPenaltyTest(unittest.TestCase):
 
             def testUnbreakable(self):
                 self._CheckPenalties(tree, [
                 ])  # yapf: disable
-        """)
+    """)
     self.assertYapfReformats(unformatted_code, expected_formatted_code)
 
   def testRetainingHorizontalWhitespace(self):
@@ -761,7 +782,7 @@ class CommandLineTest(unittest.TestCase):
         def g():
             if (xxxxxxxxxxxx.yyyyyyyy        (zzzzzzzzzzzzz  [0]) ==     'aaaaaaaaaaa' and    xxxxxxxxxxxx.yyyyyyyy(zzzzzzzzzzzzz[0].mmmmmmmm[0]) == 'bbbbbbb'):  # yapf: disable
                 pass
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         def h():
             if (xxxxxxxxxxxx.yyyyyyyy(zzzzzzzzzzzzz[0]) == 'aaaaaaaaaaa' and
@@ -772,7 +793,7 @@ class CommandLineTest(unittest.TestCase):
         def g():
             if (xxxxxxxxxxxx.yyyyyyyy        (zzzzzzzzzzzzz  [0]) ==     'aaaaaaaaaaa' and    xxxxxxxxxxxx.yyyyyyyy(zzzzzzzzzzzzz[0].mmmmmmmm[0]) == 'bbbbbbb'):  # yapf: disable
                 pass
-        """)  # noqa
+    """)  # noqa
     self.assertYapfReformats(unformatted_code, expected_formatted_code)
 
   def testRetainingVerticalWhitespace(self):
@@ -787,7 +808,7 @@ class CommandLineTest(unittest.TestCase):
             if (xxxxxxxxxxxx.yyyyyyyy(zzzzzzzzzzzzz[0]) == 'aaaaaaaaaaa' and xxxxxxxxxxxx.yyyyyyyy(zzzzzzzzzzzzz[0].mmmmmmmm[0]) == 'bbbbbbb'):
 
                 pass
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         def h():
             if (xxxxxxxxxxxx.yyyyyyyy(zzzzzzzzzzzzz[0]) == 'aaaaaaaaaaa' and
@@ -800,7 +821,7 @@ class CommandLineTest(unittest.TestCase):
             if (xxxxxxxxxxxx.yyyyyyyy(zzzzzzzzzzzzz[0]) == 'aaaaaaaaaaa' and xxxxxxxxxxxx.yyyyyyyy(zzzzzzzzzzzzz[0].mmmmmmmm[0]) == 'bbbbbbb'):
 
                 pass
-        """)  # noqa
+    """)  # noqa
     self.assertYapfReformats(
         unformatted_code,
         expected_formatted_code,
@@ -822,7 +843,7 @@ class CommandLineTest(unittest.TestCase):
         #comment
 
         #   trailing whitespace
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         if a: b
 
@@ -837,7 +858,7 @@ class CommandLineTest(unittest.TestCase):
         #comment
 
         #   trailing whitespace
-        """)
+    """)
     self.assertYapfReformats(
         unformatted_code,
         expected_formatted_code,
@@ -850,28 +871,28 @@ class CommandLineTest(unittest.TestCase):
         '''
 
         import blah
-        """)
+    """)
 
     self.assertYapfReformats(
         unformatted_code, unformatted_code, extra_options=['--lines', '2-2'])
 
   def testVerticalSpacingWithCommentWithContinuationMarkers(self):
-    unformatted_code = """\
-# \\
-# \\
-# \\
+    unformatted_code = textwrap.dedent("""\
+        # \\
+        # \\
+        # \\
 
-x = {
-}
-"""
-    expected_formatted_code = """\
-# \\
-# \\
-# \\
+        x = {
+        }
+    """)
+    expected_formatted_code = textwrap.dedent("""\
+        # \\
+        # \\
+        # \\
 
-x = {
-}
-"""
+        x = {
+        }
+    """)
     self.assertYapfReformats(
         unformatted_code,
         expected_formatted_code,
@@ -883,13 +904,13 @@ x = {
         def f():
             x = y + 42; z = n * 42
             if True: a += 1 ; b += 1 ; c += 1
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         a = line_to_format
         def f():
             x = y + 42; z = n * 42
             if True: a += 1 ; b += 1 ; c += 1
-        """)
+    """)
     self.assertYapfReformats(
         unformatted_code,
         expected_formatted_code,
@@ -905,7 +926,7 @@ x = {
         <b>Residence: </b>"""+palace["Winter"]+"""<br>
         </body>
         </html>"""
-        ''')  # noqa
+    ''')  # noqa
     expected_formatted_code = textwrap.dedent('''\
         foo = 42
         def f():
@@ -915,7 +936,7 @@ x = {
         <b>Residence: </b>"""+palace["Winter"]+"""<br>
         </body>
         </html>"""
-        ''')  # noqa
+    ''')  # noqa
     self.assertYapfReformats(
         unformatted_code,
         expected_formatted_code,
@@ -933,7 +954,7 @@ x = {
             'hello',
             'world',
         ])  # yapf: disable
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         # yapf: disable
         A = set([
@@ -945,7 +966,7 @@ x = {
             'hello',
             'world',
         ])  # yapf: disable
-        """)
+    """)
     self.assertYapfReformats(
         unformatted_code,
         expected_formatted_code,
@@ -970,7 +991,7 @@ x = {
 
                 'that'
             ]
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         def horrible():
             oh_god()
@@ -985,7 +1006,7 @@ x = {
             oh_god()
             why_would_you()
             ['do', 'that']
-        """)
+    """)
     self.assertYapfReformats(
         unformatted_code,
         expected_formatted_code,
@@ -1002,7 +1023,7 @@ x = {
                      c.ffffffffffff),
              gggggggggggg.hhhhhhhhh(c, c.ffffffffffff))
                 iiiii = jjjjjjjjjjjjjj.iiiii
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         class A(object):
             def aaaaaaaaaaaaa(self):
@@ -1011,7 +1032,7 @@ x = {
                                   'eeeeeeeeeeeeeeeeeeeeeeeee.%s' % c.ffffffffffff),
                                  gggggggggggg.hhhhhhhhh(c, c.ffffffffffff))
                 iiiii = jjjjjjjjjjjjjj.iiiii
-        """)  # noqa
+    """)  # noqa
     self.assertYapfReformats(
         unformatted_code,
         expected_formatted_code,
@@ -1026,7 +1047,7 @@ x = {
 
             def bbbbbbbbbbbbb(self):  # 5
                 pass
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         class A(object):
             def aaaaaaaaaaaaa(self):
@@ -1035,7 +1056,7 @@ x = {
 
             def bbbbbbbbbbbbb(self):  # 5
                 pass
-        """)
+    """)
     self.assertYapfReformats(
         unformatted_code,
         expected_formatted_code,
@@ -1052,7 +1073,7 @@ x = {
                      c.ffffffffffff),
              gggggggggggg.hhhhhhhhh(c, c.ffffffffffff))
                 iiiii = jjjjjjjjjjjjjj.iiiii
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         class A(object):
             def aaaaaaaaaaaaa(self):
@@ -1061,7 +1082,7 @@ x = {
                                   'eeeeeeeeeeeeeeeeeeeeeeeee.%s' % c.ffffffffffff),
                                  gggggggggggg.hhhhhhhhh(c, c.ffffffffffff))
                 iiiii = jjjjjjjjjjjjjj.iiiii
-        """)  # noqa
+    """)  # noqa
     self.assertYapfReformats(
         unformatted_code,
         expected_formatted_code,
@@ -1075,7 +1096,7 @@ x = {
             '''  # comment
             x = '''hello world'''  # second comment
             return 42  # another comment
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         def foo():
             '''First line.
@@ -1083,7 +1104,7 @@ x = {
             '''  # comment
             x = '''hello world'''  # second comment
             return 42  # another comment
-        """)
+    """)
     self.assertYapfReformats(
         unformatted_code,
         expected_formatted_code,
@@ -1092,15 +1113,15 @@ x = {
   def testDedentClosingBracket(self):
     # no line-break on the first argument, not dedenting closing brackets
     unformatted_code = textwrap.dedent("""\
-      def overly_long_function_name(first_argument_on_the_same_line,
-      second_argument_makes_the_line_too_long):
-        pass
-    """)
-    expected_formatted_code = textwrap.dedent("""\
-      def overly_long_function_name(first_argument_on_the_same_line,
-                                    second_argument_makes_the_line_too_long):
+        def overly_long_function_name(first_argument_on_the_same_line,
+        second_argument_makes_the_line_too_long):
           pass
     """)
+    expected_formatted_code = textwrap.dedent("""\
+        def overly_long_function_name(first_argument_on_the_same_line,
+                                      second_argument_makes_the_line_too_long):
+            pass
+    """)  # noqa
     self.assertYapfReformats(
         unformatted_code,
         expected_formatted_code,
@@ -1115,10 +1136,10 @@ x = {
 
     # line-break before the first argument, dedenting closing brackets if set
     unformatted_code = textwrap.dedent("""\
-      def overly_long_function_name(
-        first_argument_on_the_same_line,
-        second_argument_makes_the_line_too_long):
-        pass
+        def overly_long_function_name(
+          first_argument_on_the_same_line,
+          second_argument_makes_the_line_too_long):
+          pass
     """)
     # expected_formatted_pep8_code = textwrap.dedent("""\
     #   def overly_long_function_name(
@@ -1127,10 +1148,10 @@ x = {
     #       pass
     # """)
     expected_formatted_fb_code = textwrap.dedent("""\
-      def overly_long_function_name(
-          first_argument_on_the_same_line, second_argument_makes_the_line_too_long
-      ):
-          pass
+        def overly_long_function_name(
+            first_argument_on_the_same_line, second_argument_makes_the_line_too_long
+        ):
+            pass
     """)  # noqa
     self.assertYapfReformats(
         unformatted_code,
@@ -1150,20 +1171,21 @@ x = {
                'first_argument_of_the_thing': id,
                'second_argument_of_the_thing': "some thing"
            }
-       )""")
+       )
+    """)
     expected_formatted_code = textwrap.dedent("""\
        some_long_function_name_foo({
            'first_argument_of_the_thing': id,
            'second_argument_of_the_thing': "some thing"
        })
-       """)
+    """)
     with utils.NamedTempFile(dirname=self.test_tmpdir, mode='w') as (f, name):
       f.write(
-          textwrap.dedent(u'''\
+          textwrap.dedent("""\
           [style]
           column_limit=82
           coalesce_brackets = True
-          '''))
+      """))
       f.flush()
       self.assertYapfReformats(
           unformatted_code,
@@ -1175,12 +1197,12 @@ x = {
         def   foo():
           def bar():
             return {msg_id: author for author, msg_id in reader}
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         def foo():
           def bar():
             return {msg_id: author for author, msg_id in reader}
-        """)
+    """)
     self.assertYapfReformats(
         unformatted_code,
         expected_formatted_code,
@@ -1200,7 +1222,7 @@ x = {
                 ('yyyyy', zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz),
             '#': lambda x: x  # do nothing
         }
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         # This is a comment
         FOO = {
@@ -1214,7 +1236,7 @@ x = {
                 ('yyyyy', zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz),
             '#': lambda x: x  # do nothing
         }
-        """)
+    """)
     self.assertYapfReformats(
         unformatted_code,
         expected_formatted_code,
@@ -1227,36 +1249,36 @@ x = {
         SCOPES = [
             'hello world'  # This is a comment.
         ]
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         import os
 
         SCOPES = [
             'hello world'  # This is a comment.
         ]
-        """)
+    """)
     self.assertYapfReformats(
         unformatted_code,
         expected_formatted_code,
         extra_options=['--lines', '1-1', '--style', 'yapf'])
 
   def testUseTabs(self):
-    unformatted_code = """\
-def foo_function():
- if True:
-  pass
-"""
+    unformatted_code = textwrap.dedent("""\
+        def foo_function():
+         if True:
+          pass
+    """)
     expected_formatted_code = """\
 def foo_function():
 	if True:
 		pass
 """  # noqa: W191,E101
-    style_contents = u"""\
-[style]
-based_on_style = yapf
-USE_TABS = true
-INDENT_WIDTH=1
-"""
+    style_contents = textwrap.dedent("""\
+        [style]
+        based_on_style = yapf
+        use_tabs = true
+        indent_width = 1
+    """)
     with utils.TempFileContents(self.test_tmpdir, style_contents) as stylepath:
       self.assertYapfReformats(
           unformatted_code,
@@ -1275,12 +1297,12 @@ def f():
 	    'world',
 	]
 """  # noqa: W191,E101
-    style_contents = u"""\
-[style]
-based_on_style = yapf
-USE_TABS = true
-INDENT_WIDTH=1
-"""
+    style_contents = textwrap.dedent("""\
+        [style]
+        based_on_style = yapf
+        use_tabs = true
+        indent_width = 1
+    """)
     with utils.TempFileContents(self.test_tmpdir, style_contents) as stylepath:
       self.assertYapfReformats(
           unformatted_code,
@@ -1300,15 +1322,15 @@ def foo_function(
 			'world',
 	]
 """  # noqa: W191,E101
-    style_contents = u"""\
-[style]
-based_on_style = yapf
-USE_TABS = true
-COLUMN_LIMIT=32
-INDENT_WIDTH=4
-CONTINUATION_INDENT_WIDTH=8
-CONTINUATION_ALIGN_STYLE = fixed
-"""
+    style_contents = textwrap.dedent("""\
+        [style]
+        based_on_style = yapf
+        use_tabs = true
+        column_limit=32
+        indent_width=4
+        continuation_indent_width=8
+        continuation_align_style = fixed
+    """)
     with utils.TempFileContents(self.test_tmpdir, style_contents) as stylepath:
       self.assertYapfReformats(
           unformatted_code,
@@ -1328,15 +1350,15 @@ def foo_function(arg1, arg2,
 			'world',
 	]
 """  # noqa: W191,E101
-    style_contents = u"""\
-[style]
-based_on_style = yapf
-USE_TABS = true
-COLUMN_LIMIT=32
-INDENT_WIDTH=4
-CONTINUATION_INDENT_WIDTH=8
-CONTINUATION_ALIGN_STYLE = valign-right
-"""
+    style_contents = textwrap.dedent("""\
+        [style]
+        based_on_style = yapf
+        use_tabs = true
+        column_limit = 32
+        indent_width = 4
+        continuation_indent_width = 8
+        continuation_align_style = valign-right
+    """)
     with utils.TempFileContents(self.test_tmpdir, style_contents) as stylepath:
       self.assertYapfReformats(
           unformatted_code,
@@ -1344,26 +1366,26 @@ CONTINUATION_ALIGN_STYLE = valign-right
           extra_options=['--style={0}'.format(stylepath)])
 
   def testUseSpacesContinuationAlignStyleFixed(self):
-    unformatted_code = """\
-def foo_function(arg1, arg2, arg3):
-  return ['hello', 'world',]
-"""
-    expected_formatted_code = """\
-def foo_function(
-        arg1, arg2, arg3):
-    return [
-            'hello',
-            'world',
-    ]
-"""
-    style_contents = u"""\
-[style]
-based_on_style = yapf
-COLUMN_LIMIT=32
-INDENT_WIDTH=4
-CONTINUATION_INDENT_WIDTH=8
-CONTINUATION_ALIGN_STYLE = fixed
-"""
+    unformatted_code = textwrap.dedent("""\
+        def foo_function(arg1, arg2, arg3):
+          return ['hello', 'world',]
+    """)
+    expected_formatted_code = textwrap.dedent("""\
+        def foo_function(
+                arg1, arg2, arg3):
+            return [
+                    'hello',
+                    'world',
+            ]
+    """)
+    style_contents = textwrap.dedent("""\
+        [style]
+        based_on_style = yapf
+        column_limit = 32
+        indent_width = 4
+        continuation_indent_width = 8
+        continuation_align_style = fixed
+    """)
     with utils.TempFileContents(self.test_tmpdir, style_contents) as stylepath:
       self.assertYapfReformats(
           unformatted_code,
@@ -1371,26 +1393,26 @@ CONTINUATION_ALIGN_STYLE = fixed
           extra_options=['--style={0}'.format(stylepath)])
 
   def testUseSpacesContinuationAlignStyleVAlignRight(self):
-    unformatted_code = """\
-def foo_function(arg1, arg2, arg3):
-  return ['hello', 'world',]
-"""
-    expected_formatted_code = """\
-def foo_function(arg1, arg2,
-                    arg3):
-    return [
-            'hello',
-            'world',
-    ]
-"""
-    style_contents = u"""\
-[style]
-based_on_style = yapf
-COLUMN_LIMIT=32
-INDENT_WIDTH=4
-CONTINUATION_INDENT_WIDTH=8
-CONTINUATION_ALIGN_STYLE = valign-right
-"""
+    unformatted_code = textwrap.dedent("""\
+        def foo_function(arg1, arg2, arg3):
+          return ['hello', 'world',]
+    """)
+    expected_formatted_code = textwrap.dedent("""\
+        def foo_function(arg1, arg2,
+                            arg3):
+            return [
+                    'hello',
+                    'world',
+            ]
+    """)
+    style_contents = textwrap.dedent("""\
+        [style]
+        based_on_style = yapf
+        column_limit = 32
+        indent_width = 4
+        continuation_indent_width = 8
+        continuation_align_style = valign-right
+    """)
     with utils.TempFileContents(self.test_tmpdir, style_contents) as stylepath:
       self.assertYapfReformats(
           unformatted_code,
@@ -1401,11 +1423,11 @@ CONTINUATION_ALIGN_STYLE = valign-right
     unformatted_code = textwrap.dedent("""\
         def foo_function():
           pass
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         def foo_function():
             pass
-        """)
+    """)
 
     with utils.NamedTempFile(dirname=self.test_tmpdir) as (stylefile,
                                                            stylepath):
@@ -1431,7 +1453,7 @@ CONTINUATION_ALIGN_STYLE = valign-right
             pass
         def _():
             pass
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         A = 42
 
@@ -1441,7 +1463,7 @@ CONTINUATION_ALIGN_STYLE = valign-right
             pass
         def _():
             pass
-        """)
+    """)
     self.assertYapfReformats(
         unformatted_code,
         expected_formatted_code,
@@ -1462,7 +1484,7 @@ CONTINUATION_ALIGN_STYLE = valign-right
             BORKED:  # Broken.
                 'BROKEN'
         }
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         A = 42
 
@@ -1477,7 +1499,7 @@ CONTINUATION_ALIGN_STYLE = valign-right
             BORKED:  # Broken.
                 'BROKEN'
         }
-        """)
+    """)
     self.assertYapfReformats(
         unformatted_code,
         expected_formatted_code,
@@ -1492,7 +1514,7 @@ CONTINUATION_ALIGN_STYLE = valign-right
                 return
             return
         # yapf: enable
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         # yapf_lines_bug.py
         # yapf: disable
@@ -1501,64 +1523,38 @@ CONTINUATION_ALIGN_STYLE = valign-right
                 return
             return
         # yapf: enable
-        """)
+    """)
     self.assertYapfReformats(
         unformatted_code,
         expected_formatted_code,
         extra_options=['--lines', '1-8'])
 
-  @unittest.skipUnless(py3compat.PY36, 'Requires Python 3.6')
-  def testNoSpacesAroundBinaryOperators(self):
-    unformatted_code = """\
-a = 4-b/c@d**37
-"""
-    expected_formatted_code = """\
-a = 4-b / c@d**37
-"""
-    self.assertYapfReformats(
-        unformatted_code,
-        expected_formatted_code,
-        extra_options=[
-            '--style',
-            '{based_on_style: pep8, '
-            'no_spaces_around_selected_binary_operators: "@,**,-"}',
-        ])
-
-  @unittest.skipUnless(py3compat.PY36, 'Requires Python 3.6')
-  def testCP936Encoding(self):
-    unformatted_code = 'print("中文")\n'
-    expected_formatted_code = 'print("中文")\n'
-    self.assertYapfReformats(
-        unformatted_code,
-        expected_formatted_code,
-        env={'PYTHONIOENCODING': 'cp936'})
-
   def testDisableWithLineRanges(self):
-    unformatted_code = """\
-# yapf: disable
-a = [
-    1,
-    2,
+    unformatted_code = textwrap.dedent("""\
+        # yapf: disable
+        a = [
+            1,
+            2,
 
-    3
-]
-"""
-    expected_formatted_code = """\
-# yapf: disable
-a = [
-    1,
-    2,
+            3
+        ]
+    """)
+    expected_formatted_code = textwrap.dedent("""\
+        # yapf: disable
+        a = [
+            1,
+            2,
 
-    3
-]
-"""
+            3
+        ]
+    """)
     self.assertYapfReformats(
         unformatted_code,
         expected_formatted_code,
         extra_options=['--style', 'yapf', '--lines', '1-100'])
 
 
-class BadInputTest(unittest.TestCase):
+class BadInputTest(yapf_test_helper.YAPFTest):
   """Test yapf's behaviour when passed bad input."""
 
   def testBadSyntax(self):
@@ -1570,7 +1566,7 @@ class BadInputTest(unittest.TestCase):
     self.assertRaises(errors.YapfError, yapf_api.FormatCode, code)
 
 
-class DiffIndentTest(unittest.TestCase):
+class DiffIndentTest(yapf_test_helper.YAPFTest):
 
   @staticmethod
   def _OwnStyle():
@@ -1588,11 +1584,11 @@ class DiffIndentTest(unittest.TestCase):
     unformatted_code = textwrap.dedent("""\
         for i in range(5):
          print('bar')
-         """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         for i in range(5):
            print('bar')
-           """)
+    """)
     self._Check(unformatted_code, expected_formatted_code)
 
 
@@ -1622,7 +1618,7 @@ class HorizontallyAlignedTrailingCommentsTest(yapf_test_helper.YAPFTest):
         foo = '3____________<25>' # Aligned at third list value
 
         foo = '4______________________<35>' # Aligned beyond list values
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         foo = '1'     # Aligned at first list value
 
@@ -1631,7 +1627,7 @@ class HorizontallyAlignedTrailingCommentsTest(yapf_test_helper.YAPFTest):
         foo = '3____________<25>'         # Aligned at third list value
 
         foo = '4______________________<35>' # Aligned beyond list values
-        """)
+    """)
     self._Check(unformatted_code, expected_formatted_code)
 
   def testBlock(self):
@@ -1642,7 +1638,7 @@ class HorizontallyAlignedTrailingCommentsTest(yapf_test_helper.YAPFTest):
         func(3)                             # Line 4
                                             # Line 5
                                             # Line 6
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         func(1)       # Line 1
         func(2)       # Line 2
@@ -1650,7 +1646,7 @@ class HorizontallyAlignedTrailingCommentsTest(yapf_test_helper.YAPFTest):
         func(3)       # Line 4
                       # Line 5
                       # Line 6
-        """)
+    """)
     self._Check(unformatted_code, expected_formatted_code)
 
   def testBlockWithLongLine(self):
@@ -1661,7 +1657,7 @@ class HorizontallyAlignedTrailingCommentsTest(yapf_test_helper.YAPFTest):
         func(3)                             # Line 4
                                             # Line 5
                                             # Line 6
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         func(1)                           # Line 1
         func___________________(2)        # Line 2
@@ -1669,7 +1665,7 @@ class HorizontallyAlignedTrailingCommentsTest(yapf_test_helper.YAPFTest):
         func(3)                           # Line 4
                                           # Line 5
                                           # Line 6
-        """)
+    """)
     self._Check(unformatted_code, expected_formatted_code)
 
   def testBlockFuncSuffix(self):
@@ -1683,7 +1679,7 @@ class HorizontallyAlignedTrailingCommentsTest(yapf_test_helper.YAPFTest):
 
         def Func():
             pass
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         func(1)       # Line 1
         func(2)       # Line 2
@@ -1695,7 +1691,7 @@ class HorizontallyAlignedTrailingCommentsTest(yapf_test_helper.YAPFTest):
 
         def Func():
             pass
-        """)
+    """)
     self._Check(unformatted_code, expected_formatted_code)
 
   def testBlockCommentSuffix(self):
@@ -1708,7 +1704,7 @@ class HorizontallyAlignedTrailingCommentsTest(yapf_test_helper.YAPFTest):
                                     # Line 6
 
                                             # Aligned with prev comment block
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         func(1)       # Line 1
         func(2)       # Line 2
@@ -1718,7 +1714,7 @@ class HorizontallyAlignedTrailingCommentsTest(yapf_test_helper.YAPFTest):
                       # Line 6
 
                       # Aligned with prev comment block
-        """)  # noqa
+    """)  # noqa
     self._Check(unformatted_code, expected_formatted_code)
 
   def testBlockIndentedFuncSuffix(self):
@@ -1735,7 +1731,7 @@ class HorizontallyAlignedTrailingCommentsTest(yapf_test_helper.YAPFTest):
 
             def Func():
                 pass
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         if True:
             func(1)   # Line 1
@@ -1751,7 +1747,7 @@ class HorizontallyAlignedTrailingCommentsTest(yapf_test_helper.YAPFTest):
 
             def Func():
                 pass
-        """)
+    """)
     self._Check(unformatted_code, expected_formatted_code)
 
   def testBlockIndentedCommentSuffix(self):
@@ -1765,7 +1761,7 @@ class HorizontallyAlignedTrailingCommentsTest(yapf_test_helper.YAPFTest):
                                                 # Line 6
 
                                                 # Not aligned
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         if True:
             func(1)   # Line 1
@@ -1776,7 +1772,7 @@ class HorizontallyAlignedTrailingCommentsTest(yapf_test_helper.YAPFTest):
                       # Line 6
 
             # Not aligned
-        """)
+    """)
     self._Check(unformatted_code, expected_formatted_code)
 
   def testBlockMultiIndented(self):
@@ -1792,7 +1788,7 @@ class HorizontallyAlignedTrailingCommentsTest(yapf_test_helper.YAPFTest):
                                                         # Line 6
 
                                                         # Not aligned
-        """)  # noqa
+    """)  # noqa
     expected_formatted_code = textwrap.dedent("""\
         if True:
             if True:
@@ -1805,7 +1801,7 @@ class HorizontallyAlignedTrailingCommentsTest(yapf_test_helper.YAPFTest):
                                 # Line 6
 
                     # Not aligned
-        """)
+    """)
     self._Check(unformatted_code, expected_formatted_code)
 
   def testArgs(self):
@@ -1819,7 +1815,7 @@ class HorizontallyAlignedTrailingCommentsTest(yapf_test_helper.YAPFTest):
             arg6,
         ):
             pass
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         def MyFunc(
             arg1,               # Desc 1
@@ -1830,7 +1826,7 @@ class HorizontallyAlignedTrailingCommentsTest(yapf_test_helper.YAPFTest):
             arg6,
         ):
             pass
-        """)
+    """)
     self._Check(unformatted_code, expected_formatted_code)
 
   def testDisableBlock(self):
@@ -1845,7 +1841,7 @@ class HorizontallyAlignedTrailingCommentsTest(yapf_test_helper.YAPFTest):
 
         e() # comment 5
         f() # comment 6
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         a()           # comment 1
         b()           # comment 2
@@ -1857,7 +1853,7 @@ class HorizontallyAlignedTrailingCommentsTest(yapf_test_helper.YAPFTest):
 
         e()           # comment 5
         f()           # comment 6
-        """)
+    """)
     self._Check(unformatted_code, expected_formatted_code)
 
   def testDisabledLine(self):
@@ -1866,17 +1862,17 @@ class HorizontallyAlignedTrailingCommentsTest(yapf_test_helper.YAPFTest):
         do_not_touch1 # yapf: disable
         do_not_touch2   # yapf: disable
         a_longer_statement # comment 2
-        """)
+    """)
     expected_formatted_code = textwrap.dedent("""\
         short                   # comment 1
         do_not_touch1 # yapf: disable
         do_not_touch2   # yapf: disable
         a_longer_statement      # comment 2
-        """)
+    """)
     self._Check(unformatted_code, expected_formatted_code)
 
 
-class _SpacesAroundDictListTupleTestImpl(unittest.TestCase):
+class _SpacesAroundDictListTupleTestImpl(yapf_test_helper.YAPFTest):
 
   @staticmethod
   def _OwnStyle():
@@ -1906,40 +1902,39 @@ class SpacesAroundDictTest(_SpacesAroundDictListTupleTestImpl):
 
   def testStandard(self):
     unformatted_code = textwrap.dedent("""\
-      {1 : 2}
-      {k:v for k, v in other.items()}
-      {k for k in [1, 2, 3]}
+        {1 : 2}
+        {k:v for k, v in other.items()}
+        {k for k in [1, 2, 3]}
 
-      # The following statements should not change
-      {}
-      {1 : 2} # yapf: disable
+        # The following statements should not change
+        {}
+        {1 : 2} # yapf: disable
 
-      # yapf: disable
-      {1 : 2}
-      # yapf: enable
+        # yapf: disable
+        {1 : 2}
+        # yapf: enable
 
-      # Dict settings should not impact lists or tuples
-      [1, 2]
-      (3, 4)
-      """)
+        # Dict settings should not impact lists or tuples
+        [1, 2]
+        (3, 4)
+    """)
     expected_formatted_code = textwrap.dedent("""\
-      { 1: 2 }
-      { k: v for k, v in other.items() }
-      { k for k in [1, 2, 3] }
-
-      # The following statements should not change
-      {}
-      {1 : 2} # yapf: disable
+        { 1: 2 }
+        { k: v for k, v in other.items() }
+        { k for k in [1, 2, 3] }
 
-      # yapf: disable
-      {1 : 2}
-      # yapf: enable
+        # The following statements should not change
+        {}
+        {1 : 2} # yapf: disable
 
-      # Dict settings should not impact lists or tuples
-      [1, 2]
-      (3, 4)
-      """)
+        # yapf: disable
+        {1 : 2}
+        # yapf: enable
 
+        # Dict settings should not impact lists or tuples
+        [1, 2]
+        (3, 4)
+    """)
     self._Check(unformatted_code, expected_formatted_code)
 
 
@@ -1954,48 +1949,47 @@ class SpacesAroundListTest(_SpacesAroundDictListTupleTestImpl):
 
   def testStandard(self):
     unformatted_code = textwrap.dedent("""\
-      [a,b,c]
-      [4,5,]
-      [6, [7, 8], 9]
-      [v for v in [1,2,3] if v & 1]
-
-      # The following statements should not change
-      index[0]
-      index[a, b]
-      []
-      [v for v in [1,2,3] if v & 1] # yapf: disable
-
-      # yapf: disable
-      [a,b,c]
-      [4,5,]
-      # yapf: enable
-
-      # List settings should not impact dicts or tuples
-      {a: b}
-      (1, 2)
-      """)
+        [a,b,c]
+        [4,5,]
+        [6, [7, 8], 9]
+        [v for v in [1,2,3] if v & 1]
+
+        # The following statements should not change
+        index[0]
+        index[a, b]
+        []
+        [v for v in [1,2,3] if v & 1] # yapf: disable
+
+        # yapf: disable
+        [a,b,c]
+        [4,5,]
+        # yapf: enable
+
+        # List settings should not impact dicts or tuples
+        {a: b}
+        (1, 2)
+    """)
     expected_formatted_code = textwrap.dedent("""\
-      [ a, b, c ]
-      [ 4, 5, ]
-      [ 6, [ 7, 8 ], 9 ]
-      [ v for v in [ 1, 2, 3 ] if v & 1 ]
-
-      # The following statements should not change
-      index[0]
-      index[a, b]
-      []
-      [v for v in [1,2,3] if v & 1] # yapf: disable
-
-      # yapf: disable
-      [a,b,c]
-      [4,5,]
-      # yapf: enable
-
-      # List settings should not impact dicts or tuples
-      {a: b}
-      (1, 2)
-      """)
+        [ a, b, c ]
+        [ 4, 5, ]
+        [ 6, [ 7, 8 ], 9 ]
+        [ v for v in [ 1, 2, 3 ] if v & 1 ]
 
+        # The following statements should not change
+        index[0]
+        index[a, b]
+        []
+        [v for v in [1,2,3] if v & 1] # yapf: disable
+
+        # yapf: disable
+        [a,b,c]
+        [4,5,]
+        # yapf: enable
+
+        # List settings should not impact dicts or tuples
+        {a: b}
+        (1, 2)
+    """)
     self._Check(unformatted_code, expected_formatted_code)
 
 
@@ -2010,52 +2004,51 @@ class SpacesAroundTupleTest(_SpacesAroundDictListTupleTestImpl):
 
   def testStandard(self):
     unformatted_code = textwrap.dedent("""\
-      (0, 1)
-      (2, 3)
-      (4, 5, 6,)
-      func((7, 8), 9)
+        (0, 1)
+        (2, 3)
+        (4, 5, 6,)
+        func((7, 8), 9)
 
-      # The following statements should not change
-      func(1, 2)
-      (this_func or that_func)(3, 4)
-      if (True and False): pass
-      ()
+        # The following statements should not change
+        func(1, 2)
+        (this_func or that_func)(3, 4)
+        if (True and False): pass
+        ()
 
-      (0, 1) # yapf: disable
+        (0, 1) # yapf: disable
 
-      # yapf: disable
-      (0, 1)
-      (2, 3)
-      # yapf: enable
+        # yapf: disable
+        (0, 1)
+        (2, 3)
+        # yapf: enable
 
-      # Tuple settings should not impact dicts or lists
-      {a: b}
-      [3, 4]
-      """)
+        # Tuple settings should not impact dicts or lists
+        {a: b}
+        [3, 4]
+    """)
     expected_formatted_code = textwrap.dedent("""\
-      ( 0, 1 )
-      ( 2, 3 )
-      ( 4, 5, 6, )
-      func(( 7, 8 ), 9)
-
-      # The following statements should not change
-      func(1, 2)
-      (this_func or that_func)(3, 4)
-      if (True and False): pass
-      ()
+        ( 0, 1 )
+        ( 2, 3 )
+        ( 4, 5, 6, )
+        func(( 7, 8 ), 9)
 
-      (0, 1) # yapf: disable
+        # The following statements should not change
+        func(1, 2)
+        (this_func or that_func)(3, 4)
+        if (True and False): pass
+        ()
 
-      # yapf: disable
-      (0, 1)
-      (2, 3)
-      # yapf: enable
+        (0, 1) # yapf: disable
 
-      # Tuple settings should not impact dicts or lists
-      {a: b}
-      [3, 4]
-      """)
+        # yapf: disable
+        (0, 1)
+        (2, 3)
+        # yapf: enable
 
+        # Tuple settings should not impact dicts or lists
+        {a: b}
+        [3, 4]
+    """)
     self._Check(unformatted_code, expected_formatted_code)
 
 
diff --git a/yapftests/yapf_test_helper.py b/yapftests/yapf_test_helper.py
index 3d1da12..61aa2c5 100644
--- a/yapftests/yapf_test_helper.py
+++ b/yapftests/yapf_test_helper.py
@@ -17,25 +17,22 @@ import difflib
 import sys
 import unittest
 
-from yapf.yapflib import blank_line_calculator
-from yapf.yapflib import comment_splicer
-from yapf.yapflib import continuation_splicer
+from yapf.pytree import blank_line_calculator
+from yapf.pytree import comment_splicer
+from yapf.pytree import continuation_splicer
+from yapf.pytree import pytree_unwrapper
+from yapf.pytree import pytree_utils
+from yapf.pytree import pytree_visitor
+from yapf.pytree import split_penalty
+from yapf.pytree import subtype_assigner
 from yapf.yapflib import identify_container
-from yapf.yapflib import py3compat
-from yapf.yapflib import pytree_unwrapper
-from yapf.yapflib import pytree_utils
-from yapf.yapflib import pytree_visitor
-from yapf.yapflib import split_penalty
 from yapf.yapflib import style
-from yapf.yapflib import subtype_assigner
 
 
 class YAPFTest(unittest.TestCase):
 
   def __init__(self, *args):
     super(YAPFTest, self).__init__(*args)
-    if not py3compat.PY3:
-      self.assertRaisesRegex = self.assertRaisesRegexp
 
   def assertCodeEqual(self, expected_code, code):
     if code != expected_code:
```

