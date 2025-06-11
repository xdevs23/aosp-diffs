```diff
diff --git a/.github/dependabot.yml b/.github/dependabot.yml
new file mode 100644
index 0000000..e5903e0
--- /dev/null
+++ b/.github/dependabot.yml
@@ -0,0 +1,6 @@
+version: 2
+updates:
+- package-ecosystem: github-actions
+  directory: "/"
+  schedule:
+    interval: weekly
diff --git a/.github/workflows/dockerfiles/Dockerfile_debian b/.github/workflows/dockerfiles/Dockerfile_debian
index 7d34f4f..a73522d 100644
--- a/.github/workflows/dockerfiles/Dockerfile_debian
+++ b/.github/workflows/dockerfiles/Dockerfile_debian
@@ -31,7 +31,7 @@ RUN apt-get update && apt-get install -y \
 
 RUN apt-get clean
 
-RUN useradd -u 1000 pyfakefs
+RUN useradd pyfakefs
 
 RUN mkdir -p work \
     && wget https://github.com/$github_repo/archive/$github_branch.zip -O archive.zip \
diff --git a/.github/workflows/dockerfiles/Dockerfile_fedora b/.github/workflows/dockerfiles/Dockerfile_fedora
index 9b6b5bd..5bc3146 100644
--- a/.github/workflows/dockerfiles/Dockerfile_fedora
+++ b/.github/workflows/dockerfiles/Dockerfile_fedora
@@ -23,7 +23,7 @@ ARG github_branch=main
 
 RUN dnf install -y python3-pip unzip wget
 
-RUN useradd -u 1000 pyfakefs
+RUN useradd pyfakefs
 
 RUN mkdir -p work \
     && wget https://github.com/$github_repo/archive/$github_branch.zip -O archive.zip \
diff --git a/.github/workflows/dockerfiles/Dockerfile_redhat b/.github/workflows/dockerfiles/Dockerfile_redhat
index 00bb825..90fa0c3 100644
--- a/.github/workflows/dockerfiles/Dockerfile_redhat
+++ b/.github/workflows/dockerfiles/Dockerfile_redhat
@@ -26,7 +26,7 @@ ENV LANG en_US.UTF-8
 ENV LANGUAGE en_US:en
 ENV LC_COLLATE C.UTF-8
 
-RUN useradd -u 1000 pyfakefs
+RUN useradd pyfakefs
 
 RUN mkdir -p work \
     && wget https://github.com/$github_repo/archive/$github_branch.zip -O archive.zip \
diff --git a/.github/workflows/dockerfiles/Dockerfile_ubuntu b/.github/workflows/dockerfiles/Dockerfile_ubuntu
index f76fa31..55561bf 100644
--- a/.github/workflows/dockerfiles/Dockerfile_ubuntu
+++ b/.github/workflows/dockerfiles/Dockerfile_ubuntu
@@ -31,7 +31,7 @@ RUN apt-get update && apt-get install -y \
 
 RUN apt-get clean
 
-RUN useradd -u 1000 pyfakefs
+RUN useradd pyfakefs
 
 RUN mkdir -p work \
     && wget https://github.com/$github_repo/archive/$github_branch.zip -O archive.zip \
diff --git a/.github/workflows/dockertests.yml b/.github/workflows/dockertests.yml
index 9daa2ad..f5db5dd 100644
--- a/.github/workflows/dockertests.yml
+++ b/.github/workflows/dockertests.yml
@@ -11,7 +11,7 @@ jobs:
       matrix:
         docker-image: [debian, fedora, ubuntu, redhat]
     steps:
-    - uses: actions/checkout@v3
+    - uses: actions/checkout@v4
     - name: Setup docker container
       run: |
         docker build -t pyfakefs -f $GITHUB_WORKSPACE/.github/workflows/dockerfiles/Dockerfile_${{ matrix.docker-image }} . --build-arg github_repo=$GITHUB_REPOSITORY --build-arg github_branch=$GITHUB_REF_NAME
diff --git a/.github/workflows/release-deploy.yml b/.github/workflows/release-deploy.yml
index 41f4369..07414de 100644
--- a/.github/workflows/release-deploy.yml
+++ b/.github/workflows/release-deploy.yml
@@ -8,16 +8,19 @@ jobs:
 
   deploy:
     runs-on: ubuntu-latest
+    environment: release
+    permissions:
+      id-token: write
     strategy:
       fail-fast: true
       matrix:
         python-version: [ '3.10' ]
 
     steps:
-    - uses: actions/checkout@v3
+    - uses: actions/checkout@v4
 
     - name: Set up Python ${{ matrix.python-version }}
-      uses: actions/setup-python@v4
+      uses: actions/setup-python@v5
       with:
         python-version: ${{ matrix.python-version }}
 
@@ -29,6 +32,3 @@ jobs:
 
     - name: Publish package to PyPI
       uses: pypa/gh-action-pypi-publish@release/v1
-      with:
-        user: __token__
-        password: ${{ secrets.PYPI_TOKEN }}
diff --git a/.github/workflows/testsuite.yml b/.github/workflows/testsuite.yml
index 51b59b2..8231af2 100644
--- a/.github/workflows/testsuite.yml
+++ b/.github/workflows/testsuite.yml
@@ -3,56 +3,69 @@ name: Testsuite
 on:
   [push, pull_request]
 
+defaults:
+  run:
+    shell: bash
+
 jobs:
   pytype:
     runs-on: ubuntu-latest
     steps:
     - name: Check out repository
-      uses: actions/checkout@v3
+      uses: actions/checkout@v4
     - name: Set up Python
-      uses: actions/setup-python@v4
+      uses: actions/setup-python@v5
       with:
         python-version: "3.10"
     - name: install pytype
-      run: pip install setuptools pytype pytest scandir pathlib2 pandas xlrd django
+      run: pip install setuptools pytype pytest scandir pathlib2 pandas xlrd django pyarrow
     - name: Run pytype
       run: |
         pytype pyfakefs --keep-going --exclude pyfakefs/tests/* --exclude pyfakefs/pytest_tests/*
 
   tests:
     runs-on: ${{ matrix.os }}
+    env:
+      PYTHONWARNDEFAULTENCODING: true
+      PIP_DISABLE_PIP_VERSION_CHECK: 1
     strategy:
       fail-fast: false
       matrix:
         os: [ubuntu-latest, macOS-latest, windows-latest]
-        python-version: ["3.8", "3.9", "3.10", "3.11", "3.12-dev"]
+        python-version: [3.8, 3.9, "3.10", "3.11", "3.12", "3.13", "3.14"]
         include:
           - python-version: "pypy-3.7"
-            os: ubuntu-latest
+            os: ubuntu-22.04
           - python-version: "pypy-3.9"
             os: ubuntu-latest
           - python-version: "pypy-3.10"
             os: ubuntu-latest
+          - python-version: "3.7"
+            os: ubuntu-22.04
+          - python-version: "3.7"
+            os: windows-latest
 
     steps:
-    - uses: actions/checkout@v3
+    - uses: actions/checkout@v4
     - name: Set up Python ${{ matrix.python-version }}
-      uses: actions/setup-python@v4
+      uses: actions/setup-python@v5
       with:
         python-version: ${{ matrix.python-version }}
+        allow-prereleases: true
 
     - name: Get pip cache dir
       id: pip-cache
+      shell: bash
       run: |
         python -m pip install --upgrade pip
-        echo "::set-output name=dir::$(pip cache dir)"
+        echo "dir=$(pip cache dir)" >> $GITHUB_OUTPUT
 
     - name: Cache dependencies
       id: cache-dep
-      uses: actions/cache@v3
+      uses: actions/cache@v4
       with:
         path: ${{ steps.pip-cache.outputs.dir }}
-        key: ${{ matrix.os }}-${{ matrix.python-version }}-pip-${{ hashFiles('**/requirements.txt') }}-${{ hashFiles('**/extra_requirements.txt') }}
+        key: ${{ matrix.os }}-${{ matrix.python-version }}-pip-${{ hashFiles('**/requirements.txt') }}-${{ hashFiles('**/extra_requirements.txt') }}-${{ hashFiles('**/legacy_requirements.txt') }}
         restore-keys: |
           ${{ matrix.os }}-${{ matrix.python-version }}-pip-
 
@@ -65,30 +78,29 @@ jobs:
         export TEST_REAL_FS=1
         python -bb -m pyfakefs.tests.all_tests_without_extra_packages
       shell: bash
-    - name: Run setup.py test (uses pytest)
-      run: |
-        python setup.py test
-      shell: bash
     - name: Run unit tests without extra packages as root
       run: |
-        if [[ '${{ matrix.os  }}' != 'windows-latest' ]]; then
+        if [[ '${{ matrix.os }}' != 'windows-latest' ]]; then
           # provide the same path as non-root to get the correct virtualenv
           sudo env "PATH=$PATH" python -m pyfakefs.tests.all_tests_without_extra_packages
         fi
       shell: bash
     - name: Install extra dependencies
-      if: ${{ matrix.python-version != '3.12-dev' }}
+      if: ${{ matrix.python-version != '3.14' }}
       run: |
         pip install -r extra_requirements.txt
+        pip install -r legacy_requirements.txt
+        pip install zstandard cffi  # needed to test #910
       shell: bash
     - name: Run unit tests with extra packages as non-root user
-      if: ${{ matrix.python-version != '3.12-dev' }}
+      if: ${{ matrix.python-version != '3.14' }}
       run: |
+        export PYTHON_ZSTANDARD_IMPORT_POLICY=cffi  # needed to test #910
         python -m pyfakefs.tests.all_tests
       shell: bash
     - name: Run performance tests
       run: |
-        if [[ '${{ matrix.os  }}' != 'macOS-latest' ]]; then
+        if [[ '${{ matrix.os }}' != 'macOS-latest' ]]; then
           export TEST_PERFORMANCE=1
           python -m pyfakefs.tests.performance_test
         fi
@@ -96,36 +108,34 @@ jobs:
 
   pytest-test:
     runs-on: ${{ matrix.os }}
+    env:
+      PIP_DISABLE_PIP_VERSION_CHECK: 1
     strategy:
       fail-fast: false
       matrix:
         os: [ubuntu-latest, macOS-latest, windows-latest]
-        python-version: ["3.9"]
-        pytest-version: [3.0.0, 3.5.1, 4.0.2, 4.5.0, 5.0.1, 5.4.3, 6.0.2, 6.2.5, 7.0.1, 7.1.3, 7.2.0, 7.3.1, 7.4.0]
+        python-version: [3.8, 3.9, "3.10", "3.11", "3.12", "3.13"]
+        pytest-version: [6.2.5, 7.0.1, 7.4.4, 8.0.2, 8.3.4]
     steps:
-      - uses: actions/checkout@v3
+      - uses: actions/checkout@v4
       - name: Set up Python ${{ matrix.python-version }}
-        uses: actions/setup-python@v4
+        uses: actions/setup-python@v5
         with:
           python-version: ${{ matrix.python-version }}
       - name: Install dependencies
         run: |
-          pip install -r requirements.txt
-          pip install -U pytest==${{ matrix.pytest-version }}
-          pip install opentimelineio
-          pip install -e .
-          if [[ '${{ matrix.pytest-version }}' == '4.0.2' ]]; then
-             pip install -U attrs==19.1.0
-          fi
+          python -m pip install --upgrade pip
+          python -m pip install -r requirements.txt
+          python -m pip install -U pytest==${{ matrix.pytest-version }}
+          python -m pip install pandas parquet pyarrow
+          python -m pip install -e .
         shell: bash
       - name: Run pytest tests
         run: |
           echo "$(python -m pytest pyfakefs/pytest_tests/pytest_plugin_failing_helper.py)" > ./testresult.txt
-          python -m pytest pyfakefs/pytest_tests
-          if [[ '${{ matrix.pytest-version }}' > '3.0.0' ]]; then
-            cd pyfakefs/pytest_tests/ns_package
-            python -m pytest --log-cli-level=INFO test
-          fi
+          pytest pyfakefs/pytest_tests
+          cd pyfakefs/pytest_tests/ns_package
+          pytest --log-cli-level=INFO test
         shell: bash
 
   dependency-check:
@@ -135,15 +145,16 @@ jobs:
         os: [ubuntu-latest, windows-latest]
         python-version:  ["3.10"]
     steps:
-      - uses: actions/checkout@v3
+      - uses: actions/checkout@v4
       - name: Set up Python ${{ matrix.python-version }}
-        uses: actions/setup-python@v4
+        uses: actions/setup-python@v5
         with:
           python-version: ${{ matrix.python-version }}
       - name: Install dependencies
         run: |
           pip install -r requirements.txt
           pip install -r extra_requirements.txt
+          pip install -r legacy_requirements.txt
           pip install pytest-find-dependencies
       - name: Check dependencies
         run: python -m pytest --find-dependencies pyfakefs/tests
diff --git a/.pre-commit-config.yaml b/.pre-commit-config.yaml
index f1bcd07..d6b09ac 100644
--- a/.pre-commit-config.yaml
+++ b/.pre-commit-config.yaml
@@ -2,24 +2,33 @@ default_language_version:
   python: "3.10"
 
 repos:
+  - repo: "https://github.com/asottile/pyupgrade"
+    rev: "v3.19.1"
+    hooks:
+      - id: "pyupgrade"
+        name: "Enforce Python 3.7+ idioms"
+        args:
+          - "--py37-plus"
+
+  - repo: https://github.com/astral-sh/ruff-pre-commit
+    rev: "v0.9.6"
+    hooks:
+      - id: ruff
+        args: ["--fix"]
+      - id: ruff-format
   - repo: https://github.com/codespell-project/codespell
-    rev: v2.2.5
+    rev: v2.4.1
     hooks:
       - id: codespell
         args:
-          - --ignore-words-list=wronly,afile
-  - repo: https://github.com/psf/black
-    rev: 23.7.0
-    hooks:
-      - id: black
-        args: [ --safe, --quiet ]
+          - --ignore-words-list=wronly,afile,assertIn
   - repo: https://github.com/asottile/blacken-docs
-    rev: 1.16.0
+    rev: 1.19.1
     hooks:
       - id: blacken-docs
-        additional_dependencies: [ black==22.12.0 ]
+        additional_dependencies: [ black==24.4.2 ]
   - repo: https://github.com/pre-commit/pre-commit-hooks
-    rev: v4.4.0
+    rev: v5.0.0
     hooks:
       - id: trailing-whitespace
       - id: end-of-file-fixer
@@ -29,23 +38,15 @@ repos:
       - id: debug-statements
         language_version: python3
   - repo: https://github.com/PyCQA/autoflake
-    rev: v2.2.0
+    rev: v2.3.1
     hooks:
       - id: autoflake
         name: autoflake
         args: ["--in-place", "--remove-unused-variables", "--remove-all-unused-imports"]
         language: python
         files: \.py$
-  - repo: https://github.com/PyCQA/flake8
-    rev: 6.1.0
-    hooks:
-      - id: flake8
-        language_version: python3
-        additional_dependencies:
-          - flake8-bugbear
-        args: ["--extend-ignore=E203", "--max-line-length=88"]
   - repo: https://github.com/pre-commit/mirrors-mypy
-    rev: v1.5.1
+    rev: v1.15.0
     hooks:
       - id: mypy
         exclude: (docs|pyfakefs/tests)
diff --git a/CHANGES.md b/CHANGES.md
index 23958e8..c6229bb 100644
--- a/CHANGES.md
+++ b/CHANGES.md
@@ -1,21 +1,230 @@
 # pyfakefs Release Notes
 The released versions correspond to PyPI releases.
 
+## Policy for Python version support
+* support for new versions is usually added preliminarily during the Python release beta phase,
+  official support after the final release
+* support for EOL versions is removed as soon as the CI (GitHub actions) does no longer provide
+  these versions (usually several months after the official EOL)
+
+## Planned changes for next major release (6.0.0)
+* support for patching legacy modules `scandir` and `pathlib2` will be removed
+* the default for `FakeFilesystem.shuffle_listdir_results` will change to `True` to reflect
+  the real filesystem behavior
+
 ## Unreleased
 
 ### Changes
-* removed support for Python 3.7 (end of life)
+* added some preliminary support for Python 3.14
+
+## [Version 5.7.4](https://pypi.python.org/pypi/pyfakefs/5.7.4) (2025-01-14)
+Minor bugfix release.
+
+### Fixes
+* fixed a problem with module and session scoped fixtures in Python 3.13
+  (see [#1101](../../issues/1101))
+* fixed handling of `cwd` if set to a `pathlib.Path` (see [#1108](../../issues/1108))
+* fixed documentation for cleanup handlers, added convenience handler `reload_cleanup_handler`
+  (see [#1105](../../issues/1105))
+
+## [Version 5.7.3](https://pypi.python.org/pypi/pyfakefs/5.7.3) (2024-12-15)
+Fixes a regression in version 5.7.3.
+
+### Fixes
+* fixed a regression in version 5.7.2 that `tempfile` was not patched after pause/resume
+  (POSIX only, see [#1098](../../issues/1098))
+* added workaround for a recursion occurring if using pytest under Windows and Python >= 3.12
+  (see [#1096](../../issues/1096))
+
+### Infrastructure
+* run pytest-specific tests for all supported Python versions
+* pytest is only supported for versions >= 6.2.5, earlier version do not work in Python >= 3.10
+  due to a pytest issue - adapted tests and documentation
+
+## [Version 5.7.2](https://pypi.python.org/pypi/pyfakefs/5.7.2) (2024-12-01)
+Fixes some problems with patching.
+
+### Fixes
+* added some support for loading fake modules in `AUTO` patch mode
+  using `importlib.import_module` (see [#1079](../../issues/1079))
+* added some support to avoid patching debugger related modules
+  (see [#1083](../../issues/1083))
+
+### Performance
+* avoid reloading `tempfile` in Posix systems
+
+### Infrastructure
+* use trusted publisher for release (see https://docs.pypi.org/trusted-publishers/)
+
+## [Version 5.7.1](https://pypi.python.org/pypi/pyfakefs/5.7.1) (2024-08-13)
+Fixes a regression in version 5.7.0 that broke patching fcntl.
+
+### Fixes
+* fixes a regression that caused unfaked `fcntl` calls to fail (see [#1074](../../issues/1074))
+
+## [Version 5.7.0](https://pypi.python.org/pypi/pyfakefs/5.7.0) (2024-08-10)
+Adds official Python 3.13 support, improves OS emulation behavior.
+
+### Changes
+* officially support Python 3.13
+
+### Enhancements
+* the `additional_skip_names` parameter now works with more modules (see [#1023](../../issues/1023))
+* added support for `os.fchmod`, allow file descriptor argument for `os.chmod` only for POSIX
+  for Python < 3.13
+
+### Performance
+* avoid reloading `glob` in Python 3.13
+
+### Fixes
+* removing files while iterating over `scandir` results is now possible (see [#1051](../../issues/1051))
+* fake `pathlib.PosixPath` and `pathlib.WindowsPath` now behave more like in the real filesystem
+  (see [#1053](../../issues/1053))
+* `PurePosixPath` reported Windows reserved names as reserved in Python >= 3.12
+  (see [#1067](../../issues/1067))
+* `PurePosixPath.joinpath()` incorrectly handled paths with drives under Windows in Python >= 3.12
+  (see [#1070](../../issues/1070))
+
+## [Version 5.6.0](https://pypi.python.org/pypi/pyfakefs/5.6.0) (2024-07-12)
+Adds preliminary Python 3.13 support.
+
+### Enhancements
+* added preliminary support for Python 3.13 (tested with beta2) (see [#1017](../../issues/1017))
+* added `apply_umask` argument to `FakeFilesystem.create_dir` to allow ignoring the umask (see [#1038](../../issues/1038))
+
+### Fixes
+* use real open calls for remaining `pathlib` functions so that it works nice with skippedmodules (see [#1012](../../issues/1012))
+
+### Infrastructure
+* Add pyupgrade as a pre-commit hook.
+
+## [Version 5.5.0](https://pypi.python.org/pypi/pyfakefs/5.5.0) (2024-05-12)
+Deprecates the usage of `pathlib2` and `scandir`.
+
+### Changes
+* The usage of the `pathlib2` and `scandir` modules in pyfakefs is now deprecated.
+  They will now cause deprecation warnings if still used. Support for patching
+  these modules will be removed in pyfakefs 6.0.
+* `PureWindowsPath` and `PurePosixPath` now use filesystem-independent path separators,
+  and their path-parsing behaviors are now consistent regardless of runtime platform
+  and/or faked filesystem customization (see [#1006](../../issues/1006)).
+
+### Fixes
+* fixed handling of Windows `pathlib` paths under POSIX and vice verse (see [#1006](../../issues/1006))
+* correctly use real open calls in pathlib for skipped modules (see [#1012](../../issues/1012))
+
+## [Version 5.4.1](https://pypi.python.org/pypi/pyfakefs/5.4.0) (2024-04-11)
+Fixes a regression.
+
+### Fixes
+* fixed a regression from version 5.4.0 that incorrectly handled files opened twice via file descriptor
+  (see [#997](../../issues/997))
+
+## [Version 5.4.0](https://pypi.python.org/pypi/pyfakefs/5.4.0) (2024-04-07)
+Improves permission handling.
+
+### Changes
+* the handling of file permissions under Posix should now mostly match the behavior
+  of the real filesystem, which may change the behavior of some tests
+* removed the argument `module_cleanup_mode`, that was introduced as a temporary workaround
+  in the previous version - related problems shall be handled using a cleanup handler
+
+### Enhancements
+* added support for `O_NOFOLLOW` and `O_DIRECTORY` flags in `os.open`
+  (see [#972](../../issues/972) and [#974](../../issues/974))
+* added support for fake `os.dup`, `os.dup2` and `os.lseek` (see [#970](../../issues/970))
+
+### Fixes
+* fixed a specific problem on reloading a pandas-related module (see [#947](../../issues/947)),
+  added possibility for unload hooks for specific modules
+* use this also to reload django views (see [#932](../../issues/932))
+* fixed `EncodingWarning` for Python >= 3.11 (see [#957](../../issues/957))
+* consider directory ownership while adding or removing directory entries
+  (see [#959](../../issues/959))
+* fixed handling of directory enumeration and search permissions under Posix systems
+  (see [#960](../../issues/960))
+* fixed creation of the temp directory in the fake file system after a filesystem reset
+  (see [#965](../../issues/965))
+* fixed handling of `dirfd` in `os.symlink` (see [#968](../../issues/968))
+* add missing `follow_symlink` argument to `os.link` (see [#973](../../issues/973))
+* fixed handling of missing attribute in `os.getxattr` (see [#971](../../issues/971))
+* fixed permission problem with `shutil.rmtree` if emulating Windows under POSIX
+  (see [#979](../../issues/979))
+* fixed handling of errors on opening files via file descriptor (see [#967](../../issues/967))
+* fixed handling of `umask` - it is now applied by default
+* fixed behavior of `os.makedirs` (see [#987](../../issues/987))
+
+### Infrastructure
+* replace `undefined` by own minimal implementation to avoid importing it
+  (see [#981](../../discussions/981))
+
+
+## [Version 5.3.5](https://pypi.python.org/pypi/pyfakefs/5.3.5) (2024-01-30)
+Fixes a regression.
+
+### Fixes
+* Fixed a regression due to the changed behavior of the dynamic patcher cleanup (see [#939](../../issues/939)).
+  The change is now by default only made if the `django` module is loaded, and the behavior can
+  be changed using the new argument `module_cleanup_mode`.
+
+### Packaging
+* included `tox.ini` and a few more files into the source distribution (see [#937](../../issues/937))
+
+## [Version 5.3.4](https://pypi.python.org/pypi/pyfakefs/5.3.4) (2024-01-19)
+Bugfix release.
+
+### Fixes
+* fixed handling of unhashable modules which cannot be cached (see [#923](../../issues/923))
+* reload modules loaded by the dynamic patcher instead of removing them - sometimes they may
+  not be reloaded automatically (see [#932](../../issues/932))
+* added back argument `use_dynamic_patch` as a fallback for similar problems
+
+
+## [Version 5.3.2](https://pypi.python.org/pypi/pyfakefs/5.3.2) (2023-11-30)
+Bugfix release.
+
+### Fixes
+* fixed a problem with patching `_io` under Python 3.12 (see [#910](../../issues/910))
+* fixed a problem with accessing the temp path if emulating Linux under Windows
+  (see [#912](../../issues/912))
+* fixed result of `os.walk` with a path-like top directory
+  (see [#915](../../issues/915))
+* properly fixed the problem that filesystem patching was still active in the pytest
+  logreport phase (see [#904](../../issues/904)), the previous fix was incomplete
+
+## [Version 5.3.1](https://pypi.python.org/pypi/pyfakefs/5.3.1) (2023-11-15)
+Mostly a bugfix release.
+
+### Changes
+* changed behavior of `add_real_directory` to be able to map a real directory
+  to an existing directory in the fake filesystem (see [#901](../../issues/901))
+
+### Fixes
+* fixed the problem that filesystem patching was still active in the pytest
+  logreport phase (see [#904](../../issues/904))
+* restored compatibility with PyTorch 2.0 and above, as well as with other
+  classes that have custom __setattr__ methods (see [#905](../../pull/905))
+
+## [Version 5.3.0](https://pypi.python.org/pypi/pyfakefs/5.3.0) (2023-10-11)
+Adds official support for Python 3.12.
+
+### Changes
+* added official support for Python 3.12
 
 ### Fixes
 * removed a leftover debug print statement (see [#869](../../issues/869))
 * make sure tests work without HOME environment set (see [#870](../../issues/870))
+* automount drive or UNC path under Windows if needed for `pathlib.Path.mkdir()`
+  (see [#890](../../issues/890))
+* adapted patching `io.open` and `io.open_code` to work with Python 3.12
+  (see [#836](../../issues/836) and [#892](../../issues/892))
 
-## [Version 5.2.3](https://pypi.python.org/pypi/pyfakefs/5.2.3) (2023-08-18)
+## [Version 5.2.4](https://pypi.python.org/pypi/pyfakefs/5.2.4) (2023-08-18)
 Fixes a rare problem on pytest shutdown.
 
 ### Fixes
 * Clear the patched module cache on session shutdown (pytest only)
-  (see [#866](../../issues/866)). Added a class method `Patcher.cler_fs_cache`
+  (see [#866](../../issues/866)). Added a class method `Patcher.clear_fs_cache`
   for clearing the patched module cache.
 
 ## [Version 5.2.3](https://pypi.python.org/pypi/pyfakefs/5.2.3) (2023-07-10)
@@ -24,12 +233,12 @@ Adds compatibility with PyPy 3.10 and Python 3.12.
 ### Fixes
 * Re-create temp directory if it had been created before on resetting file system
   (see [#814](../../issues/814)).
-* Exclude pytest `pathlib` modules from patching to avoid mixup of patched/unpatched
+* Excluded pytest `pathlib` modules from patching to avoid mixup of patched/unpatched
   code (see [#814](../../issues/814)).
-* Adapt to changes in Python 3.12 beta1 (only working partially,
+* Adapted to changes in Python 3.12 beta1 (only working partially,
   see [#830](../../issues/830) and [#831](../../issues/831)).
-* Adapt to changes in `shutil` in Python 3.12 beta2 (see [#814](../../issues/814)).
-* Fix support for newer PyPi versions (see [#859](../../issues/859)).
+* Adapted to changes in `shutil` in Python 3.12 beta2 (see [#814](../../issues/814)).
+* Fixed support for newer PyPi versions (see [#859](../../issues/859)).
 
 ### Documentation
 * Added a note regarding the incompatibility of the built-in `sqlite3` module with
@@ -300,7 +509,7 @@ This is a bugfix release.
 * skip tests failing with ASCII locale
   (see [#623](../../issues/623))
 
-## [Version 4.5.0](https://pypi.python.org/pypi/pyfakefs/4.5.0) (2021-06-04)
+## Version 4.5.0 (2021-06-04)
 Adds some support for Python 3.10 and basic type checking.
 
 _Note_: This version has been yanked from PyPI as it erroneously allowed
@@ -406,8 +615,10 @@ release.
     default to avoid a large performance impact. An additional parameter
     `patch_default_args` has been added that switches this behavior on
     (see [#567](../../issues/567)).
+
+### Performance
   * Added performance improvements in the test setup, including caching the
-    the unpatched modules
+    unpatched modules
 
 ## [Version 4.2.1](https://pypi.python.org/pypi/pyfakefs/4.2.1) (2020-11-02)
 
@@ -478,7 +689,7 @@ installing them under Python 2.
 #### Fixes
   * Do not build for Python 2 (see [#524](../../issues/524))
 
-## [Version 4.0.1](https://pypi.python.org/pypi/pyfakefs/4.0.1) (2020-03-03)
+## Version 4.0.1 (2020-03-03)
 
 This as a bug fix release for a regression bug.
 
@@ -488,7 +699,7 @@ installation under Python 2. This has been fixed in version 4.0.2.
 #### Fixes
   * Avoid exception if using `flask-restx` (see [#523](../../issues/523))
 
-## [Version 4.0.0](https://pypi.python.org/pypi/pyfakefs/4.0.0) (2020-03-03)
+## Version 4.0.0 (2020-03-03)
 pyfakefs 4.0.0 drops support for Python 2.7. If you still need
 Python 2.7, you can continue to use pyfakefs 3.7.x.
 
diff --git a/Dockerfile b/Dockerfile
index 99524b8..3707d7e 100644
--- a/Dockerfile
+++ b/Dockerfile
@@ -39,7 +39,7 @@ RUN apt-get update && apt-get install -y \
     wget
 RUN apt-get clean
 
-RUN useradd -u 1000 pyfakefs
+RUN useradd pyfakefs
 
 RUN wget https://github.com/pytest-dev/pyfakefs/archive/main.zip \
     && unzip main.zip \
diff --git a/MANIFEST.in b/MANIFEST.in
index b1abafc..aed0396 100755
--- a/MANIFEST.in
+++ b/MANIFEST.in
@@ -1,3 +1,4 @@
-include CHANGES.md
 include COPYING
-include README.md
+include *.md
+include *.ini
+include *.txt
diff --git a/METADATA b/METADATA
index c81cd98..2ab4609 100644
--- a/METADATA
+++ b/METADATA
@@ -1,23 +1,20 @@
 # This project was upgraded with external_updater.
-# Usage: tools/external_updater/updater.sh update python/pyfakefs
-# For more info, check https://cs.android.com/android/platform/superproject/+/main:tools/external_updater/README.md
+# Usage: tools/external_updater/updater.sh update external/python/pyfakefs
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
 name: "pyfakefs"
 description: "pyfakefs implements a fake file system that mocks the Python file system modules. Using pyfakefs, your tests operate on a fake file system in memory without touching the real disk. The software under test requires no modification to work with pyfakefs."
 third_party {
-  url {
-    type: HOMEPAGE
-    value: "http://pyfakefs.org/"
-  }
-  url {
-    type: GIT
-    value: "https://github.com/pytest-dev/pyfakefs.git"
-  }
-  version: "979a878b12a3f625abe986a2249b677e6193ae3d"
   license_type: NOTICE
   last_upgrade_date {
-    year: 2023
-    month: 8
-    day: 25
+    year: 2025
+    month: 2
+    day: 11
+  }
+  homepage: "http://pyfakefs.org/"
+  identifier {
+    type: "Git"
+    value: "https://github.com/pytest-dev/pyfakefs.git"
+    version: "7147769ddde246390f5760d6f3034ce1c6b8f928"
   }
 }
diff --git a/OWNERS b/OWNERS
new file mode 100644
index 0000000..2e8f086
--- /dev/null
+++ b/OWNERS
@@ -0,0 +1 @@
+include platform/system/core:main:/janitors/OWNERS
diff --git a/README.md b/README.md
index cbdf11f..77867f4 100644
--- a/README.md
+++ b/README.md
@@ -55,10 +55,10 @@ provides some additional features:
   under root
 
 ## Compatibility
-pyfakefs works with CPython 3.8 and above, on Linux, Windows and macOS, and
+pyfakefs works with CPython 3.7 and above, on Linux, Windows and macOS, and
 with PyPy3.
 
-pyfakefs works with [pytest](http://doc.pytest.org) version 3.0.0 or above,
+pyfakefs works with [pytest](http://doc.pytest.org) version 6.2.5 or above,
 though a current version is recommended.
 
 pyfakefs will not work with Python libraries that use C libraries to access the
@@ -73,7 +73,7 @@ for more information about the limitations of pyfakefs.
 ### Continuous integration
 
 pyfakefs is currently automatically tested on Linux, macOS and Windows, with
-Python 3.8 to 3.12, and with PyPy3 on Linux, using
+Python 3.7 to 3.13, and with PyPy3 on Linux, using
 [GitHub Actions](https://github.com/pytest-dev/pyfakefs/actions).
 
 ### Running pyfakefs unit tests
@@ -120,7 +120,7 @@ for more information.
 pyfakefs.py was initially developed at Google by Mike Bland as a modest fake
 implementation of core Python modules.  It was introduced to all of Google
 in September 2006. Since then, it has been enhanced to extend its
-functionality and usefulness.  At last count, pyfakefs was used in over 2,000
+functionality and usefulness.  At last count, pyfakefs was used in over 20,000
 Python tests at Google.
 
 Google released pyfakefs to the public in 2011 as Google Code project
diff --git a/docs/conf.py b/docs/conf.py
index d6e0d79..6dcf4af 100644
--- a/docs/conf.py
+++ b/docs/conf.py
@@ -56,7 +56,7 @@ master_doc = "index"
 project = "pyfakefs"
 copyright = """2009 Google Inc. All Rights Reserved.
 © Copyright 2014 Altera Corporation. All Rights Reserved.
-© Copyright 2014-2023 John McGehee"""
+© Copyright 2014-2024 John McGehee"""
 author = "John McGehee"
 
 # The version info for the project you're documenting, acts as replacement for
@@ -64,9 +64,9 @@ author = "John McGehee"
 # built documents.
 #
 # The short X.Y version.
-version = "5.3"
+version = "5.8"
 # The full version, including alpha/beta/rc tags.
-release = "5.3.dev0"
+release = "5.8.dev0"
 
 # The language for content autogenerated by Sphinx. Refer to documentation
 # for a list of supported languages.
diff --git a/docs/intro.rst b/docs/intro.rst
index f022c09..9d805df 100644
--- a/docs/intro.rst
+++ b/docs/intro.rst
@@ -6,7 +6,7 @@ system that mocks the Python file system modules.
 Using pyfakefs, your tests operate on a fake file system in memory without touching the real disk.
 The software under test requires no modification to work with pyfakefs.
 
-pyfakefs works with CPython 3.8 and above, on Linux, Windows and macOS,
+pyfakefs works with CPython 3.7 and above, on Linux, Windows and macOS,
 and with PyPy3.
 
 pyfakefs works with `pytest <doc.pytest.org>`__ version 3.0.0 or above by
diff --git a/docs/modules.rst b/docs/modules.rst
index 75c96bf..55dae71 100644
--- a/docs/modules.rst
+++ b/docs/modules.rst
@@ -13,9 +13,9 @@ Fake filesystem classes
 -----------------------
 .. autoclass:: pyfakefs.fake_filesystem.FakeFilesystem
     :members: add_mount_point,
-        get_disk_usage, set_disk_usage,
+        get_disk_usage, set_disk_usage, change_disk_usage,
         add_real_directory, add_real_file, add_real_symlink, add_real_paths,
-        create_dir, create_file, create_symlink,
+        create_dir, create_file, create_symlink, create_link,
         get_object, pause, resume
 
 .. autoclass:: pyfakefs.fake_file.FakeFile
@@ -29,12 +29,12 @@ Unittest module classes
 -----------------------
 
 .. autoclass:: pyfakefs.fake_filesystem_unittest.TestCaseMixin
-    :members: fs, setUpPyfakefs, pause, resume
+    :members: fs, setUpPyfakefs, setUpClassPyfakefs, pause, resume
 
 .. autoclass:: pyfakefs.fake_filesystem_unittest.TestCase
 
 .. autoclass:: pyfakefs.fake_filesystem_unittest.Patcher
-    :members: setUp, tearDown, pause, resume
+    :members: setUp, tearDown, pause, resume, register_cleanup_handler
 
 .. automodule:: pyfakefs.fake_filesystem_unittest
     :members: patchfs
@@ -54,5 +54,3 @@ Faked module classes
 .. autoclass:: pyfakefs.fake_filesystem_shutil.FakeShutilModule
 
 .. autoclass:: pyfakefs.fake_pathlib.FakePathlibModule
-
-.. autoclass:: pyfakefs.fake_scandir.FakeScanDirModule
diff --git a/docs/troubleshooting.rst b/docs/troubleshooting.rst
index ba2b977..940c9c0 100644
--- a/docs/troubleshooting.rst
+++ b/docs/troubleshooting.rst
@@ -129,21 +129,38 @@ The test code tries to access files in the real filesystem
 ----------------------------------------------------------
 The loading of the actual Python code from the real filesystem does not use
 the filesystem functions that ``pyfakefs`` patches, but in some cases it may
-access other files in the packages. An example is loading timezone information
+access other files in the packages. An example is the ``pytz`` module, which is loading timezone information
 from configuration files. In these cases, you have to map the respective files
 or directories from the real into the fake filesystem as described in
-:ref:`real_fs_access`.
+:ref:`real_fs_access`. For the timezone example, this could look like the following::
+
+.. code:: python
+
+    from pathlib import Path
+    import pytz
+    from pyfakefs.fake_filesystem_unittest import TestCase
+
+
+    class ExampleTestCase(TestCase):
+        def setUp(self):
+            self.setUpPyfakefs()
+            info_dir = Path(pytz.__file__).parent / "zoneinfo"
+            self.fs.add_real_directory(info_dir)
+
+.. note:: In newer django versions, `tzdata` is used instead of `pytz`, but the usage will be the same.
 
 If you are using Django, various dependencies may expect both the project
 directory and the ``site-packages`` installation to exist in the fake filesystem.
 
-Here's an example of how to add these using pytest::
+Here's an example of how to add these using pytest:
 
+.. code:: python
 
     import os
     import django
     import pytest
 
+
     @pytest.fixture
     def fake_fs(fs):
         PROJECT_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
@@ -162,8 +179,7 @@ As ``pyfakefs`` does not fake the ``tempfile`` module (as described above),
 a temporary directory is required to ensure that ``tempfile`` works correctly,
 e.g., that ``tempfile.gettempdir()`` will return a valid value. This
 means that any newly created fake file system will always have either a
-directory named ``/tmp`` when running on Linux or Unix systems,
-``/var/folders/<hash>/T`` when running on macOS, or
+directory named ``/tmp`` when running on POSIX systems, or
 ``C:\Users\<user>\AppData\Local\Temp`` on Windows:
 
 .. code:: python
@@ -175,11 +191,13 @@ directory named ``/tmp`` when running on Linux or Unix systems,
       # the temp directory is always present at test start
       assert len(os.listdir("/")) == 1
 
-Under macOS and linux, if the actual temp path is not `/tmp` (which is always the case
-under macOS), a symlink to the actual temp directory is additionally created as `/tmp`
-in the fake filesystem. Note that the file size of this link is ignored while
+Under macOS and linux, if the actual temp path is not `/tmp` (which will be the case if an environment variable
+`TEMPDIR`, `TEMP` or `TMP` points to another path), a symlink to the actual temp directory is additionally created
+as `/tmp` in the fake filesystem. Note that the file size of this link is ignored while
 calculating the fake filesystem size, so that the used size with an otherwise empty
 fake filesystem can always be assumed to be 0.
+Note also that the temp directory may not be what you expect, if you emulate another file system. For example,
+if you emulate Windows under Linux, the default temp directory will be at `C:\\tmp`.
 
 
 User rights
@@ -205,6 +223,9 @@ is the convenience argument :ref:`allow_root_user`:
       def setUp(self):
           self.setUpPyfakefs(allow_root_user=False)
 
+``Pyfakefs`` also handles file permissions under UNIX systems while accessing files.
+If accessing files as another user and/or group, the respective group/other file
+permissions are considered.
 
 .. _usage_with_mock_open:
 
@@ -233,6 +254,150 @@ passed before the ``mocker`` fixture to ensure this:
       # works correctly
       mocker.patch("builtins.open", mocker.mock_open(read_data="content"))
 
+Pathlib.Path objects created outside of tests
+---------------------------------------------
+An pattern which is more often seen with the increased usage of ``pathlib`` is the
+creation of global ``pathlib.Path`` objects (instead of string paths) that are imported
+into the tests. As these objects are created in the real filesystem,
+they do not have the same attributes as fake ``pathlib.Path`` objects,
+and both will always compare as not equal,
+regardless of the path they point to:
+
+.. code:: python
+
+  import pathlib
+
+  # This Path was made in the real filesystem, before the test
+  # stands up the fake filesystem
+  FILE_PATH = pathlib.Path(__file__).parent / "file.csv"
+
+
+  def test_path_equality(fs):
+      # This Path was made after the fake filesystem is set up,
+      # and thus patching within pathlib is in effect
+      fake_file_path = pathlib.Path(str(FILE_PATH))
+
+      assert FILE_PATH == fake_file_path  # fails, compares different objects
+      assert str(FILE_PATH) == str(fake_file_path)  # succeeds, compares the actual paths
+
+Generally, mixing objects in the real filesystem and the fake filesystem
+is problematic and better avoided.
+
+.. note:: This problem only happens in Python versions up to 3.10. In Python 3.11,
+  `pathlib` has been restructured so that a pathlib path no longer contains a reference
+  to the original filesystem accessor, and it can safely be used in the fake filesystem.
+
+.. _nested_patcher_invocation:
+
+Nested file system fixtures and Patcher invocations
+---------------------------------------------------
+``pyfakefs`` does not support nested faked file systems. Instead, it uses reference counting
+on the single fake filesystem instance. That means, if you are trying to create a fake filesystem
+inside a fake filesystem, only the reference count will increase, and any arguments you may pass
+to the patcher or fixture are ignored. Likewise, if you leave a nested fake filesystem,
+only the reference count is decreased and nothing is reverted.
+
+There are some situations where that may happen, probably without you noticing:
+
+* If you use the module- or session based variants of the ``fs`` fixture (e.g. ``fs_module`` or
+  ``fs_session``), you may still use the ``fs`` fixture in single tests. This will practically
+  reference the module- or session based fake filesystem, instead of creating a new one.
+
+.. code:: python
+
+  @pytest.fixture(scope="module", autouse=True)
+  def use_fs(fs_module):
+      # do some setup...
+      yield fs_module
+
+
+  def test_something(fs):
+      do_more_fs_setup()
+      test_something()
+      # the fs setup done in this test is not reverted!
+
+* If you invoke a ``Patcher`` instance inside a test with the ``fs`` fixture (or with an active
+  ``fs_module`` or ``fs_session`` fixture), this will be ignored. For example:
+
+.. code:: python
+
+  def test_something(fs):
+      with Patcher(allow_root_user=False):
+          # root user is still allowed
+          do_stuff()
+
+* The same is true, if you use ``setUpPyfakefs`` or ``setUpClassPyfakefs`` in a unittest context, or if you use
+  the ``patchfs`` decorator. ``Patcher`` instances created in the tests will be ignored likewise.
+
+.. _failing_dyn_patcher:
+
+Tests failing after a test using pyfakefs
+-----------------------------------------
+If previously passing tests fail after a test using ``pyfakefs``, something may be wrong with reverting the
+patches. The most likely cause is a problem with the dynamic patcher, which is invoked if modules are loaded
+dynamically during the tests. These modules are removed after the test, and reloaded the next time they are
+imported, to avoid any remaining patched functions or variables. Sometimes, there is a problem with that reload.
+
+If you want to know if your problem is indeed with the dynamic patcher, you can switch it off by setting
+:ref:`use_dynamic_patch` to `False` (here an example with pytest):
+
+.. code:: python
+
+  @pytest.fixture
+  def fs_no_dyn_patch():
+      with Patcher(use_dynamic_patch=False):
+          yield
+
+
+  def test_something(fs_no_dyn_patch):
+      assert foo()  # do the testing
+
+If in this case the following tests pass as expected, the dynamic patcher is indeed the problem.
+If your ``pyfakefs`` test also works with that setting, you may just use this. Otherwise,
+the dynamic patcher is needed, and the concrete problem has to be fixed. There is the possibility
+to add a hook for the cleanup of a specific module, which allows to change the process of unloading
+the module. This is currently used in ``pyfakefs`` for two cases: to reload ``django`` views instead of
+just unloading them (needed due to some django internals), and for the reload of a specific module
+in ``pandas``, which does not work out of the box.
+
+A cleanup handler takes the module name as an argument, and returns a Boolean that indicates if the
+cleanup was handled (by returning `True`), or if the module should still be unloaded. This handler has to
+be added to the patcher:
+
+.. code:: python
+
+  def handler_no_cleanup(_name):
+      # This is the simplest case: no cleanup is done at all.
+      # This makes only sense if you are sure that no file system functions are called.
+      return True
+
+
+  @pytest.fixture
+  def my_fs():
+      with Patcher() as patcher:
+          patcher.cleanup_handlers["modulename"] = handler_no_cleanup
+          yield patcher.fs
+
+
+A specific problem are modules that use filesystem functions and are imported by other modules locally
+(e.g. inside a function). These kinds of modules are not correctly reset and need to be reloaded manually.
+For this case, the cleanup handler `reload_cleanup_handler` in `pyfakefs.helpers` can be used:
+
+.. code:: python
+
+  from pyfakefs.helpers import reload_cleanup_handler
+
+
+  @pytest.fixture
+  def my_fs():
+      with Patcher() as patcher:
+          patcher.cleanup_handlers["modulename"] = reload_cleanup_handler
+          yield patcher.fs
+
+As this may not be trivial, we recommend to write an issue in ``pyfakefs`` with a reproducible example.
+We will analyze the problem, and if we find a solution we will either get this fixed in ``pyfakefs``
+(if it is related to a commonly used module), or help you to resolve it.
+
 
 .. _`multiprocessing`: https://docs.python.org/3/library/multiprocessing.html
 .. _`subprocess`: https://docs.python.org/3/library/subprocess.html
diff --git a/docs/usage.rst b/docs/usage.rst
index f90377f..6c1f31d 100644
--- a/docs/usage.rst
+++ b/docs/usage.rst
@@ -17,19 +17,23 @@ Here is an example for a simple test:
 
 .. code:: python
 
-   def my_fakefs_test(fs):
+   import os
+
+
+   def test_fakefs(fs):
        # "fs" is the reference to the fake file system
        fs.create_file("/var/data/xx1.txt")
        assert os.path.exists("/var/data/xx1.txt")
 
 If you are bothered by the ``pylint`` warning,
-``C0103: Argument name "fs" doesn't conform to snake_case naming style
-(invalid-name)``,
-you can define a longer name in your ``conftest.py`` and use that in your
-tests:
+``C0103: Argument name "fs" doesn't conform to snake_case naming style (invalid-name)``,
+you can define a longer name in your ``conftest.py`` and use that in your tests:
 
 .. code:: python
 
+    import pytest
+
+
     @pytest.fixture
     def fake_filesystem(fs):  # pylint:disable=invalid-name
         """Variable name 'fs' causes a pylint warning. Provide a longer name
@@ -47,7 +51,7 @@ respectively.
   not setup / tear down the fake filesystem in the current scope; instead, it
   will just serve as a reference to the active fake filesystem. That means that changes
   done in the fake filesystem inside a test will remain there until the respective scope
-  ends.
+  ends (see also :ref:`nested_patcher_invocation`).
 
 Patch using fake_filesystem_unittest
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
@@ -60,6 +64,7 @@ with the fake file system functions and modules:
 
 .. code:: python
 
+    import os
     from pyfakefs.fake_filesystem_unittest import TestCase
 
 
@@ -81,6 +86,8 @@ method ``setUpClassPyfakefs`` instead:
 
 .. code:: python
 
+    import os
+    import pathlib
     from pyfakefs.fake_filesystem_unittest import TestCase
 
 
@@ -89,7 +96,9 @@ method ``setUpClassPyfakefs`` instead:
         def setUpClass(cls):
             cls.setUpClassPyfakefs()
             # setup the fake filesystem using standard functions
-            pathlib.Path("/test/file1.txt").touch()
+            path = pathlib.Path("/test")
+            path.mkdir()
+            (path / "file1.txt").touch()
             # you can also access the fake fs via fake_fs() if needed
             cls.fake_fs().create_file("/test/file2.txt", contents="test")
 
@@ -105,7 +114,8 @@ method ``setUpClassPyfakefs`` instead:
             self.assertTrue(os.path.exists(file_path))
 
 .. note:: This feature cannot be used with a Python version before Python 3.8 due to
-  a missing feature in ``unittest``.
+  a missing feature in ``unittest``. If you use ``pytest`` for running tests using this feature,
+  you need to have at least ``pytest`` version 6.2 due to an issue in earlier versions.
 
 .. caution:: If this is used, any changes made in the fake filesystem inside a test
   will remain there for all following tests in the test class, if they are not reverted
@@ -170,13 +180,13 @@ order, as shown here:
    @patchfs
    @mock.patch("foo.bar")
    def test_something(fake_fs, mocked_bar):
-       ...
+       assert foo()
 
 
    @mock.patch("foo.bar")
    @patchfs
    def test_something(mocked_bar, fake_fs):
-       ...
+       assert foo()
 
 .. note::
   Avoid writing the ``patchfs`` decorator *between* ``mock.patch`` operators,
@@ -247,7 +257,7 @@ In case of ``pytest``, you have two possibilities:
 
 
   def test_something(fs_no_root):
-      ...
+      assert foo()
 
 - You can also pass the arguments using ``@pytest.mark.parametrize``. Note that
   you have to provide `all Patcher arguments`_ before the needed ones, as
@@ -262,7 +272,7 @@ In case of ``pytest``, you have two possibilities:
 
   @pytest.mark.parametrize("fs", [[None, None, None, False]], indirect=True)
   def test_something(fs):
-      ...
+      assert foo()
 
 Unittest
 ........
@@ -280,7 +290,7 @@ instance:
           self.setUpPyfakefs(allow_root_user=False)
 
       def testSomething(self):
-          ...
+          assert foo()
 
 patchfs
 .......
@@ -294,7 +304,7 @@ the decorator:
 
   @patchfs(allow_root_user=False)
   def test_something(fake_fs):
-      ...
+      assert foo()
 
 
 List of custom arguments
@@ -380,6 +390,7 @@ an example from a related issue):
 .. code:: python
 
   import pathlib
+  import click
 
 
   @click.command()
@@ -395,12 +406,13 @@ dynamically. All modules loaded after the initial patching described above
 will be patched using this second mechanism.
 
 Given that the example function ``check_if_exists`` shown above is located in
-the file ``example/sut.py``, the following code will work:
+the file ``example/sut.py``, the following code will work (imports are omitted):
 
 .. code:: python
 
   import example
 
+
   # example using unittest
   class ReloadModuleTest(fake_filesystem_unittest.TestCase):
       def setUp(self):
@@ -456,6 +468,9 @@ has now been been integrated into ``pyfakefs``):
 
 .. code:: python
 
+  import django
+
+
   class FakeLocks:
       """django.core.files.locks uses low level OS functions, fake it."""
 
@@ -485,13 +500,14 @@ has now been been integrated into ``pyfakefs``):
   with Patcher(modules_to_patch={"django.core.files.locks": FakeLocks}):
       test_django_stuff()
 
+
   # test code using unittest
   class TestUsingDjango(fake_filesystem_unittest.TestCase):
       def setUp(self):
           self.setUpPyfakefs(modules_to_patch={"django.core.files.locks": FakeLocks})
 
       def test_django_stuff(self):
-          ...
+          assert foo()
 
 
   # test code using pytest
@@ -499,13 +515,13 @@ has now been been integrated into ``pyfakefs``):
       "fs", [[None, None, {"django.core.files.locks": FakeLocks}]], indirect=True
   )
   def test_django_stuff(fs):
-      ...
+      assert foo()
 
 
   # test code using patchfs decorator
   @patchfs(modules_to_patch={"django.core.files.locks": FakeLocks})
   def test_django_stuff(fake_fs):
-      ...
+      assert foo()
 
 additional_skip_names
 .....................
@@ -525,6 +541,7 @@ Alternatively to the module names, the modules themselves may be used:
 .. code:: python
 
   import pydevd
+  from pyfakefs.fake_filesystem_unittest import Patcher
 
   with Patcher(additional_skip_names=[pydevd]) as patcher:
       patcher.fs.create_file("foo")
@@ -547,8 +564,7 @@ these libraries so that they will work with the fake filesystem. Currently, this
 includes patches for ``pandas`` read methods like ``read_csv`` and
 ``read_excel``, and for ``Django`` file locks--more may follow. Ordinarily,
 the default value of ``use_known_patches`` should be used, but it is present
-to allow users to disable this patching in case it causes any problems. It
-may be removed or replaced by more fine-grained arguments in future releases.
+to allow users to disable this patching in case it causes any problems.
 
 patch_open_code
 ...............
@@ -569,10 +585,21 @@ set ``patch_open_code`` to ``PatchMode.AUTO``:
 
   @patchfs(patch_open_code=PatchMode.AUTO)
   def test_something(fs):
-      ...
+      assert foo()
+
+In this mode, it is also possible to import modules created in the fake filesystem
+using `importlib.import_module`. Make sure that the `sys.path` contains the parent path in this case:
+
+.. code:: python
+
+  @patchfs(patch_open_code=PatchMode.AUTO)
+  def test_fake_import(fs):
+      fake_module_path = Path("/") / "site-packages" / "fake_module.py"
+      self.fs.create_file(fake_module_path, contents="x = 5")
+      sys.path.insert(0, str(fake_module_path.parent))
+      module = importlib.import_module("fake_module")
+      assert module.x == 5
 
-.. note:: This argument is subject to change or removal in future
-  versions of ``pyfakefs``, depending on the upcoming use cases.
 
 .. _patch_default_args:
 
@@ -595,7 +622,7 @@ search for this kind of default arguments and patch them automatically.
 You could also use the :ref:`modules_to_reload` option with the module that
 contains the default argument instead, if you want to avoid the overhead.
 
-.. note:: There are some cases where this option dees not work:
+.. note:: There are some cases where this option does *not* work:
 
   - if default arguments are *computed* using file system functions:
 
@@ -660,23 +687,35 @@ If you want to clear the cache just for a specific test instead, you can call
       fs.clear_cache()
       ...
 
+.. _use_dynamic_patch:
+
+use_dynamic_patch
+~~~~~~~~~~~~~~~~~
+If ``True`` (the default), dynamic patching after setup is used (for example
+for modules loaded locally inside of functions).
+Can be switched off if it causes unwanted side effects, though that would mean that
+dynamically loaded modules are no longer patched, if they use file system functions.
+See also :ref:`failing_dyn_patcher` in the troubleshooting guide for more information.
+
 
 .. _convenience_methods:
 
 Using convenience methods
 -------------------------
 While ``pyfakefs`` can be used just with the standard Python file system
-functions, there are few convenience methods in ``fake_filesystem`` that can
+functions, there are a few convenience methods in ``fake_filesystem`` that can
 help you setting up your tests. The methods can be accessed via the
 ``fake_filesystem`` instance in your tests: ``Patcher.fs``, the ``fs``
-fixture in pytest, ``TestCase.fs`` for ``unittest``, and the ``fs`` argument
+fixture in pytest, ``TestCase.fs`` for ``unittest``, and the positional argument
 for the ``patchfs`` decorator.
 
 File creation helpers
 ~~~~~~~~~~~~~~~~~~~~~
 To create files, directories or symlinks together with all the directories
-in the path, you may use ``create_file()``, ``create_dir()``,
-``create_symlink()`` and ``create_link()``, respectively.
+in the path, you may use :py:meth:`create_file()<pyfakefs.fake_filesystem.FakeFilesystem.create_file>`,
+:py:meth:`create_dir()<pyfakefs.fake_filesystem.FakeFilesystem.create_dir>`,
+:py:meth:`create_symlink()<pyfakefs.fake_filesystem.FakeFilesystem.create_symlink>` and
+:py:meth:`create_link()<pyfakefs.fake_filesystem.FakeFilesystem.create_link>`, respectively.
 
 ``create_file()`` also allows you to set the file mode and the file contents
 together with the encoding if needed. Alternatively, you can define a file
@@ -713,8 +752,10 @@ automatically.
 Access to files in the real file system
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 If you want to have read access to real files or directories, you can map
-them into the fake file system using ``add_real_file()``,
-``add_real_directory()``, ``add_real_symlink()`` and ``add_real_paths()``.
+them into the fake file system using :py:meth:`add_real_file()<pyfakefs.fake_filesystem.FakeFilesystem.add_real_file>`,
+:py:meth:`add_real_directory()<pyfakefs.fake_filesystem.FakeFilesystem.add_real_directory>`,
+:py:meth:`add_real_symlink()<pyfakefs.fake_filesystem.FakeFilesystem.add_real_symlink>` and
+:py:meth:`add_real_paths()<pyfakefs.fake_filesystem.FakeFilesystem.add_real_paths>`.
 They take a file path, a directory path, a symlink path, or a list of paths,
 respectively, and make them accessible from the fake file system. By
 default, the contents of the mapped files and directories are read only on
@@ -725,10 +766,13 @@ files are never changed.
 
 ``add_real_file()``, ``add_real_directory()`` and ``add_real_symlink()`` also
 allow you to map a file or a directory tree into another location in the
-fake filesystem via the argument ``target_path``.
+fake filesystem via the argument ``target_path``. If the target directory already exists
+in the fake filesystem, the directory contents are merged. If a file in the fake filesystem
+would be overwritten by a file from the real filesystem, an exception is raised.
 
 .. code:: python
 
+    import os
     from pyfakefs.fake_filesystem_unittest import TestCase
 
 
@@ -800,7 +844,7 @@ Handling mount points
 ~~~~~~~~~~~~~~~~~~~~~
 Under Linux and macOS, the root path (``/``) is the only mount point created
 in the fake file system. If you need support for more mount points, you can add
-them using ``add_mount_point()``.
+them using :py:meth:`add_mount_point()<pyfakefs.fake_filesystem.FakeFilesystem.add_mount_point>`.
 
 Under Windows, drives and UNC paths are internally handled as mount points.
 Adding a file or directory on another drive or UNC path automatically
@@ -818,7 +862,7 @@ Setting the file system size
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 If you need to know the file system size in your tests (for example for
 testing cleanup scripts), you can set the fake file system size using
-``set_disk_usage()``. By default, this sets the total size in bytes of the
+:py:meth:`set_disk_usage()<pyfakefs.fake_filesystem.FakeFilesystem.set_disk_usage>`. By default, this sets the total size in bytes of the
 root partition; if you add a path as parameter, the size will be related to
 the mount point (see above) the path is related to.
 
@@ -829,6 +873,8 @@ and you may fail to create new files if the fake file system is full.
 
 .. code:: python
 
+    import errno
+    import os
     from pyfakefs.fake_filesystem_unittest import TestCase
 
 
@@ -838,12 +884,13 @@ and you may fail to create new files if the fake file system is full.
             self.fs.set_disk_usage(100)
 
         def test_disk_full(self):
-            with open("/foo/bar.txt", "w") as f:
-                with self.assertRaises(OSError):
+            os.mkdir("/foo")
+            with self.assertRaises(OSError) as e:
+                with open("/foo/bar.txt", "w") as f:
                     f.write("a" * 200)
-                    f.flush()
+            self.assertEqual(errno.ENOSPC, e.exception.errno)
 
-To get the file system size, you may use ``get_disk_usage()``, which is
+To get the file system size, you may use :py:meth:`get_disk_usage()<pyfakefs.fake_filesystem.FakeFilesystem.get_disk_usage>`, which is
 modeled after ``shutil.disk_usage()``.
 
 Suspending patching
@@ -859,6 +906,8 @@ Here is an example that tests the usage with the ``pyfakefs`` pytest fixture:
 
 .. code:: python
 
+    import os
+    import tempfile
     from pyfakefs.fake_filesystem_unittest import Pause
 
 
@@ -877,6 +926,8 @@ Here is the same code using a context manager:
 
 .. code:: python
 
+    import os
+    import tempfile
     from pyfakefs.fake_filesystem_unittest import Pause
 
 
@@ -920,6 +971,7 @@ The following test works both under Windows and Linux:
 
 .. code:: python
 
+  import os
   from pyfakefs.fake_filesystem import OSType
 
 
@@ -929,6 +981,10 @@ The following test works both under Windows and Linux:
       assert os.path.splitdrive(r"C:\foo\bar") == ("C:", r"\foo\bar")
       assert os.path.ismount("C:")
 
+.. note:: Only behavior not relying on OS-specific functionality is emulated on another system.
+  For example, if you use the Linux-specific functionality of extended attributes (``os.getxattr`` etc.)
+  in your code, you have to test this under Linux.
+
 Set file as inaccessible under Windows
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 Normally, if you try to set a file or directory as inaccessible using ``chmod`` under
@@ -940,12 +996,17 @@ possibility to use the ``force_unix_mode`` argument to ``FakeFilesystem.chmod``:
 
 .. code:: python
 
+    import pathlib
+    import pytest
+    from pyfakefs.fake_filesystem import OSType
+
+
     def test_is_file_for_unreadable_dir_windows(fs):
         fs.os = OSType.WINDOWS
         path = pathlib.Path("/foo/bar")
         fs.create_file(path)
         # normal chmod does not really set the mode to 0
-        self.fs.chmod("/foo", 0o000)
+        fs.chmod("/foo", 0o000)
         assert path.is_file()
         # but it does in forced UNIX mode
         fs.chmod("/foo", 0o000, force_unix_mode=True)
diff --git a/extra_requirements.txt b/extra_requirements.txt
index 6c69b9c..d19e84a 100644
--- a/extra_requirements.txt
+++ b/extra_requirements.txt
@@ -1,19 +1,9 @@
-# "pathlib2" and "scandir" are backports of new standard modules,  pyfakefs will
-# use them if available when running on older Python versions.
-#
-# They are dependencies of pytest when Python < 3.6 so we sometimes get them via
-# requirements.txt, this file makes them explicit dependencies for testing &
-# development.
-#
-# Older versions might work ok, the versions chosen here are just the latest
-# available at the time of writing.
-pathlib2>=2.3.2
-scandir>=1.8
-
-# pandas + xlrd are used to test pandas-specific patches to allow
+# these are used to test pandas-specific patches to allow
 # pyfakefs to work with pandas
 # we use the latest version to see any problems with new versions
 pandas==1.3.5; python_version == '3.7' # pyup: ignore
-pandas==2.0.3; python_version > '3.7'
+pandas==2.0.3; python_version == '3.8' # pyup: ignore
+pandas==2.2.3; python_version > '3.8'
 xlrd==2.0.1
-openpyxl==3.1.2
+openpyxl==3.1.3; python_version == '3.7' # pyup: ignore
+openpyxl==3.1.5; python_version > '3.7'
diff --git a/legacy_requirements.txt b/legacy_requirements.txt
new file mode 100644
index 0000000..2f75c6e
--- /dev/null
+++ b/legacy_requirements.txt
@@ -0,0 +1,8 @@
+# "pathlib2" and "scandir" are backports of new standard modules,  pyfakefs will
+# patch them if available when running on older Python versions.
+#
+# The modules are no longer for all required Python version, and only used for CI tests.
+# Note that the usage of these modules is deprecated, and their support
+# will be removed in pyfakefs 6.0
+pathlib2>=2.3.2
+scandir>=1.8; python_version < '3.13'  # not (yet) available for Python 3.13
diff --git a/pyfakefs/_version.py b/pyfakefs/_version.py
index bdb37fc..498f76d 100644
--- a/pyfakefs/_version.py
+++ b/pyfakefs/_version.py
@@ -1 +1 @@
-__version__ = "5.3.dev0"
+__version__ = "5.8.dev0"
diff --git a/pyfakefs/fake_file.py b/pyfakefs/fake_file.py
index 5bc3119..d43eb6d 100644
--- a/pyfakefs/fake_file.py
+++ b/pyfakefs/fake_file.py
@@ -12,13 +12,13 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
-"""Fake implementations for different file objects.
-"""
+"""Fake implementations for different file objects."""
+
 import errno
 import io
-import locale
 import os
 import sys
+import traceback
 from stat import (
     S_IFREG,
     S_IFDIR,
@@ -52,11 +52,18 @@ from pyfakefs.helpers import (
     real_encoding,
     AnyPath,
     AnyString,
+    get_locale_encoding,
+    _OpenModes,
+    is_root,
 )
 
 if TYPE_CHECKING:
     from pyfakefs.fake_filesystem import FakeFilesystem
 
+
+# Work around pyupgrade auto-rewriting `io.open()` to `open()`.
+io_open = io.open
+
 AnyFileWrapper = Union[
     "FakeFileWrapper",
     "FakeDirWrapper",
@@ -72,7 +79,7 @@ class FakeLargeFileIoException(Exception):
     """
 
     def __init__(self, file_path: str) -> None:
-        super(FakeLargeFileIoException, self).__init__(
+        super().__init__(
             "Read and write operations not supported for "
             "fake large file: %s" % file_path
         )
@@ -133,6 +140,7 @@ class FakeFile:
         encoding: Optional[str] = None,
         errors: Optional[str] = None,
         side_effect: Optional[Callable[["FakeFile"], None]] = None,
+        open_modes: Optional[_OpenModes] = None,
     ):
         """
         Args:
@@ -151,6 +159,7 @@ class FakeFile:
             errors: The error mode used for encoding/decoding errors.
             side_effect: function handle that is executed when file is written,
                 must accept the file object as an argument.
+            open_modes: The modes the file was opened with (e.g. can read, write etc.)
         """
         # to be backwards compatible regarding argument order, we raise on None
         if filesystem is None:
@@ -179,6 +188,7 @@ class FakeFile:
         # Linux specific: extended file system attributes
         self.xattr: Dict = {}
         self.opened_as: AnyString = ""
+        self.open_modes = open_modes
 
     @property
     def byte_contents(self) -> Optional[bytes]:
@@ -190,7 +200,7 @@ class FakeFile:
         """Return the contents as string with the original encoding."""
         if isinstance(self.byte_contents, bytes):
             return self.byte_contents.decode(
-                self.encoding or locale.getpreferredencoding(False),
+                self.encoding or get_locale_encoding(),
                 errors=self.errors,
             )
         return None
@@ -263,7 +273,7 @@ class FakeFile:
         if is_unicode_string(contents):
             contents = bytes(
                 cast(str, contents),
-                self.encoding or locale.getpreferredencoding(False),
+                self.encoding or get_locale_encoding(),
                 self.errors,
             )
         return cast(bytes, contents)
@@ -350,7 +360,7 @@ class FakeFile:
         self.epoch += 1
 
     @property
-    def path(self) -> AnyStr:
+    def path(self) -> AnyStr:  # type: ignore[type-var]
         """Return the full path of the current object."""
         names: List[AnyStr] = []  # pytype: disable=invalid-annotation
         obj: Optional[FakeFile] = self
@@ -389,13 +399,27 @@ class FakeFile:
         return super().__setattr__(key, value)
 
     def __str__(self) -> str:
-        return "%r(%o)" % (self.name, self.st_mode)
+        return f"{self.name!r}({self.st_mode:o})"
+
+    def has_permission(self, permission_bits: int) -> bool:
+        """Checks if the given permissions are set in the fake file.
+
+        Args:
+            permission_bits: The permission bits as set for the user.
+
+        Returns:
+            True if the permissions are set in the correct class (user/group/other).
+        """
+        if helpers.get_uid() == self.stat_result.st_uid:
+            return self.st_mode & permission_bits == permission_bits
+        if helpers.get_gid() == self.stat_result.st_gid:
+            return self.st_mode & (permission_bits >> 3) == permission_bits >> 3
+        return self.st_mode & (permission_bits >> 6) == permission_bits >> 6
 
 
 class FakeNullFile(FakeFile):
     def __init__(self, filesystem: "FakeFilesystem") -> None:
-        devnull = "nul" if filesystem.is_windows_fs else "/dev/null"
-        super(FakeNullFile, self).__init__(devnull, filesystem=filesystem, contents="")
+        super().__init__(filesystem.devnull, filesystem=filesystem, contents="")
 
     @property
     def byte_contents(self) -> bytes:
@@ -437,7 +461,7 @@ class FakeFileFromRealFile(FakeFile):
     def byte_contents(self) -> Optional[bytes]:
         if not self.contents_read:
             self.contents_read = True
-            with io.open(self.file_path, "rb") as f:
+            with io_open(self.file_path, "rb") as f:
                 self._byte_contents = f.read()
         # On MacOS and BSD, the above io.open() updates atime on the real file
         self.st_atime = os.stat(self.file_path).st_atime
@@ -445,7 +469,7 @@ class FakeFileFromRealFile(FakeFile):
 
     def set_contents(self, contents, encoding=None):
         self.contents_read = True
-        super(FakeFileFromRealFile, self).set_contents(contents, encoding)
+        super().set_contents(contents, encoding)
 
     def is_large_file(self):
         """The contents are never faked."""
@@ -504,8 +528,8 @@ class FakeDirectory(FakeFile):
         """
         if (
             not helpers.is_root()
-            and not self.st_mode & helpers.PERM_WRITE
             and not self.filesystem.is_windows_fs
+            and not self.has_permission(helpers.PERM_WRITE)
         ):
             raise OSError(errno.EACCES, "Permission Denied", self.path)
 
@@ -567,14 +591,30 @@ class FakeDirectory(FakeFile):
         pathname_name = self._normalized_entryname(pathname_name)
         entry = self.get_entry(pathname_name)
         if self.filesystem.is_windows_fs:
-            if entry.st_mode & helpers.PERM_WRITE == 0:
+            if not is_root() and entry.st_mode & helpers.PERM_WRITE == 0:
                 self.filesystem.raise_os_error(errno.EACCES, pathname_name)
             if self.filesystem.has_open_file(entry):
-                self.filesystem.raise_os_error(errno.EACCES, pathname_name)
+                raise_error = True
+                if os.name == "posix" and not hasattr(os, "O_TMPFILE"):
+                    # special handling for emulating Windows under macOS and PyPi
+                    # tempfile uses unlink based on the real OS while deleting
+                    # a temporary file, so we ignore that error in this specific case
+                    st = traceback.extract_stack(limit=6)
+                    if sys.version_info < (3, 10):
+                        if (
+                            st[0].name == "TemporaryFile"
+                            and st[0].line == "_os.unlink(name)"
+                        ):
+                            raise_error = False
+                    else:
+                        # TemporaryFile implementation has changed in Python 3.10
+                        if st[0].name == "opener" and st[0].line == "_os.unlink(name)":
+                            raise_error = False
+                if raise_error:
+                    self.filesystem.raise_os_error(errno.EACCES, pathname_name)
         else:
-            if not helpers.is_root() and (
-                self.st_mode & (helpers.PERM_WRITE | helpers.PERM_EXE)
-                != helpers.PERM_WRITE | helpers.PERM_EXE
+            if not helpers.is_root() and not self.has_permission(
+                helpers.PERM_WRITE | helpers.PERM_EXE
             ):
                 self.filesystem.raise_os_error(errno.EACCES, pathname_name)
 
@@ -613,7 +653,7 @@ class FakeDirectory(FakeFile):
         return False
 
     def __str__(self) -> str:
-        description = super(FakeDirectory, self).__str__() + ":\n"
+        description = super().__str__() + ":\n"
         for item in self.entries:
             item_desc = self.entries[item].__str__()
             for line in item_desc.split("\n"):
@@ -651,7 +691,7 @@ class FakeDirectoryFromRealDirectory(FakeDirectory):
         """
         target_path = target_path or source_path
         real_stat = os.stat(source_path)
-        super(FakeDirectoryFromRealDirectory, self).__init__(
+        super().__init__(
             name=to_string(os.path.split(target_path)[1]),
             perm_bits=real_stat.st_mode,
             filesystem=filesystem,
@@ -693,7 +733,7 @@ class FakeDirectoryFromRealDirectory(FakeDirectory):
         # we cannot get the size until the contents are loaded
         if not self.contents_read:
             return 0
-        return super(FakeDirectoryFromRealDirectory, self).size
+        return super().size
 
     @size.setter
     def size(self, st_size: int) -> None:
@@ -723,6 +763,7 @@ class FakeFileWrapper:
         errors: Optional[str],
         buffering: int,
         raw_io: bool,
+        opened_as_fd: bool,
         is_stream: bool = False,
     ):
         self.file_object = file_object
@@ -734,6 +775,7 @@ class FakeFileWrapper:
         self._file_epoch = file_object.epoch
         self.raw_io = raw_io
         self._binary = binary
+        self.opened_as_fd = opened_as_fd
         self.is_stream = is_stream
         self._changed = False
         self._buffer_size = buffering
@@ -745,7 +787,7 @@ class FakeFileWrapper:
         self._use_line_buffer = not binary and buffering == 1
 
         contents = file_object.byte_contents
-        self._encoding = encoding or locale.getpreferredencoding(False)
+        self._encoding = encoding or get_locale_encoding()
         errors = errors or "strict"
         self._io: Union[BinaryBufferIO, TextBufferIO] = (
             BinaryBufferIO(contents)
@@ -807,21 +849,35 @@ class FakeFileWrapper:
 
     def close(self) -> None:
         """Close the file."""
+        self.close_fd(self.filedes)
+
+    def close_fd(self, fd: Optional[int]) -> None:
+        """Close the file for the given file descriptor."""
+
         # ignore closing a closed file
         if not self._is_open():
             return
 
         # for raw io, all writes are flushed immediately
-        if self.allow_update and not self.raw_io:
-            self.flush()
+        if not self.raw_io:
+            try:
+                self.flush()
+            except OSError as e:
+                if e.errno == errno.EBADF:
+                    # if we get here, we have an open file descriptor
+                    # without write permission, which has to be closed
+                    assert self.filedes
+                    self._filesystem.close_open_file(self.filedes)
+                raise
+
             if self._filesystem.is_windows_fs and self._changed:
                 self.file_object.st_mtime = helpers.now()
 
-        assert self.filedes is not None
+        assert fd is not None
         if self._closefd:
-            self._filesystem._close_open_file(self.filedes)
+            self._filesystem.close_open_file(fd)
         else:
-            open_files = self._filesystem.open_files[self.filedes]
+            open_files = self._filesystem.open_files[fd]
             assert open_files is not None
             open_files.remove(self)
         if self.delete_on_close:
@@ -848,8 +904,12 @@ class FakeFileWrapper:
 
     def flush(self) -> None:
         """Flush file contents to 'disk'."""
+        if self.is_stream:
+            return
+
         self._check_open_file()
-        if self.allow_update and not self.is_stream:
+
+        if self.allow_update:
             contents = self._io.getvalue()
             if self._append:
                 self._sync_io()
@@ -869,9 +929,15 @@ class FakeFileWrapper:
                     self.file_object.st_ctime = current_time
                     self.file_object.st_mtime = current_time
             self._file_epoch = self.file_object.epoch
-
-            if not self.is_stream:
-                self._flush_related_files()
+            self._flush_related_files()
+        else:
+            buf_length = len(self._io.getvalue())
+            content_length = 0
+            if self.file_object.byte_contents is not None:
+                content_length = len(self.file_object.byte_contents)
+            # an error is only raised if there is something to flush
+            if content_length != buf_length:
+                self._filesystem.raise_os_error(errno.EBADF)
 
     def update_flush_pos(self) -> None:
         self._flush_pos = self._io.tell()
@@ -1114,7 +1180,7 @@ class FakeFileWrapper:
             self._check_open_file()
         if not self._read and reading:
             return self._read_error()
-        if not self.allow_update and writing:
+        if not self.opened_as_fd and not self.allow_update and writing:
             return self._write_error()
 
         if reading:
@@ -1196,12 +1262,32 @@ class StandardStreamWrapper:
     def read(self, n: int = -1) -> bytes:
         return cast(bytes, self._stream_object.read())
 
+    def write(self, contents: bytes) -> int:
+        self._stream_object.write(cast(str, contents))
+        return len(contents)
+
     def close(self) -> None:
         """We do not support closing standard streams."""
 
+    def close_fd(self, fd: Optional[int]) -> None:
+        """We do not support closing standard streams."""
+
     def is_stream(self) -> bool:
         return True
 
+    def __enter__(self) -> "StandardStreamWrapper":
+        """To support usage of this standard stream with the 'with' statement."""
+        return self
+
+    def __exit__(
+        self,
+        exc_type: Optional[Type[BaseException]],
+        exc_val: Optional[BaseException],
+        exc_tb: Optional[TracebackType],
+    ) -> None:
+        """To support usage of this standard stream with the 'with' statement."""
+        self.close()
+
 
 class FakeDirWrapper:
     """Wrapper for a FakeDirectory object to be used in open files list."""
@@ -1230,8 +1316,34 @@ class FakeDirWrapper:
 
     def close(self) -> None:
         """Close the directory."""
-        assert self.filedes is not None
-        self._filesystem._close_open_file(self.filedes)
+        self.close_fd(self.filedes)
+
+    def close_fd(self, fd: Optional[int]) -> None:
+        """Close the directory."""
+        assert fd is not None
+        self._filesystem.close_open_file(fd)
+
+    def read(self, numBytes: int = -1) -> bytes:
+        """Read from the directory."""
+        return self.file_object.read(numBytes)
+
+    def write(self, contents: bytes) -> int:
+        """Write to the directory."""
+        self.file_object.write(contents)
+        return len(contents)
+
+    def __enter__(self) -> "FakeDirWrapper":
+        """To support usage of this fake directory with the 'with' statement."""
+        return self
+
+    def __exit__(
+        self,
+        exc_type: Optional[Type[BaseException]],
+        exc_val: Optional[BaseException],
+        exc_tb: Optional[TracebackType],
+    ) -> None:
+        """To support usage of this fake directory with the 'with' statement."""
+        self.close()
 
 
 class FakePipeWrapper:
@@ -1294,8 +1406,12 @@ class FakePipeWrapper:
 
     def close(self) -> None:
         """Close the pipe descriptor."""
-        assert self.filedes is not None
-        open_files = self._filesystem.open_files[self.filedes]
+        self.close_fd(self.filedes)
+
+    def close_fd(self, fd: Optional[int]) -> None:
+        """Close the pipe descriptor with the given file descriptor."""
+        assert fd is not None
+        open_files = self._filesystem.open_files[fd]
         assert open_files is not None
         open_files.remove(self)
         if self.real_file:
diff --git a/pyfakefs/fake_filesystem.py b/pyfakefs/fake_filesystem.py
index 9f170d1..53d5265 100644
--- a/pyfakefs/fake_filesystem.py
+++ b/pyfakefs/fake_filesystem.py
@@ -80,6 +80,9 @@ True
 >>> stat.S_ISDIR(os_module.stat(os_module.path.dirname(pathname)).st_mode)
 True
 """
+
+import contextlib
+import dataclasses
 import errno
 import heapq
 import os
@@ -100,7 +103,6 @@ from stat import (
 )
 from typing import (
     List,
-    Optional,
     Callable,
     Union,
     Any,
@@ -110,6 +112,7 @@ from typing import (
     AnyStr,
     overload,
     NoReturn,
+    Optional,
 )
 
 from pyfakefs import fake_file, fake_path, fake_io, fake_os, helpers, fake_open
@@ -121,6 +124,9 @@ from pyfakefs.helpers import (
     matching_string,
     AnyPath,
     AnyString,
+    WINDOWS_PROPERTIES,
+    POSIX_PROPERTIES,
+    FSType,
 )
 
 if sys.platform.startswith("linux"):
@@ -178,12 +184,9 @@ class FakeFilesystem:
     """Provides the appearance of a real directory tree for unit testing.
 
     Attributes:
-        path_separator: The path separator, corresponds to `os.path.sep`.
-        alternative_path_separator: Corresponds to `os.path.altsep`.
-        is_windows_fs: `True` in a real or faked Windows file system.
-        is_macos: `True` under MacOS, or if we are faking it.
         is_case_sensitive: `True` if a case-sensitive file system is assumed.
-        root: The root :py:class:`FakeDirectory` entry of the file system.
+        root: The root :py:class:`FakeDirectory<pyfakefs.fake_file.FakeDirectory>` entry
+            of the file system.
         umask: The umask used for newly created files, see `os.umask`.
         patcher: Holds the Patcher object if created from it. Allows access
             to the patcher object if using the pytest fs fixture.
@@ -215,12 +218,8 @@ class FakeFilesystem:
         >>> filesystem = FakeFilesystem(path_separator='/')
 
         """
-        self.path_separator: str = path_separator
-        self.alternative_path_separator: Optional[str] = os.path.altsep
         self.patcher = patcher
         self.create_temp_dir = create_temp_dir
-        if path_separator != os.sep:
-            self.alternative_path_separator = None
 
         # is_windows_fs can be used to test the behavior of pyfakefs under
         # Windows fs on non-Windows systems and vice verse;
@@ -233,7 +232,19 @@ class FakeFilesystem:
 
         # is_case_sensitive can be used to test pyfakefs for case-sensitive
         # file systems on non-case-sensitive systems and vice verse
-        self.is_case_sensitive: bool = not (self.is_windows_fs or self._is_macos)
+        self.is_case_sensitive: bool = not (self._is_windows_fs or self._is_macos)
+
+        # by default, we use the configured filesystem
+        self.fs_type = FSType.DEFAULT
+        base_properties = (
+            WINDOWS_PROPERTIES if self._is_windows_fs else POSIX_PROPERTIES
+        )
+        self.fs_properties = [
+            dataclasses.replace(base_properties),
+            POSIX_PROPERTIES,
+            WINDOWS_PROPERTIES,
+        ]
+        self.path_separator = path_separator
 
         self.root: FakeDirectory
         self._cwd = ""
@@ -260,30 +271,71 @@ class FakeFilesystem:
 
     @property
     def is_linux(self) -> bool:
+        """Returns `True` in a real or faked Linux file system."""
         return not self.is_windows_fs and not self.is_macos
 
     @property
     def is_windows_fs(self) -> bool:
-        return self._is_windows_fs
+        """Returns `True` in a real or faked Windows file system."""
+        return self.fs_type == FSType.WINDOWS or (
+            self.fs_type == FSType.DEFAULT and self._is_windows_fs
+        )
 
     @is_windows_fs.setter
     def is_windows_fs(self, value: bool) -> None:
         if self._is_windows_fs != value:
             self._is_windows_fs = value
+            if value:
+                self._is_macos = False
             self.reset()
             FakePathModule.reset(self)
 
     @property
     def is_macos(self) -> bool:
+        """Returns `True` in a real or faked macOS file system."""
         return self._is_macos
 
     @is_macos.setter
     def is_macos(self, value: bool) -> None:
         if self._is_macos != value:
             self._is_macos = value
+            if value:
+                self._is_windows_fs = False
             self.reset()
             FakePathModule.reset(self)
 
+    @property
+    def path_separator(self) -> str:
+        """Returns the path separator, corresponds to `os.path.sep`."""
+        return self.fs_properties[self.fs_type.value].sep
+
+    @path_separator.setter
+    def path_separator(self, value: str) -> None:
+        self.fs_properties[0].sep = value
+        if value != os.sep:
+            self.alternative_path_separator = None
+
+    @property
+    def alternative_path_separator(self) -> Optional[str]:
+        """Returns the alternative path separator, corresponds to `os.path.altsep`."""
+        return self.fs_properties[self.fs_type.value].altsep
+
+    @alternative_path_separator.setter
+    def alternative_path_separator(self, value: Optional[str]) -> None:
+        self.fs_properties[0].altsep = value
+
+    @property
+    def devnull(self) -> str:
+        return self.fs_properties[self.fs_type.value].devnull
+
+    @property
+    def pathsep(self) -> str:
+        return self.fs_properties[self.fs_type.value].pathsep
+
+    @property
+    def line_separator(self) -> str:
+        return self.fs_properties[self.fs_type.value].linesep
+
     @property
     def cwd(self) -> str:
         """Return the current working directory of the fake filesystem."""
@@ -294,7 +346,10 @@ class FakeFilesystem:
         """Set the current working directory of the fake filesystem.
         Make sure a new drive or share is auto-mounted under Windows.
         """
-        self._cwd = value
+        _cwd = make_string_path(value)
+        self._cwd = _cwd.replace(
+            matching_string(_cwd, os.sep), matching_string(_cwd, self.path_separator)
+        )
         self._auto_mount_drive_if_needed(value)
 
     @property
@@ -332,8 +387,11 @@ class FakeFilesystem:
         self._is_windows_fs = value == OSType.WINDOWS
         self._is_macos = value == OSType.MACOS
         self.is_case_sensitive = value == OSType.LINUX
-        self.path_separator = "\\" if value == OSType.WINDOWS else "/"
-        self.alternative_path_separator = "/" if value == OSType.WINDOWS else None
+        self.fs_type = FSType.DEFAULT
+        base_properties = (
+            WINDOWS_PROPERTIES if self._is_windows_fs else POSIX_PROPERTIES
+        )
+        self.fs_properties[0] = base_properties
         self.reset()
         FakePathModule.reset(self)
 
@@ -356,6 +414,15 @@ class FakeFilesystem:
 
             fake_pathlib.init_module(self)
 
+    @contextlib.contextmanager
+    def use_fs_type(self, fs_type: FSType):
+        old_fs_type = self.fs_type
+        try:
+            self.fs_type = fs_type
+            yield
+        finally:
+            self.fs_type = old_fs_type
+
     def _add_root_mount_point(self, total_size):
         mount_point = "C:" if self.is_windows_fs else self.path_separator
         self._cwd = mount_point
@@ -364,15 +431,15 @@ class FakeFilesystem:
         self.add_mount_point(mount_point, total_size)
 
     def pause(self) -> None:
-        """Pause the patching of the file system modules until `resume` is
+        """Pause the patching of the file system modules until :py:meth:`resume` is
         called. After that call, all file system calls are executed in the
         real file system.
-        Calling pause() twice is silently ignored.
+        Calling `pause()` twice is silently ignored.
         Only allowed if the file system object was created by a
-        Patcher object. This is also the case for the pytest `fs` fixture.
+        `Patcher` object. This is also the case for the pytest `fs` fixture.
 
         Raises:
-            RuntimeError: if the file system was not created by a Patcher.
+            RuntimeError: if the file system was not created by a `Patcher`.
         """
         if self.patcher is None:
             raise RuntimeError(
@@ -382,7 +449,7 @@ class FakeFilesystem:
         self.patcher.pause()
 
     def resume(self) -> None:
-        """Resume the patching of the file system modules if `pause` has
+        """Resume the patching of the file system modules if :py:meth:`pause` has
         been called before. After that call, all file system calls are
         executed in the fake file system.
         Does nothing if patching is not paused.
@@ -401,9 +468,6 @@ class FakeFilesystem:
         if self.patcher:
             self.patcher.clear_cache()
 
-    def line_separator(self) -> str:
-        return "\r\n" if self.is_windows_fs else "\n"
-
     def raise_os_error(
         self,
         err_no: int,
@@ -456,8 +520,8 @@ class FakeFilesystem:
             total_size: The new total size of the added filesystem device
                 in bytes. Defaults to infinite size.
 
-            can_exist: If True, no error is raised if the mount point
-                already exists
+            can_exist: If `True`, no error is raised if the mount point
+                already exists.
 
         Returns:
             The newly created mount point dict.
@@ -581,7 +645,7 @@ class FakeFilesystem:
         """Return the total, used and free disk space in bytes as named tuple,
         or placeholder values simulating unlimited space if not set.
 
-        .. note:: This matches the return value of shutil.disk_usage().
+        .. note:: This matches the return value of ``shutil.disk_usage()``.
 
         Args:
             path: The disk space is returned for the file system device where
@@ -642,7 +706,7 @@ class FakeFilesystem:
             st_dev: The device ID for the respective file system.
 
         Raises:
-            OSError: if usage_change exceeds the free file system space
+            OSError: if `usage_change` exceeds the free file system space
         """
         mount_point = self._mount_point_for_device(st_dev)
         if mount_point:
@@ -673,6 +737,7 @@ class FakeFilesystem:
                 follow_symlinks,
                 allow_fd=True,
                 check_read_perm=False,
+                check_exe_perm=False,
             )
         except TypeError:
             file_object = self.resolve(entry_path)
@@ -680,7 +745,7 @@ class FakeFilesystem:
             # make sure stat raises if a parent dir is not readable
             parent_dir = file_object.parent_dir
             if parent_dir:
-                self.get_object(parent_dir.path)  # type: ignore[arg-type]
+                self.get_object(parent_dir.path, check_read_perm=False)  # type: ignore[arg-type]
 
         self.raise_for_filepath_ending_with_separator(
             entry_path, file_object, follow_symlinks
@@ -719,7 +784,7 @@ class FakeFilesystem:
 
     def chmod(
         self,
-        path: AnyStr,
+        path: Union[AnyStr, int],
         mode: int,
         follow_symlinks: bool = True,
         force_unix_mode: bool = False,
@@ -727,15 +792,16 @@ class FakeFilesystem:
         """Change the permissions of a file as encoded in integer mode.
 
         Args:
-            path: (str) Path to the file.
+            path: (str | int) Path to the file or file descriptor.
             mode: (int) Permissions.
             follow_symlinks: If `False` and `path` points to a symlink,
                 the link itself is affected instead of the linked object.
             force_unix_mode: if True and run under Windows, the mode is not
                 adapted for Windows to allow making dirs unreadable
         """
+        allow_fd = not self.is_windows_fs or sys.version_info >= (3, 13)
         file_object = self.resolve(
-            path, follow_symlinks, allow_fd=True, check_owner=True
+            path, follow_symlinks, allow_fd=allow_fd, check_owner=True
         )
         if self.is_windows_fs and not force_unix_mode:
             if mode & helpers.PERM_WRITE:
@@ -811,7 +877,7 @@ class FakeFilesystem:
         if ns is not None and len(ns) != 2:
             raise TypeError("utime: 'ns' must be a tuple of two ints")
 
-    def _add_open_file(self, file_obj: AnyFileWrapper) -> int:
+    def add_open_file(self, file_obj: AnyFileWrapper, new_fd: int = -1) -> int:
         """Add file_obj to the list of open files on the filesystem.
         Used internally to manage open files.
 
@@ -819,10 +885,31 @@ class FakeFilesystem:
 
         Args:
             file_obj: File object to be added to open files list.
+            new_fd: The optional new file descriptor.
 
         Returns:
             File descriptor number for the file object.
         """
+        if new_fd >= 0:
+            size = len(self.open_files)
+            if new_fd < size:
+                open_files = self.open_files[new_fd]
+                if open_files:
+                    for f in open_files:
+                        try:
+                            f.close()
+                        except OSError:
+                            pass
+                if new_fd in self._free_fd_heap:
+                    self._free_fd_heap.remove(new_fd)
+                self.open_files[new_fd] = [file_obj]
+            else:
+                for fd in range(size, new_fd):
+                    self.open_files.append([])
+                    heapq.heappush(self._free_fd_heap, fd)
+                self.open_files.append([file_obj])
+            return new_fd
+
         if self._free_fd_heap:
             open_fd = heapq.heappop(self._free_fd_heap)
             self.open_files[open_fd] = [file_obj]
@@ -831,7 +918,7 @@ class FakeFilesystem:
         self.open_files.append([file_obj])
         return len(self.open_files) - 1
 
-    def _close_open_file(self, file_des: int) -> None:
+    def close_open_file(self, file_des: int) -> None:
         """Remove file object with given descriptor from the list
         of open files.
 
@@ -857,13 +944,29 @@ class FakeFilesystem:
         Returns:
             Open file object.
         """
+        try:
+            return self.get_open_files(file_des)[0]
+        except IndexError:
+            self.raise_os_error(errno.EBADF, str(file_des))
+
+    def get_open_files(self, file_des: int) -> List[AnyFileWrapper]:
+        """Return the list of open files for a file descriptor.
+
+        Args:
+            file_des: File descriptor of the open files.
+
+        Raises:
+            OSError: an invalid file descriptor.
+            TypeError: filedes is not an integer.
+
+        Returns:
+            List of open file objects.
+        """
         if not is_int_type(file_des):
             raise TypeError("an integer is required")
         valid = file_des < len(self.open_files)
         if valid:
-            file_list = self.open_files[file_des]
-            if file_list is not None:
-                return file_list[0]
+            return self.open_files[file_des] or []
         self.raise_os_error(errno.EBADF, str(file_des))
 
     def has_open_file(self, file_object: FakeFile) -> bool:
@@ -1103,8 +1206,9 @@ class FakeFilesystem:
         if isinstance(p, bytes):
             sep = self.path_separator.encode()
             altsep = None
-            if self.alternative_path_separator:
-                altsep = self.alternative_path_separator.encode()
+            alternative_path_separator = self.alternative_path_separator
+            if alternative_path_separator is not None:
+                altsep = alternative_path_separator.encode()
             colon = b":"
             unc_prefix = b"\\\\?\\UNC\\"
             empty = b""
@@ -1205,26 +1309,23 @@ class FakeFilesystem:
             return paths[0]
         if self.is_windows_fs:
             return self._join_paths_with_drive_support(*file_paths)
-        joined_path_segments = []
+        path = file_paths[0]
         sep = self.get_path_separator(file_paths[0])
-        for path_segment in file_paths:
-            if self._starts_with_root_path(path_segment):
+        for path_segment in file_paths[1:]:
+            if path_segment.startswith(sep) or not path:
                 # An absolute path
-                joined_path_segments = [path_segment]
+                path = path_segment
+            elif path.endswith(sep):
+                path += path_segment
             else:
-                if joined_path_segments and not joined_path_segments[-1].endswith(sep):
-                    joined_path_segments.append(sep)
-                if path_segment:
-                    joined_path_segments.append(path_segment)
-        return matching_string(file_paths[0], "").join(joined_path_segments)
+                path += sep + path_segment
+        return path
 
     @overload
-    def _path_components(self, path: str) -> List[str]:
-        ...
+    def _path_components(self, path: str) -> List[str]: ...
 
     @overload
-    def _path_components(self, path: bytes) -> List[bytes]:
-        ...
+    def _path_components(self, path: bytes) -> List[bytes]: ...
 
     def _path_components(self, path: AnyStr) -> List[AnyStr]:
         """Breaks the path into a list of component names.
@@ -1253,7 +1354,11 @@ class FakeFilesystem:
         if not path or path == self.get_path_separator(path):
             return []
         drive, path = self.splitdrive(path)
-        path_components = path.split(self.get_path_separator(path))
+        sep = self.get_path_separator(path)
+        # handle special case of Windows emulated under POSIX
+        if self.is_windows_fs and sys.platform != "win32":
+            path = path.replace(matching_string(sep, "\\"), sep)
+        path_components = path.split(sep)
         assert drive or path_components
         if not path_components[0]:
             if len(path_components) > 1 and not path_components[1]:
@@ -1284,6 +1389,14 @@ class FakeFilesystem:
                 # check if the path exists because it has been mapped in
                 # this is not foolproof, but handles most cases
                 try:
+                    if len(file_path) == 2:
+                        # avoid recursion, check directly in the entries
+                        return any(
+                            [
+                                entry.upper() == file_path.upper()
+                                for entry in self.root_dir.entries
+                            ]
+                        )
                     self.get_object_from_normpath(file_path)
                     return True
                 except OSError:
@@ -1399,7 +1512,7 @@ class FakeFilesystem:
             raise TypeError
         if not path:
             return False
-        if path == self.dev_null.name:
+        if path == self.devnull:
             return not self.is_windows_fs or sys.version_info >= (3, 8)
         try:
             if self.is_filepath_ending_with_separator(path):
@@ -1463,6 +1576,11 @@ class FakeFilesystem:
         if path is None:
             # file.open(None) raises TypeError, so mimic that.
             raise TypeError("Expected file system path string, received None")
+        if sys.platform == "win32" and self.os != OSType.WINDOWS:
+            path = path.replace(
+                matching_string(path, os.sep),
+                matching_string(path, self.path_separator),
+            )
         if not path or not self._valid_relative_path(path):
             # file.open('') raises OSError, so mimic that, and validate that
             # all parts of a relative path exist.
@@ -1471,7 +1589,7 @@ class FakeFilesystem:
         path = self.replace_windows_root(path)
         if self._is_root_path(path):
             return path
-        if path == matching_string(path, self.dev_null.name):
+        if path == matching_string(path, self.devnull):
             return path
         path_components = self._path_components(path)
         resolved_components = self._resolve_components(path_components)
@@ -1591,6 +1709,7 @@ class FakeFilesystem:
         self,
         file_path: AnyPath,
         check_read_perm: bool = True,
+        check_exe_perm: bool = True,
         check_owner: bool = False,
     ) -> AnyFile:
         """Search for the specified filesystem object within the fake
@@ -1601,6 +1720,8 @@ class FakeFilesystem:
                 path that has already been normalized/resolved.
             check_read_perm: If True, raises OSError if a parent directory
                 does not have read permission
+            check_exe_perm: If True, raises OSError if a parent directory
+                does not have execute (e.g. search) permission
             check_owner: If True, and check_read_perm is also True,
                 only checks read permission if the current user id is
                 different from the file object user id
@@ -1614,7 +1735,7 @@ class FakeFilesystem:
         path = make_string_path(file_path)
         if path == matching_string(path, self.root.name):
             return self.root
-        if path == matching_string(path, self.dev_null.name):
+        if path == matching_string(path, self.devnull):
             return self.dev_null
 
         path = self._original_path(path)
@@ -1632,9 +1753,11 @@ class FakeFilesystem:
                 target = target.get_entry(component)  # type: ignore
                 if (
                     not is_root()
-                    and check_read_perm
+                    and (check_read_perm or check_exe_perm)
                     and target
-                    and not self._can_read(target, check_owner)
+                    and not self._can_read(
+                        target, check_read_perm, check_exe_perm, check_owner
+                    )
                 ):
                     self.raise_os_error(errno.EACCES, target.path)
         except KeyError:
@@ -1642,26 +1765,29 @@ class FakeFilesystem:
         return target
 
     @staticmethod
-    def _can_read(target, owner_can_read):
-        if target.st_uid == helpers.get_uid():
-            if owner_can_read or target.st_mode & 0o400:
-                return True
-        if target.st_gid == get_gid():
-            if target.st_mode & 0o040:
-                return True
-        return target.st_mode & 0o004
+    def _can_read(target, check_read_perm, check_exe_perm, owner_can_read):
+        if owner_can_read and target.st_uid == helpers.get_uid():
+            return True
+        permission = helpers.PERM_READ if check_read_perm else 0
+        if S_ISDIR(target.st_mode) and check_exe_perm:
+            permission |= helpers.PERM_EXE
+        if not permission:
+            return True
+        return target.has_permission(permission)
 
     def get_object(self, file_path: AnyPath, check_read_perm: bool = True) -> FakeFile:
         """Search for the specified filesystem object within the fake
         filesystem.
 
         Args:
-            file_path: Specifies the target FakeFile object to retrieve.
+            file_path: Specifies the target
+                :py:class:`FakeFile<pyfakefs.fake_file.FakeFile>` object to retrieve.
             check_read_perm: If True, raises OSError if a parent directory
                 does not have read permission
 
         Returns:
-            The FakeFile object corresponding to `file_path`.
+            The :py:class:`FakeFile<pyfakefs.fake_file.FakeFile>` object corresponding
+            to `file_path`.
 
         Raises:
             OSError: if the object is not found.
@@ -1672,10 +1798,11 @@ class FakeFilesystem:
 
     def resolve(
         self,
-        file_path: AnyStr,
+        file_path: Union[AnyStr, int],
         follow_symlinks: bool = True,
         allow_fd: bool = False,
         check_read_perm: bool = True,
+        check_exe_perm: bool = True,
         check_owner: bool = False,
     ) -> FakeFile:
         """Search for the specified filesystem object, resolving all links.
@@ -1687,6 +1814,8 @@ class FakeFilesystem:
             allow_fd: If `True`, `file_path` may be an open file descriptor
             check_read_perm: If True, raises OSError if a parent directory
                 does not have read permission
+            check_read_perm: If True, raises OSError if a parent directory
+                does not have execute permission
             check_owner: If True, and check_read_perm is also True,
                 only checks read permission if the current user id is
                 different from the file object user id
@@ -1699,13 +1828,16 @@ class FakeFilesystem:
         """
         if isinstance(file_path, int):
             if allow_fd:
-                return self.get_open_file(file_path).get_object()
-            raise TypeError("path should be string, bytes or " "os.PathLike, not int")
+                open_file = self.get_open_file(file_path).get_object()
+                assert isinstance(open_file, FakeFile)
+                return open_file
+            raise TypeError("path should be string, bytes or os.PathLike, not int")
 
         if follow_symlinks:
             return self.get_object_from_normpath(
                 self.resolve_path(file_path, allow_fd),
                 check_read_perm,
+                check_exe_perm,
                 check_owner,
             )
         return self.lresolve(file_path)
@@ -1748,7 +1880,7 @@ class FakeFilesystem:
                 if not self.is_windows_fs and isinstance(parent_obj, FakeFile):
                     self.raise_os_error(errno.ENOTDIR, path_str)
                 self.raise_os_error(errno.ENOENT, path_str)
-            if not parent_obj.st_mode & helpers.PERM_READ:
+            if not parent_obj.has_permission(helpers.PERM_READ):
                 self.raise_os_error(errno.EACCES, parent_directory)
             return (
                 parent_obj.get_entry(to_string(child_name))
@@ -1773,7 +1905,10 @@ class FakeFilesystem:
         if not file_path:
             target_directory = self.root_dir
         else:
-            target_directory = cast(FakeDirectory, self.resolve(file_path))
+            target_directory = cast(
+                FakeDirectory,
+                self.resolve(file_path, check_read_perm=False, check_exe_perm=True),
+            )
             if not S_ISDIR(target_directory.st_mode):
                 error = errno.ENOENT if self.is_windows_fs else errno.ENOTDIR
                 self.raise_os_error(error, file_path)
@@ -2025,25 +2160,32 @@ class FakeFilesystem:
         except AttributeError:
             self.raise_os_error(errno.ENOTDIR, file_path)
 
-    def make_string_path(self, path: AnyPath) -> AnyStr:
+    def make_string_path(self, path: AnyPath) -> AnyStr:  # type: ignore[type-var]
         path_str = make_string_path(path)
         os_sep = matching_string(path_str, os.sep)
         fake_sep = self.get_path_separator(path_str)
         return path_str.replace(os_sep, fake_sep)  # type: ignore[return-value]
 
     def create_dir(
-        self, directory_path: AnyPath, perm_bits: int = helpers.PERM_DEF
+        self,
+        directory_path: AnyPath,
+        perm_bits: int = helpers.PERM_DEF,
+        apply_umask: bool = True,
     ) -> FakeDirectory:
-        """Create `directory_path`, and all the parent directories.
+        """Create `directory_path` and all the parent directories, and return
+        the created :py:class:`FakeDirectory<pyfakefs.fake_file.FakeDirectory>` object.
 
         Helper method to set up your test faster.
 
         Args:
             directory_path: The full directory path to create.
-            perm_bits: The permission bits as set by `chmod`.
+            perm_bits: The permission bits as set by ``chmod``.
+            apply_umask: If `True` (default), the current umask is applied
+                to `perm_bits`.
 
         Returns:
-            The newly created FakeDirectory object.
+            The newly created
+            :py:class:`FakeDirectory<pyfakefs.fake_file.FakeDirectory>` object.
 
         Raises:
             OSError: if the directory already exists.
@@ -2078,6 +2220,8 @@ class FakeFilesystem:
         # set the permission after creating the directories
         # to allow directory creation inside a read-only directory
         for new_dir in new_dirs:
+            if apply_umask:
+                perm_bits &= ~self.umask
             new_dir.st_mode = S_IFDIR | perm_bits
 
         return current_dir
@@ -2089,35 +2233,36 @@ class FakeFilesystem:
         contents: AnyString = "",
         st_size: Optional[int] = None,
         create_missing_dirs: bool = True,
-        apply_umask: bool = False,
+        apply_umask: bool = True,
         encoding: Optional[str] = None,
         errors: Optional[str] = None,
         side_effect: Optional[Callable] = None,
     ) -> FakeFile:
         """Create `file_path`, including all the parent directories along
-        the way.
+        the way, and return the created
+        :py:class:`FakeFile<pyfakefs.fake_file.FakeFile>` object.
 
         This helper method can be used to set up tests more easily.
 
         Args:
             file_path: The path to the file to create.
-            st_mode: The stat constant representing the file type.
-            contents: the contents of the file. If not given and st_size is
-                None, an empty file is assumed.
+            st_mode: The `stat` constant representing the file type.
+            contents: the contents of the file. If not given and `st_size` is
+                `None`, an empty file is assumed.
             st_size: file size; only valid if contents not given. If given,
                 the file is considered to be in "large file mode" and trying
                 to read from or write to the file will result in an exception.
             create_missing_dirs: If `True`, auto create missing directories.
-            apply_umask: `True` if the current umask must be applied
-                on `st_mode`.
-            encoding: If `contents` is a unicode string, the encoding used
+            apply_umask: If `True` (default), the current umask is applied
+                to `st_mode`.
+            encoding: If `contents` is of type `str`, the encoding used
                 for serialization.
             errors: The error mode used for encoding/decoding errors.
-            side_effect: function handle that is executed when file is written,
+            side_effect: function handle that is executed when the file is written,
                 must accept the file object as an argument.
 
         Returns:
-            The newly created FakeFile object.
+            The newly created :py:class:`FakeFile<pyfakefs.fake_file.FakeFile>` object.
 
         Raises:
             OSError: if the file already exists.
@@ -2142,8 +2287,9 @@ class FakeFilesystem:
         target_path: Optional[AnyPath] = None,
     ) -> FakeFile:
         """Create `file_path`, including all the parent directories along the
-        way, for an existing real file. The contents of the real file are read
-        only on demand.
+        way, for an existing real file, and return the created
+        :py:class:`FakeFile<pyfakefs.fake_file.FakeFile>` object.
+        The contents of the real file are read only on demand.
 
         Args:
             source_path: Path to an existing file in the real file system
@@ -2154,7 +2300,7 @@ class FakeFilesystem:
                 otherwise it is equal to `source_path`.
 
         Returns:
-            the newly created FakeFile object.
+            the newly created :py:class:`FakeFile<pyfakefs.fake_file.FakeFile>` object.
 
         Raises:
             OSError: if the file does not exist in the real file system.
@@ -2181,9 +2327,10 @@ class FakeFilesystem:
     def add_real_symlink(
         self, source_path: AnyPath, target_path: Optional[AnyPath] = None
     ) -> FakeFile:
-        """Create a symlink at source_path (or target_path, if given).  It will
-        point to the same path as the symlink on the real filesystem.  Relative
-        symlinks will point relative to their new location.  Absolute symlinks
+        """Create a symlink at `source_path` (or `target_path`, if given) and return
+        the created :py:class:`FakeFile<pyfakefs.fake_file.FakeFile>` object.
+        It will point to the same path as the symlink on the real filesystem.
+        Relative symlinks will point relative to their new location.  Absolute symlinks
         will point to the same, absolute path as on the real filesystem.
 
         Args:
@@ -2192,7 +2339,7 @@ class FakeFilesystem:
                 filesystem, otherwise, the same as `source_path`.
 
         Returns:
-            the newly created FakeFile object.
+            the newly created :py:class:`FakeFile<pyfakefs.fake_file.FakeFile>` object.
 
         Raises:
             OSError: if the directory does not exist in the real file system.
@@ -2220,8 +2367,12 @@ class FakeFilesystem:
         target_path: Optional[AnyPath] = None,
     ) -> FakeDirectory:
         """Create a fake directory corresponding to the real directory at the
-        specified path.  Add entries in the fake directory corresponding to
+        specified path, and return the created
+        :py:class:`FakeDirectory<pyfakefs.fake_file.FakeDirectory>` object.
+        Add entries in the fake directory corresponding to
         the entries in the real directory.  Symlinks are supported.
+        If the target directory already exists in the fake filesystem, the directory
+        contents are merged. Overwriting existing files is not allowed.
 
         Args:
             source_path: The path to the existing directory.
@@ -2240,52 +2391,82 @@ class FakeFilesystem:
                 the target directory is the same as `source_path`.
 
         Returns:
-            the newly created FakeDirectory object.
+            the newly created
+            :py:class:`FakeDirectory<pyfakefs.fake_file.FakeDirectory>` object.
 
         Raises:
-            OSError: if the directory does not exist in the real file system.
-            OSError: if the directory already exists in the fake file system.
+            OSError: if the directory does not exist in the real filesystem.
+            OSError: if a file or link exists in the fake filesystem where a real
+                file or directory shall be mapped.
         """
-        source_path_str = make_string_path(source_path)  # TODO: add test
+        source_path_str = make_string_path(source_path)
         source_path_str = self._path_without_trailing_separators(source_path_str)
         if not os.path.exists(source_path_str):
             self.raise_os_error(errno.ENOENT, source_path_str)
         target_path_str = make_string_path(target_path or source_path_str)
+
+        # get rid of inconsistencies between real and fake path separators
+        if os.altsep is not None:
+            target_path_str = os.path.normpath(target_path_str)
+        if os.sep != self.path_separator:
+            target_path_str = target_path_str.replace(os.sep, self.path_separator)
+
         self._auto_mount_drive_if_needed(target_path_str)
-        new_dir: FakeDirectory
         if lazy_read:
-            parent_path = os.path.split(target_path_str)[0]
-            if self.exists(parent_path):
-                parent_dir = self.get_object(parent_path)
-            else:
-                parent_dir = self.create_dir(parent_path)
-            new_dir = FakeDirectoryFromRealDirectory(
-                source_path_str, self, read_only, target_path_str
+            self._create_fake_from_real_dir_lazily(
+                source_path_str, target_path_str, read_only
             )
-            parent_dir.add_entry(new_dir)
         else:
-            new_dir = self.create_dir(target_path_str)
-            for base, _, files in os.walk(source_path_str):
-                new_base = os.path.join(
-                    new_dir.path,  # type: ignore[arg-type]
-                    os.path.relpath(base, source_path_str),
-                )
-                for fileEntry in os.listdir(base):
-                    abs_fileEntry = os.path.join(base, fileEntry)
-
-                    if not os.path.islink(abs_fileEntry):
-                        continue
-
-                    self.add_real_symlink(
-                        abs_fileEntry, os.path.join(new_base, fileEntry)
-                    )
-                for fileEntry in files:
-                    path = os.path.join(base, fileEntry)
-                    if os.path.islink(path):
-                        continue
+            self._create_fake_from_real_dir(source_path_str, target_path_str, read_only)
+        return cast(FakeDirectory, self.get_object(target_path_str))
+
+    def _create_fake_from_real_dir(self, source_path_str, target_path_str, read_only):
+        if not self.exists(target_path_str):
+            self.create_dir(target_path_str)
+        for base, _, files in os.walk(source_path_str):
+            new_base = os.path.join(
+                target_path_str,
+                os.path.relpath(base, source_path_str),
+            )
+            for file_entry in os.listdir(base):
+                file_path = os.path.join(base, file_entry)
+                if os.path.islink(file_path):
+                    self.add_real_symlink(file_path, os.path.join(new_base, file_entry))
+            for file_entry in files:
+                path = os.path.join(base, file_entry)
+                if not os.path.islink(path):
                     self.add_real_file(
-                        path, read_only, os.path.join(new_base, fileEntry)
+                        path, read_only, os.path.join(new_base, file_entry)
+                    )
+
+    def _create_fake_from_real_dir_lazily(
+        self, source_path_str, target_path_str, read_only
+    ):
+        if self.exists(target_path_str):
+            if not self.isdir(target_path_str):
+                raise OSError(errno.ENOTDIR, "Mapping target is not a directory")
+            for entry in os.listdir(source_path_str):
+                src_entry_path = os.path.join(source_path_str, entry)
+                target_entry_path = os.path.join(target_path_str, entry)
+                if os.path.isdir(src_entry_path):
+                    self.add_real_directory(
+                        src_entry_path, read_only, True, target_entry_path
                     )
+                elif os.path.islink(src_entry_path):
+                    self.add_real_symlink(src_entry_path, target_entry_path)
+                elif os.path.isfile(src_entry_path):
+                    self.add_real_file(src_entry_path, read_only, target_entry_path)
+            return self.get_object(target_path_str)
+
+        parent_path = os.path.split(target_path_str)[0]
+        if self.exists(parent_path):
+            parent_dir = self.get_object(parent_path)
+        else:
+            parent_dir = self.create_dir(parent_path)
+        new_dir = FakeDirectoryFromRealDirectory(
+            source_path_str, self, read_only, target_path_str
+        )
+        parent_dir.add_entry(new_dir)
         return new_dir
 
     def add_real_paths(
@@ -2295,24 +2476,24 @@ class FakeFilesystem:
         lazy_dir_read: bool = True,
     ) -> None:
         """This convenience method adds multiple files and/or directories from
-        the real file system to the fake file system. See `add_real_file()` and
-        `add_real_directory()`.
+        the real file system to the fake file system. See :py:meth:`add_real_file` and
+        :py:meth:`add_real_directory`.
 
         Args:
             path_list: List of file and directory paths in the real file
                 system.
-            read_only: If set, all files and files under under the directories
+            read_only: If set, all files and files under the directories
                 are treated as read-only, e.g. a write access raises an
                 exception; otherwise, writing to the files changes the fake
                 files only as usually.
             lazy_dir_read: Uses lazy reading of directory contents if set
-                (see `add_real_directory`)
+                (see :py:meth:`add_real_directory`)
 
         Raises:
             OSError: if any of the files and directories in the list
                 does not exist in the real file system.
-            OSError: if any of the files and directories in the list
-                already exists in the fake file system.
+            OSError: if a file or link exists in the fake filesystem where a real
+                file or directory shall be mapped.
         """
         for path in path_list:
             if os.path.isdir(path):
@@ -2327,7 +2508,7 @@ class FakeFilesystem:
         contents: AnyString = "",
         st_size: Optional[int] = None,
         create_missing_dirs: bool = True,
-        apply_umask: bool = False,
+        apply_umask: bool = True,
         encoding: Optional[str] = None,
         errors: Optional[str] = None,
         read_from_real_fs: bool = False,
@@ -2372,7 +2553,8 @@ class FakeFilesystem:
             if not create_missing_dirs:
                 self.raise_os_error(errno.ENOENT, parent_directory)
             parent_directory = matching_string(
-                path, self.create_dir(parent_directory).path  # type: ignore
+                path,
+                self.create_dir(parent_directory).path,  # type: ignore
             )
         else:
             parent_directory = self._original_path(parent_directory)
@@ -2415,16 +2597,18 @@ class FakeFilesystem:
         link_target: AnyPath,
         create_missing_dirs: bool = True,
     ) -> FakeFile:
-        """Create the specified symlink, pointed at the specified link target.
+        """Create the specified symlink, pointed at the specified link target,
+        and return the created :py:class:`FakeFile<pyfakefs.fake_file.FakeFile>` object
+        representing the link.
 
         Args:
             file_path:  path to the symlink to create
             link_target:  the target of the symlink
             create_missing_dirs: If `True`, any missing parent directories of
-                file_path will be created
+                `file_path` will be created
 
         Returns:
-            The newly created FakeFile object.
+            The newly created :py:class:`FakeFile<pyfakefs.fake_file.FakeFile>` object.
 
         Raises:
             OSError: if the symlink could not be created
@@ -2459,11 +2643,13 @@ class FakeFilesystem:
         # resolve the link path only if it is not a link itself
         if not self.islink(link_path):
             link_path = self.resolve_path(link_path)
+        permission = helpers.PERM_DEF_FILE if self.is_windows_fs else helpers.PERM_DEF
         return self.create_file_internally(
             link_path,
-            st_mode=S_IFLNK | helpers.PERM_DEF,
+            st_mode=S_IFLNK | permission,
             contents=link_target_path,
             create_missing_dirs=create_missing_dirs,
+            apply_umask=self.is_macos,
         )
 
     def create_link(
@@ -2473,22 +2659,25 @@ class FakeFilesystem:
         follow_symlinks: bool = True,
         create_missing_dirs: bool = True,
     ) -> FakeFile:
-        """Create a hard link at new_path, pointing at old_path.
+        """Create a hard link at `new_path`, pointing at `old_path`,
+        and return the created :py:class:`FakeFile<pyfakefs.fake_file.FakeFile>` object
+        representing the link.
 
         Args:
             old_path: An existing link to the target file.
             new_path: The destination path to create a new link at.
-            follow_symlinks: If False and old_path is a symlink, link the
+            follow_symlinks: If `False` and `old_path` is a symlink, link the
                 symlink instead of the object it points to.
             create_missing_dirs: If `True`, any missing parent directories of
-                file_path will be created
+                `file_path` will be created
 
         Returns:
-            The FakeFile object referred to by old_path.
+            The :py:class:`FakeFile<pyfakefs.fake_file.FakeFile>` object referred to
+            by `old_path`.
 
         Raises:
-            OSError:  if something already exists at new_path.
-            OSError:  if old_path is a directory.
+            OSError:  if something already exists at `new_path`.
+            OSError:  if `old_path` is a directory.
             OSError:  if the parent directory doesn't exist.
         """
         old_path_str = make_string_path(old_path)
@@ -2626,12 +2815,16 @@ class FakeFilesystem:
 
         if self.is_windows_fs:
             dir_name = self.absnormpath(dir_name)
-        parent_dir, _ = self.splitpath(dir_name)
+        parent_dir, rest = self.splitpath(dir_name)
         if parent_dir:
             base_dir = self.normpath(parent_dir)
             ellipsis = matching_string(parent_dir, self.path_separator + "..")
             if parent_dir.endswith(ellipsis) and not self.is_windows_fs:
                 base_dir, dummy_dotdot, _ = parent_dir.partition(ellipsis)
+            if self.is_windows_fs and not rest and not self.exists(base_dir):
+                # under Windows, the parent dir may be a drive or UNC path
+                # which has to be mounted
+                self._auto_mount_drive_if_needed(parent_dir)
             if not self.exists(base_dir):
                 self.raise_os_error(errno.ENOENT, base_dir)
 
@@ -2704,7 +2897,7 @@ class FakeFilesystem:
             else:
                 current_dir = cast(FakeDirectory, current_dir.entries[component])
         try:
-            self.create_dir(dir_name, mode & ~self.umask)
+            self.create_dir(dir_name, mode)
         except OSError as e:
             if e.errno == errno.EACCES:
                 # permission denied - propagate exception
@@ -2712,7 +2905,8 @@ class FakeFilesystem:
             if not exist_ok or not isinstance(self.resolve(dir_name), FakeDirectory):
                 if self.is_windows_fs and e.errno == errno.ENOTDIR:
                     e.errno = errno.ENOENT
-                self.raise_os_error(e.errno, e.filename)
+                # mypy thinks that errno may be None
+                self.raise_os_error(cast(int, e.errno), e.filename)
 
     def _is_of_type(
         self,
@@ -2802,7 +2996,11 @@ class FakeFilesystem:
             return False
 
     def confirmdir(
-        self, target_directory: AnyStr, check_owner: bool = False
+        self,
+        target_directory: AnyStr,
+        check_read_perm: bool = True,
+        check_exe_perm: bool = True,
+        check_owner: bool = False,
     ) -> FakeDirectory:
         """Test that the target is actually a directory, raising OSError
         if not.
@@ -2810,6 +3008,10 @@ class FakeFilesystem:
         Args:
             target_directory: Path to the target directory within the fake
                 filesystem.
+            check_read_perm: If True, raises OSError if the directory
+                does not have read permission
+            check_exe_perm: If True, raises OSError if the directory
+                does not have execute (e.g. search) permission
             check_owner: If True, only checks read permission if the current
                 user id is different from the file object user id
 
@@ -2821,7 +3023,12 @@ class FakeFilesystem:
         """
         directory = cast(
             FakeDirectory,
-            self.resolve(target_directory, check_owner=check_owner),
+            self.resolve(
+                target_directory,
+                check_read_perm=check_read_perm,
+                check_exe_perm=check_exe_perm,
+                check_owner=check_owner,
+            ),
         )
         if not directory.st_mode & S_IFDIR:
             self.raise_os_error(errno.ENOTDIR, target_directory, 267)
@@ -2915,7 +3122,7 @@ class FakeFilesystem:
             OSError: if the target is not a directory.
         """
         target_directory = self.resolve_path(target_directory, allow_fd=True)
-        directory = self.confirmdir(target_directory)
+        directory = self.confirmdir(target_directory, check_exe_perm=False)
         directory_contents = list(directory.entries.keys())
         if self.shuffle_listdir_results:
             random.shuffle(directory_contents)
@@ -2924,15 +3131,71 @@ class FakeFilesystem:
     def __str__(self) -> str:
         return str(self.root_dir)
 
+    if sys.version_info >= (3, 13):
+        # used for emulating Windows
+        _WIN_RESERVED_NAMES = frozenset(
+            {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
+            | {f"COM{c}" for c in "123456789\xb9\xb2\xb3"}
+            | {f"LPT{c}" for c in "123456789\xb9\xb2\xb3"}
+        )
+        _WIN_RESERVED_CHARS = frozenset(
+            {chr(i) for i in range(32)} | {'"', "*", ":", "<", ">", "?", "|", "/", "\\"}
+        )
+
+        def isreserved(self, path):
+            if not self.is_windows_fs:
+                return False
+
+            def is_reserved_name(name):
+                if sys.platform == "win32":
+                    from os.path import _isreservedname  # type: ignore[import-error]
+
+                    return _isreservedname(name)
+
+                if name[-1:] in (".", " "):
+                    return name not in (".", "..")
+                if self._WIN_RESERVED_CHARS.intersection(name):
+                    return True
+                name = name.partition(".")[0].rstrip(" ").upper()
+                return name in self._WIN_RESERVED_NAMES
+
+            path = os.fsdecode(self.splitroot(path)[2])
+            if self.alternative_path_separator is not None:
+                path = path.replace(
+                    self.alternative_path_separator, self.path_separator
+                )
+
+            return any(
+                is_reserved_name(name)
+                for name in reversed(path.split(self.path_separator))
+            )
+
     def _add_standard_streams(self) -> None:
-        self._add_open_file(StandardStreamWrapper(sys.stdin))
-        self._add_open_file(StandardStreamWrapper(sys.stdout))
-        self._add_open_file(StandardStreamWrapper(sys.stderr))
+        self.add_open_file(StandardStreamWrapper(sys.stdin))
+        self.add_open_file(StandardStreamWrapper(sys.stdout))
+        self.add_open_file(StandardStreamWrapper(sys.stderr))
+
+    def _tempdir_name(self):
+        """This logic is extracted from tempdir._candidate_tempdir_list.
+        We cannot rely on tempdir.gettempdir() in an empty filesystem, as it tries
+        to write to the filesystem to ensure that the tempdir is valid.
+        """
+        # reset the cached tempdir in tempfile
+        tempfile.tempdir = None
+        for env_name in "TMPDIR", "TEMP", "TMP":
+            dir_name = os.getenv(env_name)
+            if dir_name:
+                return dir_name
+        # we have to check the real OS temp path here, as this is what
+        # tempfile assumes
+        if os.name == "nt":
+            return os.path.expanduser(r"~\AppData\Local\Temp")
+        return "/tmp"
 
     def _create_temp_dir(self):
         # the temp directory is assumed to exist at least in `tempfile`,
         # so we create it here for convenience
-        temp_dir = tempfile.gettempdir()
+        temp_dir = self._tempdir_name()
         if not self.exists(temp_dir):
             self.create_dir(temp_dir)
         if sys.platform != "win32" and not self.exists("/tmp"):
diff --git a/pyfakefs/fake_filesystem_shutil.py b/pyfakefs/fake_filesystem_shutil.py
index 561ccd2..d3f4ea5 100755
--- a/pyfakefs/fake_filesystem_shutil.py
+++ b/pyfakefs/fake_filesystem_shutil.py
@@ -26,6 +26,7 @@ work fine with the fake file system if `os`/`os.path` are patched.
   `fake_filesystem_unittest.TestCase`, pytest fs fixture,
   or directly `Patcher`.
 """
+
 import os
 import shutil
 import sys
diff --git a/pyfakefs/fake_filesystem_unittest.py b/pyfakefs/fake_filesystem_unittest.py
index 4604a65..e42eaa0 100644
--- a/pyfakefs/fake_filesystem_unittest.py
+++ b/pyfakefs/fake_filesystem_unittest.py
@@ -35,11 +35,12 @@ Existing unit tests that use the real file system can be retrofitted to use
 pyfakefs by simply changing their base class from `:py:class`unittest.TestCase`
 to `:py:class`pyfakefs.fake_filesystem_unittest.TestCase`.
 """
+
 import _io  # type:ignore[import]
-import builtins
 import doctest
 import functools
 import genericpath
+import glob
 import inspect
 import io
 import linecache
@@ -48,7 +49,12 @@ import shutil
 import sys
 import tempfile
 import tokenize
+import unittest
+import warnings
+from importlib import reload
 from importlib.abc import Loader, MetaPathFinder
+from importlib.machinery import ModuleSpec
+from importlib.util import spec_from_file_location, module_from_spec
 from types import ModuleType, TracebackType, FunctionType
 from typing import (
     Any,
@@ -65,10 +71,13 @@ from typing import (
     ItemsView,
     Sequence,
 )
-import unittest
-import warnings
 from unittest import TestSuite
 
+from pyfakefs import fake_filesystem, fake_io, fake_os, fake_open, fake_path, fake_file
+from pyfakefs import fake_filesystem_shutil
+from pyfakefs import fake_legacy_modules
+from pyfakefs import fake_pathlib
+from pyfakefs import mox3_stubout
 from pyfakefs.fake_filesystem import (
     set_uid,
     set_gid,
@@ -76,23 +85,49 @@ from pyfakefs.fake_filesystem import (
     PatchMode,
     FakeFilesystem,
 )
+from pyfakefs.fake_os import use_original_os
 from pyfakefs.helpers import IS_PYPY
+from pyfakefs.legacy_packages import pathlib2, scandir
 from pyfakefs.mox3_stubout import StubOutForTesting
 
-from importlib.machinery import ModuleSpec
-from importlib import reload
+OS_MODULE = "nt" if sys.platform == "win32" else "posix"
+PATH_MODULE = "ntpath" if sys.platform == "win32" else "posixpath"
 
-from pyfakefs import fake_filesystem, fake_io, fake_os, fake_open, fake_path, fake_file
-from pyfakefs import fake_filesystem_shutil
-from pyfakefs import fake_pathlib
-from pyfakefs import mox3_stubout
-from pyfakefs.extra_packages import pathlib2, use_scandir
 
-if use_scandir:
-    from pyfakefs import fake_scandir
+class TempfilePatcher:
+    """Handles tempfile patching for Posix systems."""
 
-OS_MODULE = "nt" if sys.platform == "win32" else "posix"
-PATH_MODULE = "ntpath" if sys.platform == "win32" else "posixpath"
+    def __init__(self):
+        self.tempfile_cleanup = None
+
+    def start_patching(self):
+        if self.tempfile_cleanup is not None:
+            return
+        if sys.version_info >= (3, 12):
+
+            def cleanup(self_, windows=(os.name == "nt"), unlink=None):
+                self.tempfile_cleanup(self_, windows, unlink or os.unlink)
+
+            self.tempfile_cleanup = tempfile._TemporaryFileCloser.cleanup  # type: ignore[module-attr]
+            tempfile._TemporaryFileCloser.cleanup = cleanup  # type: ignore[module-attr]
+        elif sys.platform != "win32":
+
+            def close(self_, unlink=None):
+                self.tempfile_cleanup(self_, unlink or os.unlink)
+
+            self.tempfile_cleanup = tempfile._TemporaryFileCloser.close  # type: ignore[module-attr]
+            tempfile._TemporaryFileCloser.close = close  # type: ignore[module-attr]
+
+    def stop_patching(self):
+        if self.tempfile_cleanup is None:
+            return
+        if sys.version_info < (3, 12):
+            tempfile._TemporaryFileCloser.close = self.tempfile_cleanup  # type: ignore[module-attr]
+        else:
+            tempfile._TemporaryFileCloser.cleanup = self.tempfile_cleanup  # type: ignore[module-attr]
+        self.tempfile_cleanup = None
+        # reset the cached tempdir in tempfile
+        tempfile.tempdir = None
 
 
 def patchfs(
@@ -105,7 +140,8 @@ def patchfs(
     use_known_patches: bool = True,
     patch_open_code: PatchMode = PatchMode.OFF,
     patch_default_args: bool = False,
-    use_cache: bool = True
+    use_cache: bool = True,
+    use_dynamic_patch: bool = True,
 ) -> Callable:
     """Convenience decorator to use patcher with additional parameters in a
     test function.
@@ -133,6 +169,7 @@ def patchfs(
                 patch_open_code=patch_open_code,
                 patch_default_args=patch_default_args,
                 use_cache=use_cache,
+                use_dynamic_patch=use_dynamic_patch,
             ) as p:
                 args = list(args)
                 args.append(p.fs)
@@ -168,6 +205,7 @@ def load_doctests(
     use_known_patches: bool = True,
     patch_open_code: PatchMode = PatchMode.OFF,
     patch_default_args: bool = False,
+    use_dynamic_patch: bool = True,
 ) -> TestSuite:  # pylint:disable=unused-argument
     """Load the doctest tests for the specified module into unittest.
         Args:
@@ -187,6 +225,7 @@ def load_doctests(
             use_known_patches=use_known_patches,
             patch_open_code=patch_open_code,
             patch_default_args=patch_default_args,
+            use_dynamic_patch=use_dynamic_patch,
             is_doc_test=True,
         )
     assert Patcher.DOC_PATCHER is not None
@@ -207,7 +246,7 @@ class TestCaseMixin:
     modules by fake implementations.
 
     Attributes:
-        additional_skip_names: names of modules inside of which no module
+        additional_skip_names: names of modules where no module
             replacement shall be performed, in addition to the names in
             :py:attr:`fake_filesystem_unittest.Patcher.SKIPNAMES`.
             Instead of the module names, the modules themselves may be used.
@@ -220,7 +259,7 @@ class TestCaseMixin:
             fully qualified patched module names. Can be used to add patching
             of modules not provided by `pyfakefs`.
 
-    If you specify some of these attributes here and you have DocTests,
+    If you specify some of these attributes here, and you have DocTests,
     consider also specifying the same arguments to :py:func:`load_doctests`.
 
     Example usage in derived test classes::
@@ -266,6 +305,7 @@ class TestCaseMixin:
         patch_open_code: PatchMode = PatchMode.OFF,
         patch_default_args: bool = False,
         use_cache: bool = True,
+        use_dynamic_patch: bool = True,
     ) -> None:
         """Bind the file-related modules to the :py:class:`pyfakefs` fake file
         system instead of the real file system.  Also bind the fake `open()`
@@ -297,6 +337,7 @@ class TestCaseMixin:
             patch_open_code=patch_open_code,
             patch_default_args=patch_default_args,
             use_cache=use_cache,
+            use_dynamic_patch=use_dynamic_patch,
         )
 
         self._patcher.setUp()
@@ -313,6 +354,7 @@ class TestCaseMixin:
         patch_open_code: PatchMode = PatchMode.OFF,
         patch_default_args: bool = False,
         use_cache: bool = True,
+        use_dynamic_patch: bool = True,
     ) -> None:
         """Similar to :py:func:`setUpPyfakefs`, but as a class method that
         can be used in `setUpClass` instead of in `setUp`.
@@ -322,6 +364,8 @@ class TestCaseMixin:
         :py:func:`setUpPyfakefs` in the same class will not work correctly.
 
         .. note:: This method is only available from Python 3.8 onwards.
+        .. note:: If using `pytest` as testrunner, you need at least pytest 6.2
+            for this method to work.
         """
         if sys.version_info < (3, 8):
             raise NotImplementedError(
@@ -348,6 +392,7 @@ class TestCaseMixin:
             patch_open_code=patch_open_code,
             patch_default_args=patch_default_args,
             use_cache=use_cache,
+            use_dynamic_patch=use_dynamic_patch,
         )
 
         Patcher.PATCHER.setUp()
@@ -470,6 +515,13 @@ class Patcher:
         SKIPMODULES.add(posixpath)
         SKIPMODULES.add(fcntl)
 
+    # a list of modules detected at run-time
+    # each tool defines one or more module name prefixes for modules to be skipped
+    RUNTIME_SKIPMODULES = {
+        "pydevd": ["_pydevd_", "pydevd", "_pydev_"],  # Python debugger (PyCharm/VSCode)
+        "_jb_runner_tools": ["_jb_"],  # JetBrains tools
+    }
+
     # caches all modules that do not have file system modules or function
     # to speed up _find_modules
     CACHED_MODULES: Set[ModuleType] = set()
@@ -478,7 +530,7 @@ class Patcher:
     FS_DEFARGS: List[Tuple[FunctionType, int, Callable[..., Any]]] = []
     SKIPPED_FS_MODULES: Dict[str, Set[Tuple[ModuleType, str]]] = {}
 
-    assert None in SKIPMODULES, "sys.modules contains 'None' values;" " must skip them."
+    assert None in SKIPMODULES, "sys.modules contains 'None' values; must skip them."
 
     IS_WINDOWS = sys.platform in ("win32", "cygwin")
 
@@ -512,11 +564,12 @@ class Patcher:
         patch_open_code: PatchMode = PatchMode.OFF,
         patch_default_args: bool = False,
         use_cache: bool = True,
+        use_dynamic_patch: bool = True,
         is_doc_test: bool = False,
     ) -> None:
         """
         Args:
-            additional_skip_names: names of modules inside of which no module
+            additional_skip_names: names of modules where no module
                 replacement shall be performed, in addition to the names in
                 :py:attr:`fake_filesystem_unittest.Patcher.SKIPNAMES`.
                 Instead of the module names, the modules themselves
@@ -544,6 +597,9 @@ class Patcher:
                 cached between tests for performance reasons. As this is a new
                 feature, this argument allows to turn it off in case it
                 causes any problems.
+            use_dynamic_patch: If `True`, dynamic patching after setup is used
+                (for example for modules loaded locally inside of functions).
+                Can be switched off if it causes unwanted side effects.
         """
         self.is_doc_test = is_doc_test
         if is_doc_test:
@@ -556,18 +612,20 @@ class Patcher:
             set_uid(1)
             set_gid(1)
 
-        self._skip_names = self.SKIPNAMES.copy()
+        self.skip_names = self.SKIPNAMES.copy()
         # save the original open function for use in pytest plugin
         self.original_open = open
         self.patch_open_code = patch_open_code
-        self.fake_open: fake_open.FakeFileOpen
+        self.linecache_updatecache = None
+        self.linecache_checkcache = None
+        self.tempfile_patcher = TempfilePatcher()
 
         if additional_skip_names is not None:
             skip_names = [
                 cast(ModuleType, m).__name__ if inspect.ismodule(m) else cast(str, m)
                 for m in additional_skip_names
             ]
-            self._skip_names.update(skip_names)
+            self.skip_names.update(skip_names)
 
         self._fake_module_classes: Dict[str, Any] = {}
         self._unfaked_module_classes: Dict[str, Any] = {}
@@ -575,25 +633,27 @@ class Patcher:
         self._init_fake_module_classes()
 
         # reload tempfile under posix to patch default argument
-        self.modules_to_reload: List[ModuleType] = (
-            [] if sys.platform == "win32" else [tempfile]
-        )
+        self.modules_to_reload: List[ModuleType] = []
         if modules_to_reload is not None:
             self.modules_to_reload.extend(modules_to_reload)
         self.patch_default_args = patch_default_args
         self.use_cache = use_cache
+        self.use_dynamic_patch = use_dynamic_patch
+        self.cleanup_handlers: Dict[str, Callable[[str], bool]] = {}
 
         if use_known_patches:
             from pyfakefs.patched_packages import (
                 get_modules_to_patch,
                 get_classes_to_patch,
                 get_fake_module_classes,
+                get_cleanup_handlers,
             )
 
             modules_to_patch = modules_to_patch or {}
             modules_to_patch.update(get_modules_to_patch())
             self._class_modules.update(get_classes_to_patch())
             self._fake_module_classes.update(get_fake_module_classes())
+            self.cleanup_handlers.update(get_cleanup_handlers())
 
         if modules_to_patch is not None:
             for name, fake_module in modules_to_patch.items():
@@ -606,8 +666,8 @@ class Patcher:
             if patched_module_names != self.PATCHED_MODULE_NAMES:
                 self.__class__.PATCHED_MODULE_NAMES = patched_module_names
                 clear_cache = True
-            if self._skip_names != self.ADDITIONAL_SKIP_NAMES:
-                self.__class__.ADDITIONAL_SKIP_NAMES = self._skip_names
+            if self.skip_names != self.ADDITIONAL_SKIP_NAMES:
+                self.__class__.ADDITIONAL_SKIP_NAMES = self.skip_names
                 clear_cache = True
             if patch_default_args != self.PATCH_DEFAULT_ARGS:
                 self.__class__.PATCH_DEFAULT_ARGS = patch_default_args
@@ -628,6 +688,22 @@ class Patcher:
         self._isStale = True
         self._dyn_patcher: Optional[DynamicPatcher] = None
         self._patching = False
+        self._paused = False
+
+    def checkcache(self, filename=None):
+        """Calls the original linecache.checkcache making sure no fake OS calls
+        are used."""
+        with use_original_os():
+            return self.linecache_checkcache(filename)
+
+    def updatecache(self, filename, module_globals=None):
+        """Calls the original linecache.updatecache making sure no fake OS calls
+        are used."""
+        with use_original_os():
+            # workaround for updatecache problem with pytest under Windows, see #1096
+            if not filename.endswith(r"pytest.exe\__main__.py"):
+                return self.linecache_updatecache(filename, module_globals)
+            return []
 
     @classmethod
     def clear_fs_cache(cls) -> None:
@@ -642,6 +718,22 @@ class Patcher:
         """Clear the module cache (convenience instance method)."""
         self.__class__.clear_fs_cache()
 
+    def register_cleanup_handler(self, name: str, handler: Callable[[str], bool]):
+        """Register a handler for cleaning up a module after it had been loaded by
+        the dynamic patcher. This allows to handle modules that cannot be reloaded
+        without unwanted side effects.
+
+        Args:
+            name: The fully qualified module name.
+            handler: A callable that may do any module cleanup, or do nothing
+                and return `True` in case reloading shall be prevented.
+
+        Returns:
+            `True` if no further cleanup/reload shall occur after the handler is
+                executed, `False` if the cleanup/reload shall still happen.
+        """
+        self.cleanup_handlers[name] = handler
+
     def _init_fake_module_classes(self) -> None:
         # IMPORTANT TESTING NOTE: Whenever you add a new module below, test
         # it by adding an attribute in fixtures/module_with_attributes.py
@@ -653,9 +745,14 @@ class Patcher:
             "io": fake_io.FakeIoModule,
             "pathlib": fake_pathlib.FakePathlibModule,
         }
-        if IS_PYPY:
-            # in PyPy io.open, the module is referenced as _io
-            self._fake_module_classes["_io"] = fake_io.FakeIoModule
+        if sys.version_info >= (3, 13):
+            # for Python 3.13, we need both pathlib (path with __init__.py) and
+            # pathlib._local (has the actual implementation);
+            # depending on how pathlib is imported, either may be used
+            self._fake_module_classes["pathlib._local"] = fake_pathlib.FakePathlibModule
+        if IS_PYPY or sys.version_info >= (3, 12):
+            # in PyPy and later cpython versions, the module is referenced as _io
+            self._fake_module_classes["_io"] = fake_io.FakeIoModule2
         if sys.platform == "win32":
             self._fake_module_classes["nt"] = fake_path.FakeNtModule
         else:
@@ -665,15 +762,23 @@ class Patcher:
         # be contained in - this allows for alternative modules like
         # `pathlib` and `pathlib2`
         self._class_modules["Path"] = ["pathlib"]
+        if sys.version_info >= (3, 13):
+            self._class_modules["Path"].append("pathlib._local")
         self._unfaked_module_classes["pathlib"] = fake_pathlib.RealPathlibModule
+        if sys.version_info >= (3, 13):
+            self._unfaked_module_classes["pathlib._local"] = (
+                fake_pathlib.RealPathlibModule
+            )
         if pathlib2:
-            self._fake_module_classes["pathlib2"] = fake_pathlib.FakePathlibModule
+            self._fake_module_classes["pathlib2"] = (
+                fake_legacy_modules.FakePathlib2Module
+            )
             self._class_modules["Path"].append("pathlib2")
             self._unfaked_module_classes["pathlib2"] = fake_pathlib.RealPathlibModule
+        if scandir:
+            self._fake_module_classes["scandir"] = fake_legacy_modules.FakeScanDirModule
         self._fake_module_classes["Path"] = fake_pathlib.FakePathlibPathModule
         self._unfaked_module_classes["Path"] = fake_pathlib.RealPathlibPathModule
-        if use_scandir:
-            self._fake_module_classes["scandir"] = fake_scandir.FakeScanDirModule
 
     def _init_fake_module_functions(self) -> None:
         # handle patching function imported separately like
@@ -697,12 +802,12 @@ class Patcher:
         fake_module = fake_filesystem.FakePathModule
         for fct_name in fake_module.dir():
             module_attr = (getattr(fake_module, fct_name), PATH_MODULE)
-            self._fake_module_functions.setdefault(fct_name, {})[
-                "genericpath"
-            ] = module_attr
-            self._fake_module_functions.setdefault(fct_name, {})[
-                PATH_MODULE
-            ] = module_attr
+            self._fake_module_functions.setdefault(fct_name, {})["genericpath"] = (
+                module_attr
+            )
+            self._fake_module_functions.setdefault(fct_name, {})[PATH_MODULE] = (
+                module_attr
+            )
 
     def __enter__(self) -> "Patcher":
         """Context manager for usage outside of
@@ -804,10 +909,14 @@ class Patcher:
                 # see https://github.com/pytest-dev/py/issues/73
                 # and any other exception triggered by inspect.ismodule
                 if self.use_cache:
-                    self.__class__.CACHED_MODULES.add(module)
+                    try:
+                        self.__class__.CACHED_MODULES.add(module)
+                    except TypeError:
+                        # unhashable module - don't cache it
+                        pass
                 continue
             skipped = module in self.SKIPMODULES or any(
-                [sn.startswith(module.__name__) for sn in self._skip_names]
+                [sn.startswith(module.__name__) for sn in self.skip_names]
             )
             module_items = module.__dict__.copy().items()
 
@@ -851,11 +960,10 @@ class Patcher:
 
         self.fs = fake_filesystem.FakeFilesystem(patcher=self, create_temp_dir=True)
         self.fs.patch_open_code = self.patch_open_code
-        self.fake_open = fake_open.FakeFileOpen(self.fs)
         for name in self._fake_module_classes:
             self.fake_modules[name] = self._fake_module_classes[name](self.fs)
             if hasattr(self.fake_modules[name], "skip_names"):
-                self.fake_modules[name].skip_names = self._skip_names
+                self.fake_modules[name].skip_names = self.skip_names
         self.fake_modules[PATH_MODULE] = self.fake_modules["os"].path
         for name in self._unfaked_module_classes:
             self.unfaked_modules[name] = self._unfaked_module_classes[name]()
@@ -882,6 +990,15 @@ class Patcher:
         if self.has_fcopy_file:
             shutil._HAS_FCOPYFILE = False  # type: ignore[attr-defined]
 
+        # do not use the fd functions, as they may not be available in the target OS
+        if hasattr(shutil, "_use_fd_functions"):
+            shutil._use_fd_functions = False  # type: ignore[module-attr]
+        # in Python 3.14, _rmtree_impl is set at load time based on _use_fd_functions
+        # the safe version cannot be used at the moment as it used asserts of type
+        # 'assert func is os.rmtree', which do not work with the fake versions
+        if hasattr(shutil, "_rmtree_impl"):
+            shutil._rmtree_impl = shutil._rmtree_unsafe  # type: ignore[attr-defined]
+
         with warnings.catch_warnings():
             # ignore warnings, see #542 and #614
             warnings.filterwarnings("ignore")
@@ -899,16 +1016,38 @@ class Patcher:
     def start_patching(self) -> None:
         if not self._patching:
             self._patching = True
+            self._paused = False
+
+            if sys.version_info >= (3, 12):
+                # in linecache, 'os' is now imported locally, which involves the
+                # dynamic patcher, therefore we patch the affected functions
+                self.linecache_updatecache = linecache.updatecache
+                linecache.updatecache = self.updatecache
+                self.linecache_checkcache = linecache.checkcache
+                linecache.checkcache = self.checkcache
+
+            self.tempfile_patcher.start_patching()
 
             self.patch_modules()
             self.patch_functions()
             self.patch_defaults()
+            self._set_glob_os_functions()
 
             self._dyn_patcher = DynamicPatcher(self)
             sys.meta_path.insert(0, self._dyn_patcher)
             for module in self.modules_to_reload:
                 if sys.modules.get(module.__name__) is module:
                     reload(module)
+            if not self.use_dynamic_patch:
+                self._dyn_patcher.cleanup()
+                sys.meta_path.pop(0)
+
+    def _set_glob_os_functions(self):
+        # make sure the os functions cached in glob are patched
+        if sys.version_info >= (3, 13):
+            globber = glob._StringGlobber  # type: ignore[module-attr]
+            globber.lstat = staticmethod(os.lstat)
+            globber.scandir = staticmethod(os.scandir)
 
     def patch_functions(self) -> None:
         assert self._stubs is not None
@@ -922,17 +1061,30 @@ class Patcher:
                 self._stubs.smart_set(module, name, attr)
 
     def patch_modules(self) -> None:
+        skip_prefix_list = []
+        for rt_skip_module, prefixes in self.RUNTIME_SKIPMODULES.items():
+            if rt_skip_module in sys.modules:
+                skip_prefix_list.extend(prefixes)
+        skip_prefixes = tuple(skip_prefix_list)
+
         assert self._stubs is not None
         for name, modules in self.FS_MODULES.items():
             for module, attr in modules:
-                self._stubs.smart_set(module, name, self.fake_modules[attr])
+                try:
+                    if not skip_prefixes or not module.__name__.startswith(
+                        skip_prefixes
+                    ):
+                        self._stubs.smart_set(module, name, self.fake_modules[attr])
+                    elif attr in self.unfaked_modules:
+                        self._stubs.smart_set(module, name, self.unfaked_modules[attr])
+                except Exception:
+                    # handle the rare case that a module has no __name__
+                    pass
+
         for name, modules in self.SKIPPED_FS_MODULES.items():
             for module, attr in modules:
                 if attr in self.unfaked_modules:
                     self._stubs.smart_set(module, name, self.unfaked_modules[attr])
-        if sys.version_info >= (3, 12):
-            # workaround for patching open - does not work with skip modules
-            self._stubs.smart_set(builtins, "open", self.fake_open)
 
     def patch_defaults(self) -> None:
         for fct, idx, ft in self.FS_DEFARGS:
@@ -979,16 +1131,26 @@ class Patcher:
         else:
             self.__class__.PATCHER = None
 
-    def stop_patching(self) -> None:
+    def stop_patching(self, temporary=False) -> None:
         if self._patching:
             self._isStale = True
             self._patching = False
+            self._paused = temporary
             if self._stubs:
                 self._stubs.smart_unset_all()
             self.unset_defaults()
-            if self._dyn_patcher:
+            if self.use_dynamic_patch and self._dyn_patcher:
                 self._dyn_patcher.cleanup()
                 sys.meta_path.pop(0)
+            self.tempfile_patcher.stop_patching()
+            if self.linecache_updatecache is not None:
+                linecache.updatecache = self.linecache_updatecache
+                linecache.checkcache = self.linecache_checkcache
+            self._set_glob_os_functions()
+
+    @property
+    def is_patching(self):
+        return self._patching
 
     def unset_defaults(self) -> None:
         for fct, idx, ft in self.FS_DEFARGS:
@@ -1007,7 +1169,7 @@ class Patcher:
         Calling pause() twice is silently ignored.
 
         """
-        self.stop_patching()
+        self.stop_patching(temporary=True)
 
     def resume(self) -> None:
         """Resume the patching of the file system modules if `pause` has
@@ -1015,13 +1177,14 @@ class Patcher:
         executed in the fake file system.
         Does nothing if patching is not paused.
         """
-        self.start_patching()
+        if self._paused:
+            self.start_patching()
 
 
 class Pause:
     """Simple context manager that allows to pause/resume patching the
     filesystem. Patching is paused in the context manager, and resumed after
-    going out of it's scope.
+    going out of its scope.
     """
 
     def __init__(self, caller: Union[Patcher, TestCaseMixin, FakeFilesystem]):
@@ -1063,6 +1226,7 @@ class DynamicPatcher(MetaPathFinder, Loader):
         self.sysmodules = {}
         self.modules = self._patcher.fake_modules
         self._loaded_module_names: Set[str] = set()
+        self.cleanup_handlers = patcher.cleanup_handlers
 
         # remove all modules that have to be patched from `sys.modules`,
         # otherwise the find_... methods will not be called
@@ -1083,15 +1247,16 @@ class DynamicPatcher(MetaPathFinder, Loader):
         reloaded_module_names = [
             module.__name__ for module in self._patcher.modules_to_reload
         ]
-        # Dereference all modules loaded during the test so they will reload on
-        # the next use, ensuring that no faked modules are referenced after the
-        # test.
+        # Delete all modules loaded during the test, ensuring that
+        # they are reloaded after the test.
         for name in self._loaded_module_names:
             if name in sys.modules and name not in reloaded_module_names:
+                if name in self.cleanup_handlers and self.cleanup_handlers[name](name):
+                    continue
                 del sys.modules[name]
 
     def needs_patch(self, name: str) -> bool:
-        """Check if the module with the given name shall be replaced."""
+        """Checks if the module with the given name shall be replaced."""
         if name not in self.modules:
             self._loaded_module_names.add(name)
             return False
@@ -1099,6 +1264,24 @@ class DynamicPatcher(MetaPathFinder, Loader):
             return False
         return True
 
+    def fake_module_path(self, name: str) -> str:
+        """Checks if the module with the given name is a module existing in the fake
+        filesystem and returns its path in this case.
+        """
+        fs = self._patcher.fs
+        # we assume that the module name is the absolute module path
+        if fs is not None:
+            base_path = name.replace(".", fs.path_separator)
+            for path in sys.path:
+                module_path = fs.joinpaths(path, base_path)
+                py_module_path = module_path + ".py"
+                if fs.exists(py_module_path):
+                    return fs.absnormpath(py_module_path)
+                init_path = fs.joinpaths(module_path, "__init__.py")
+                if fs.exists(init_path):
+                    return fs.absnormpath(init_path)
+        return ""
+
     def find_spec(
         self,
         fullname: str,
@@ -1108,6 +1291,15 @@ class DynamicPatcher(MetaPathFinder, Loader):
         """Module finder."""
         if self.needs_patch(fullname):
             return ModuleSpec(fullname, self)
+        if self._patcher.patch_open_code != PatchMode.OFF:
+            # handle modules created in the fake filesystem
+            module_path = self.fake_module_path(fullname)
+            if module_path:
+                spec = spec_from_file_location(fullname, module_path)
+                if spec:
+                    module = module_from_spec(spec)
+                    sys.modules[fullname] = module
+                    return ModuleSpec(fullname, self)
         return None
 
     def load_module(self, fullname: str) -> ModuleType:
diff --git a/pyfakefs/fake_io.py b/pyfakefs/fake_io.py
index fc719ad..6d5b67c 100644
--- a/pyfakefs/fake_io.py
+++ b/pyfakefs/fake_io.py
@@ -12,13 +12,13 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
-""" Uses :py:class:`FakeIoModule` to provide a
-    fake ``io`` module replacement.
+"""Uses :py:class:`FakeIoModule` to provide a
+fake ``io`` module replacement.
 """
+
+import _io  # pytype: disable=import-error
 import io
-import os
 import sys
-import traceback
 from enum import Enum
 from typing import (
     List,
@@ -32,8 +32,8 @@ from typing import (
 )
 
 from pyfakefs.fake_file import AnyFileWrapper
-from pyfakefs.fake_open import FakeFileOpen
-from pyfakefs.helpers import IS_PYPY
+from pyfakefs.fake_open import fake_open
+from pyfakefs.helpers import IS_PYPY, is_called_from_skipped_module
 
 if TYPE_CHECKING:
     from pyfakefs.fake_filesystem import FakeFilesystem
@@ -90,32 +90,17 @@ class FakeIoModule:
         """Redirect the call to FakeFileOpen.
         See FakeFileOpen.call() for description.
         """
-        # workaround for built-in open called from skipped modules (see #552)
-        # as open is not imported explicitly, we cannot patch it for
-        # specific modules; instead we check if the caller is a skipped
-        # module (should work in most cases)
-        stack = traceback.extract_stack(limit=2)
-        module_name = os.path.splitext(stack[0].filename)[0]
-        module_name = module_name.replace(os.sep, ".")
-        if any(
-            [
-                module_name == sn or module_name.endswith("." + sn)
-                for sn in self.skip_names
-            ]
-        ):
-            return io.open(  # pytype: disable=wrong-arg-count
-                file,
-                mode,
-                buffering,
-                encoding,
-                errors,
-                newline,
-                closefd,
-                opener,
-            )
-        fake_open = FakeFileOpen(self.filesystem)
         return fake_open(
-            file, mode, buffering, encoding, errors, newline, closefd, opener
+            self.filesystem,
+            self.skip_names,
+            file,
+            mode,
+            buffering,
+            encoding,
+            errors,
+            newline,
+            closefd,
+            opener,
         )
 
     if sys.version_info >= (3, 8):
@@ -143,6 +128,18 @@ class FakeIoModule:
         return getattr(self._io_module, name)
 
 
+class FakeIoModule2(FakeIoModule):
+    """Similar to ``FakeIoModule``, but fakes `_io` instead of `io`."""
+
+    def __init__(self, filesystem: "FakeFilesystem"):
+        """
+        Args:
+            filesystem: FakeFilesystem used to provide file system information.
+        """
+        super().__init__(filesystem)
+        self._io_module = _io
+
+
 if sys.platform != "win32":
     import fcntl
 
@@ -183,6 +180,20 @@ if sys.platform != "win32":
         ) -> Any:
             pass
 
+        def __getattribute__(self, name):
+            """Prevents patching of skipped modules."""
+            fs: FakeFilesystem = object.__getattribute__(self, "filesystem")
+            fnctl_module = object.__getattribute__(self, "_fcntl_module")
+            if fs.patcher:
+                if is_called_from_skipped_module(
+                    skip_names=fs.patcher.skip_names,
+                    case_sensitive=fs.is_case_sensitive,
+                ):
+                    # remove the `self` argument for FakeOsModule methods
+                    return getattr(fnctl_module, name)
+
+            return object.__getattribute__(self, name)
+
         def __getattr__(self, name):
             """Forwards any unfaked calls to the standard fcntl module."""
             return getattr(self._fcntl_module, name)
diff --git a/pyfakefs/fake_legacy_modules.py b/pyfakefs/fake_legacy_modules.py
new file mode 100644
index 0000000..7c25b98
--- /dev/null
+++ b/pyfakefs/fake_legacy_modules.py
@@ -0,0 +1,110 @@
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
+import warnings
+
+
+from pyfakefs.fake_pathlib import FakePathlibModule
+from pyfakefs.fake_scandir import scandir, walk
+
+
+def legacy_warning(module_name):
+    msg = (
+        f"You are using the legacy package '{module_name}' instead of the "
+        f"built-in module."
+        "Patching this package will no longer be supported in pyfakefs >= 6"
+    )
+    warnings.warn(msg, category=DeprecationWarning)
+
+
+class FakePathlib2Module(FakePathlibModule):
+    """Uses FakeFilesystem to provide a fake pathlib module replacement.
+    for the `pathlib2` package available on PyPi.
+    The usage of `pathlib2` is deprecated and will no longer be supported
+    in future pyfakefs versions.
+    """
+
+    has_warned = False
+
+    def __getattribute__(self, name):
+        attr = object.__getattribute__(self, name)
+        if hasattr(attr, "__call__") and not FakePathlib2Module.has_warned:
+            FakePathlib2Module.has_warned = True
+            legacy_warning("pathlib2")
+        return attr
+
+
+class FakeScanDirModule:
+    """Uses FakeFilesystem to provide a fake module replacement
+    for the `scandir` package available on PyPi.
+
+    The usage of the `scandir` package is deprecated and will no longer be supported
+    in future pyfakefs versions.
+
+    You need a fake_filesystem to use this:
+    `filesystem = fake_filesystem.FakeFilesystem()`
+    `fake_scandir_module = fake_filesystem.FakeScanDirModule(filesystem)`
+    """
+
+    @staticmethod
+    def dir():
+        """Return the list of patched function names. Used for patching
+        functions imported from the module.
+        """
+        return "scandir", "walk"
+
+    def __init__(self, filesystem):
+        self.filesystem = filesystem
+
+    has_warned = False
+
+    def scandir(self, path="."):
+        """Return an iterator of DirEntry objects corresponding to the entries
+        in the directory given by path.
+
+        Args:
+            path: Path to the target directory within the fake filesystem.
+
+        Returns:
+            an iterator to an unsorted list of os.DirEntry objects for
+            each entry in path.
+
+        Raises:
+            OSError: if the target is not a directory.
+        """
+        if not self.has_warned:
+            self.__class__.has_warned = True
+            legacy_warning("scandir")
+        return scandir(self.filesystem, path)
+
+    def walk(self, top, topdown=True, onerror=None, followlinks=False):
+        """Perform a walk operation over the fake filesystem.
+
+        Args:
+            top: The root directory from which to begin walk.
+            topdown: Determines whether to return the tuples with the root as
+                the first entry (`True`) or as the last, after all the child
+                directory tuples (`False`).
+            onerror: If not `None`, function which will be called to handle the
+                `os.error` instance provided when `os.listdir()` fails.
+            followlinks: If `True`, symbolic links are followed.
+
+        Yields:
+            (path, directories, nondirectories) for top and each of its
+            subdirectories.  See the documentation for the builtin os module
+            for further details.
+        """
+        if not self.has_warned:
+            self.__class__.has_warned = True
+            legacy_warning("scandir")
+
+        return walk(self.filesystem, top, topdown, onerror, followlinks)
diff --git a/pyfakefs/fake_open.py b/pyfakefs/fake_open.py
index 912ada9..04c521d 100644
--- a/pyfakefs/fake_open.py
+++ b/pyfakefs/fake_open.py
@@ -12,12 +12,12 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
-"""A fake open() function replacement. See ``fake_filesystem`` for usage.
-"""
+"""A fake open() function replacement. See ``fake_filesystem`` for usage."""
+
 import errno
+import io
 import os
 import sys
-from collections import namedtuple
 from stat import (
     S_ISDIR,
 )
@@ -29,6 +29,9 @@ from typing import (
     cast,
     AnyStr,
     TYPE_CHECKING,
+    Callable,
+    IO,
+    List,
 )
 
 from pyfakefs import helpers
@@ -40,19 +43,19 @@ from pyfakefs.fake_file import (
 )
 from pyfakefs.helpers import (
     AnyString,
+    is_called_from_skipped_module,
     is_root,
     PERM_READ,
     PERM_WRITE,
+    _OpenModes,
 )
 
 if TYPE_CHECKING:
     from pyfakefs.fake_filesystem import FakeFilesystem
 
 
-_OpenModes = namedtuple(
-    "_OpenModes",
-    "must_exist can_read can_write truncate append must_not_exist",
-)
+# Work around pyupgrade auto-rewriting `io.open()` to `open()`.
+io_open = io.open
 
 _OPEN_MODE_MAP = {
     # mode name:(file must exist, can read, can write,
@@ -68,6 +71,42 @@ _OPEN_MODE_MAP = {
 }
 
 
+def fake_open(
+    filesystem: "FakeFilesystem",
+    skip_names: List[str],
+    file: Union[AnyStr, int],
+    mode: str = "r",
+    buffering: int = -1,
+    encoding: Optional[str] = None,
+    errors: Optional[str] = None,
+    newline: Optional[str] = None,
+    closefd: bool = True,
+    opener: Optional[Callable] = None,
+) -> Union[AnyFileWrapper, IO[Any]]:
+    """Redirect the call to FakeFileOpen.
+    See FakeFileOpen.call() for description.
+    """
+    if is_called_from_skipped_module(
+        skip_names=skip_names,
+        case_sensitive=filesystem.is_case_sensitive,
+        check_open_code=sys.version_info >= (3, 12),
+    ):
+        return io_open(  # pytype: disable=wrong-arg-count
+            file,
+            mode,
+            buffering,
+            encoding,
+            errors,
+            newline,
+            closefd,
+            opener,
+        )
+    fake_file_open = FakeFileOpen(filesystem)
+    return fake_file_open(
+        file, mode, buffering, encoding, errors, newline, closefd, opener
+    )
+
+
 class FakeFileOpen:
     """Faked `file()` and `open()` function replacements.
 
@@ -148,16 +187,22 @@ class FakeFileOpen:
             raise ValueError("binary mode doesn't take an encoding argument")
 
         newline, open_modes = self._handle_file_mode(mode, newline, open_modes)
+        opened_as_fd = isinstance(file_, int)
 
         # the pathlib opener is defined in a Path instance that may not be
         # patched under some circumstances; as it just calls standard open(),
         # we may ignore it, as it would not change the behavior
-        if opener is not None and opener.__module__ != "pathlib":
+        if opener is not None and opener.__module__ not in (
+            "pathlib",
+            "pathlib._local",
+        ):
             # opener shall return a file descriptor, which will be handled
             # here as if directly passed
             file_ = opener(file_, self._open_flags_from_open_modes(open_modes))
 
-        file_object, file_path, filedes, real_path = self._handle_file_arg(file_)
+        file_object, file_path, filedes, real_path, can_write = self._handle_file_arg(
+            file_
+        )
         if file_object is None and file_path is None:
             # file must be a fake pipe wrapper, find it...
             if (
@@ -176,7 +221,7 @@ class FakeFileOpen:
                 existing_wrapper.can_write,
                 mode,
             )
-            file_des = self.filesystem._add_open_file(wrapper)
+            file_des = self.filesystem.add_open_file(wrapper)
             wrapper.filedes = file_des
             return wrapper
 
@@ -197,7 +242,11 @@ class FakeFileOpen:
 
         assert real_path is not None
         file_object = self._init_file_object(
-            file_object, file_path, open_modes, real_path
+            file_object,
+            file_path,
+            open_modes,
+            real_path,
+            check_file_permission=not opened_as_fd,
         )
 
         if S_ISDIR(file_object.st_mode):
@@ -218,7 +267,7 @@ class FakeFileOpen:
         fakefile = FakeFileWrapper(
             file_object,
             file_path,
-            update=open_modes.can_write,
+            update=open_modes.can_write and can_write,
             read=open_modes.can_read,
             append=open_modes.append,
             delete_on_close=self._delete_on_close,
@@ -230,6 +279,7 @@ class FakeFileOpen:
             errors=errors,
             buffering=buffering,
             raw_io=self.raw_io,
+            opened_as_fd=opened_as_fd,
         )
         if filedes is not None:
             fakefile.filedes = filedes
@@ -238,7 +288,7 @@ class FakeFileOpen:
             assert open_files_list is not None
             open_files_list.append(fakefile)
         else:
-            fakefile.filedes = self.filesystem._add_open_file(fakefile)
+            fakefile.filedes = self.filesystem.add_open_file(fakefile)
         return fakefile
 
     @staticmethod
@@ -267,11 +317,19 @@ class FakeFileOpen:
         file_path: AnyStr,
         open_modes: _OpenModes,
         real_path: AnyString,
+        check_file_permission: bool,
     ) -> FakeFile:
         if file_object:
-            if not is_root() and (
-                (open_modes.can_read and not file_object.st_mode & PERM_READ)
-                or (open_modes.can_write and not file_object.st_mode & PERM_WRITE)
+            if (
+                check_file_permission
+                and not is_root()
+                and (
+                    (open_modes.can_read and not file_object.has_permission(PERM_READ))
+                    or (
+                        open_modes.can_write
+                        and not file_object.has_permission(PERM_WRITE)
+                    )
+                )
             ):
                 self.filesystem.raise_os_error(errno.EACCES, file_path)
             if open_modes.can_write:
@@ -304,29 +362,35 @@ class FakeFileOpen:
 
     def _handle_file_arg(
         self, file_: Union[AnyStr, int]
-    ) -> Tuple[Optional[FakeFile], Optional[AnyStr], Optional[int], Optional[AnyStr]]:
+    ) -> Tuple[
+        Optional[FakeFile], Optional[AnyStr], Optional[int], Optional[AnyStr], bool
+    ]:
         file_object = None
         if isinstance(file_, int):
             # opening a file descriptor
             filedes: int = file_
             wrapper = self.filesystem.get_open_file(filedes)
+            can_write = True
             if isinstance(wrapper, FakePipeWrapper):
-                return None, None, filedes, None
+                return None, None, filedes, None, can_write
             if isinstance(wrapper, FakeFileWrapper):
                 self._delete_on_close = wrapper.delete_on_close
+                can_write = wrapper.allow_update
+
             file_object = cast(
                 FakeFile, self.filesystem.get_open_file(filedes).get_object()
             )
             assert file_object is not None
             path = file_object.name
-            return (
+            return (  # pytype: disable=bad-return-type
                 file_object,
                 cast(AnyStr, path),  # pytype: disable=invalid-annotation
                 filedes,
                 cast(AnyStr, path),  # pytype: disable=invalid-annotation
+                can_write,
             )
 
-        # open a file file by path
+        # open a file by path
         file_path = cast(AnyStr, file_)  # pytype: disable=invalid-annotation
         if file_path == self.filesystem.dev_null.name:
             file_object = self.filesystem.dev_null
@@ -337,7 +401,7 @@ class FakeFileOpen:
                 file_object = self.filesystem.get_object_from_normpath(
                     real_path, check_read_perm=False
                 )
-        return file_object, file_path, None, real_path
+        return file_object, file_path, None, real_path, True
 
     def _handle_file_mode(
         self,
diff --git a/pyfakefs/fake_os.py b/pyfakefs/fake_os.py
index ba19bf8..83c4011 100644
--- a/pyfakefs/fake_os.py
+++ b/pyfakefs/fake_os.py
@@ -12,9 +12,10 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
-""" Uses :py:class:`FakeOsModule` to provide a
-    fake :py:mod:`os` module replacement.
+"""Uses :py:class:`FakeOsModule` to provide a
+fake :py:mod:`os` module replacement.
 """
+
 import errno
 import functools
 import inspect
@@ -39,7 +40,6 @@ from typing import (
     Set,
 )
 
-from pyfakefs.extra_packages import use_scandir
 from pyfakefs.fake_file import (
     FakeDirectory,
     FakeDirWrapper,
@@ -54,6 +54,7 @@ from pyfakefs.fake_path import FakePathModule
 from pyfakefs.fake_scandir import scandir, walk, ScanDirIter
 from pyfakefs.helpers import (
     FakeStatResult,
+    is_called_from_skipped_module,
     is_int_type,
     is_byte_string,
     make_string_path,
@@ -101,12 +102,15 @@ class FakeOsModule:
             "chmod",
             "chown",
             "close",
+            "dup",
+            "dup2",
             "fstat",
             "fsync",
             "getcwd",
             "lchmod",
             "link",
             "listdir",
+            "lseek",
             "lstat",
             "makedirs",
             "mkdir",
@@ -118,6 +122,7 @@ class FakeOsModule:
             "removedirs",
             "rename",
             "rmdir",
+            "scandir",
             "stat",
             "symlink",
             "umask",
@@ -141,8 +146,6 @@ class FakeOsModule:
                 "getgid",
                 "getuid",
             ]
-        if use_scandir:
-            _dir += ["scandir"]
         return _dir
 
     def __init__(self, filesystem: "FakeFilesystem"):
@@ -207,7 +210,7 @@ class FakeOsModule:
             return 0o002
         else:
             # under Unix, we return the real umask;
-            # as there is no pure getter for umask, so we have to first
+            # there is no pure getter for umask, so we have to first
             # set a mode to get the previous one and then re-set that
             mask = os.umask(0)
             os.umask(mask)
@@ -219,7 +222,7 @@ class FakeOsModule:
         flags: int,
         mode: Optional[int] = None,
         *,
-        dir_fd: Optional[int] = None
+        dir_fd: Optional[int] = None,
     ) -> int:
         """Return the file descriptor for a FakeFile.
 
@@ -247,6 +250,22 @@ class FakeOsModule:
             else:
                 mode = 0o777 & ~self._umask()
 
+        has_directory_flag = (
+            hasattr(os, "O_DIRECTORY") and flags & os.O_DIRECTORY == os.O_DIRECTORY
+        )
+        if (
+            has_directory_flag
+            and self.filesystem.exists(path)
+            and not self.filesystem.isdir(path)
+        ):
+            raise OSError(errno.ENOTDIR, "path is not a directory", path)
+
+        has_follow_flag = (
+            hasattr(os, "O_NOFOLLOW") and flags & os.O_NOFOLLOW == os.O_NOFOLLOW
+        )
+        if has_follow_flag and self.filesystem.islink(path):
+            raise OSError(errno.ELOOP, "path is a symlink", path)
+
         has_tmpfile_flag = (
             hasattr(os, "O_TMPFILE") and flags & os.O_TMPFILE == os.O_TMPFILE
         )
@@ -278,7 +297,7 @@ class FakeOsModule:
                 ) or open_modes.can_write:
                     self.filesystem.raise_os_error(errno.EISDIR, path)
                 dir_wrapper = FakeDirWrapper(obj, path, self.filesystem)
-                file_des = self.filesystem._add_open_file(dir_wrapper)
+                file_des = self.filesystem.add_open_file(dir_wrapper)
                 dir_wrapper.filedes = file_des
                 return file_des
 
@@ -306,7 +325,17 @@ class FakeOsModule:
             TypeError: if file descriptor is not an integer.
         """
         file_handle = self.filesystem.get_open_file(fd)
-        file_handle.close()
+        file_handle.close_fd(fd)
+
+    def dup(self, fd: int) -> int:
+        file_handle = self.filesystem.get_open_file(fd)
+        return self.filesystem.add_open_file(file_handle)
+
+    def dup2(self, fd: int, fd2: int, inheritable: bool = True) -> int:
+        if fd == fd2:
+            return fd
+        file_handle = self.filesystem.get_open_file(fd)
+        return self.filesystem.add_open_file(file_handle, fd2)
 
     def read(self, fd: int, n: int) -> bytes:
         """Read number of bytes from a file descriptor, returns bytes read.
@@ -357,13 +386,20 @@ class FakeOsModule:
         file_handle.flush()
         return len(contents)
 
+    def lseek(self, fd: int, pos: int, whence: int):
+        file_handle = self.filesystem.get_open_file(fd)
+        if isinstance(file_handle, FakeFileWrapper):
+            file_handle.seek(pos, whence)
+        else:
+            raise OSError(errno.EBADF, "Bad file descriptor for fseek")
+
     def pipe(self) -> Tuple[int, int]:
         read_fd, write_fd = os.pipe()
         read_wrapper = FakePipeWrapper(self.filesystem, read_fd, False)
-        file_des = self.filesystem._add_open_file(read_wrapper)
+        file_des = self.filesystem.add_open_file(read_wrapper)
         read_wrapper.filedes = file_des
         write_wrapper = FakePipeWrapper(self.filesystem, write_fd, True)
-        file_des = self.filesystem._add_open_file(write_wrapper)
+        file_des = self.filesystem.add_open_file(write_wrapper)
         write_wrapper.filedes = file_des
         return read_wrapper.filedes, write_wrapper.filedes
 
@@ -422,7 +458,7 @@ class FakeOsModule:
         directory = self.filesystem.resolve(path)
         # A full implementation would check permissions all the way
         # up the tree.
-        if not is_root() and not directory.st_mode | PERM_EXE:
+        if not is_root() and not directory.has_permission(PERM_EXE):
             self.filesystem.raise_os_error(errno.EACCES, directory.name)
         self.filesystem.cwd = path  # type: ignore[assignment]
 
@@ -460,8 +496,7 @@ class FakeOsModule:
         `path`.
 
         Args:
-            path: File path, file descriptor or path-like object (for
-                Python >= 3.6).
+            path: File path, file descriptor or path-like object.
             attribute: (str or bytes) The attribute name.
             follow_symlinks: (bool) If True (the default), symlinks in the
                 path are traversed.
@@ -479,6 +514,8 @@ class FakeOsModule:
         if isinstance(attribute, bytes):
             attribute = attribute.decode(sys.getfilesystemencoding())
         file_obj = self.filesystem.resolve(path, follow_symlinks, allow_fd=True)
+        if attribute not in file_obj.xattr:
+            raise OSError(errno.ENODATA, "No data available", path)
         return file_obj.xattr.get(attribute)
 
     def listxattr(
@@ -487,8 +524,8 @@ class FakeOsModule:
         """Return a list of the extended filesystem attributes on `path`.
 
         Args:
-            path: File path, file descriptor or path-like object (for
-                Python >= 3.6). If None, the current directory is used.
+            path: File path, file descriptor or path-like object.
+               If None, the current directory is used.
             follow_symlinks: (bool) If True (the default), symlinks in the
                 path are traversed.
 
@@ -512,11 +549,10 @@ class FakeOsModule:
     def removexattr(
         self, path: AnyStr, attribute: AnyString, *, follow_symlinks: bool = True
     ) -> None:
-        """Removes the extended filesystem attribute attribute from `path`.
+        """Removes the extended filesystem attribute from `path`.
 
         Args:
-            path: File path, file descriptor or path-like object (for
-                Python >= 3.6).
+            path: File path, file descriptor or path-like object
             attribute: (str or bytes) The attribute name.
             follow_symlinks: (bool) If True (the default), symlinks in the
                 path are traversed.
@@ -540,14 +576,13 @@ class FakeOsModule:
         value: bytes,
         flags: int = 0,
         *,
-        follow_symlinks: bool = True
+        follow_symlinks: bool = True,
     ) -> None:
         """Sets the value of the given extended filesystem attribute for
         `path`.
 
         Args:
-            path: File path, file descriptor or path-like object (for
-                Python >= 3.6).
+            path: File path, file descriptor or path-like object.
             attribute: The attribute name (str or bytes).
             value: (byte-like) The value to be set.
             follow_symlinks: (bool) If True (the default), symlinks in the
@@ -637,7 +672,7 @@ class FakeOsModule:
         path: AnyStr,
         *,
         dir_fd: Optional[int] = None,
-        follow_symlinks: bool = True
+        follow_symlinks: bool = True,
     ) -> FakeStatResult:
         """Return the os.stat-like tuple for the FakeFile object of entry_path.
 
@@ -674,7 +709,7 @@ class FakeOsModule:
             OSError: if the filesystem object doesn't exist.
         """
         # stat should return the tuple representing return value of os.stat
-        path = self._path_with_dir_fd(path, self.lstat, dir_fd)
+        path = self._path_with_dir_fd(path, self.lstat, dir_fd, check_supported=False)
         return self.filesystem.stat(path, follow_symlinks=False)
 
     def remove(self, path: AnyStr, dir_fd: Optional[int] = None) -> None:
@@ -690,7 +725,7 @@ class FakeOsModule:
             OSError: if path does not exist.
             OSError: if removal failed.
         """
-        path = self._path_with_dir_fd(path, self.remove, dir_fd)
+        path = self._path_with_dir_fd(path, self.remove, dir_fd, check_supported=False)
         self.filesystem.remove(path)
 
     def unlink(self, path: AnyStr, *, dir_fd: Optional[int] = None) -> None:
@@ -715,7 +750,7 @@ class FakeOsModule:
         dst: AnyStr,
         *,
         src_dir_fd: Optional[int] = None,
-        dst_dir_fd: Optional[int] = None
+        dst_dir_fd: Optional[int] = None,
     ) -> None:
         """Rename a FakeFile object at old_file_path to new_file_path,
         preserving all properties.
@@ -777,7 +812,7 @@ class FakeOsModule:
         dst: AnyStr,
         *,
         src_dir_fd: Optional[int] = None,
-        dst_dir_fd: Optional[int] = None
+        dst_dir_fd: Optional[int] = None,
     ) -> None:
         """Renames a FakeFile object at old_file_path to new_file_path,
         preserving all properties.
@@ -801,8 +836,12 @@ class FakeOsModule:
             OSError: if the file would be moved to another filesystem
                 (e.g. mount point)
         """
-        src = self._path_with_dir_fd(src, self.rename, src_dir_fd)
-        dst = self._path_with_dir_fd(dst, self.rename, dst_dir_fd)
+        src = self._path_with_dir_fd(
+            src, self.rename, src_dir_fd, check_supported=False
+        )
+        dst = self._path_with_dir_fd(
+            dst, self.rename, dst_dir_fd, check_supported=False
+        )
         self.filesystem.rename(src, dst, force_replace=True)
 
     def rmdir(self, path: AnyStr, *, dir_fd: Optional[int] = None) -> None:
@@ -891,10 +930,34 @@ class FakeOsModule:
         """
         if exist_ok is None:
             exist_ok = False
-        self.filesystem.makedirs(name, mode, exist_ok)
+
+        # copied and adapted from real implementation in os.py (Python 3.12)
+        head, tail = self.filesystem.splitpath(name)
+        if not tail:
+            head, tail = self.filesystem.splitpath(head)
+        if head and tail and not self.filesystem.exists(head):
+            try:
+                self.makedirs(head, exist_ok=exist_ok)
+            except FileExistsError:
+                pass
+            cdir = self.filesystem.cwd
+            if isinstance(tail, bytes):
+                if tail == bytes(cdir, "ASCII"):
+                    return
+            elif tail == cdir:
+                return
+        try:
+            self.mkdir(name, mode)
+        except OSError:
+            if not exist_ok or not self.filesystem.isdir(name):
+                raise
 
     def _path_with_dir_fd(
-        self, path: AnyStr, fct: Callable, dir_fd: Optional[int]
+        self,
+        path: AnyStr,
+        fct: Callable,
+        dir_fd: Optional[int],
+        check_supported: bool = True,
     ) -> AnyStr:
         """Return the path considering dir_fd. Raise on invalid parameters."""
         try:
@@ -904,12 +967,11 @@ class FakeOsModule:
             path = path
         if dir_fd is not None:
             # check if fd is supported for the built-in real function
-            if fct not in self.supports_dir_fd:
+            if check_supported and (fct not in self.supports_dir_fd):
                 raise NotImplementedError("dir_fd unavailable on this platform")
             if isinstance(path, int):
                 raise ValueError(
-                    "%s: Can't specify dir_fd without "
-                    "matching path_str" % fct.__name__
+                    "%s: Can't specify dir_fd without matching path_str" % fct.__name__
                 )
             if not self.path.isabs(path):
                 open_file = self.filesystem.get_open_file(dir_fd)
@@ -960,7 +1022,7 @@ class FakeOsModule:
         *,
         dir_fd: Optional[int] = None,
         effective_ids: bool = False,
-        follow_symlinks: bool = True
+        follow_symlinks: bool = True,
     ) -> bool:
         """Check if a file exists and has the specified permissions.
 
@@ -992,13 +1054,30 @@ class FakeOsModule:
             mode &= ~os.W_OK
         return (mode & ((stat_result.st_mode >> 6) & 7)) == mode
 
+    def fchmod(
+        self,
+        fd: int,
+        mode: int,
+    ) -> None:
+        """Change the permissions of an open file as encoded in integer mode.
+
+        Args:
+            fd: (int) File descriptor.
+            mode: (int) Permissions.
+        """
+        if self.filesystem.is_windows_fs and sys.version_info < (3, 13):
+            raise AttributeError(
+                "module 'os' has no attribute 'fchmod'. Did you mean: 'chmod'?"
+            )
+        self.filesystem.chmod(fd, mode)
+
     def chmod(
         self,
         path: AnyStr,
         mode: int,
         *,
         dir_fd: Optional[int] = None,
-        follow_symlinks: bool = True
+        follow_symlinks: bool = True,
     ) -> None:
         """Change the permissions of a file as encoded in integer mode.
 
@@ -1014,7 +1093,7 @@ class FakeOsModule:
             self.chmod not in self.supports_follow_symlinks or IS_PYPY
         ):
             raise NotImplementedError(
-                "`follow_symlinks` for chmod() is not available " "on this system"
+                "`follow_symlinks` for chmod() is not available on this system"
             )
         path = self._path_with_dir_fd(path, self.chmod, dir_fd)
         self.filesystem.chmod(path, mode, follow_symlinks)
@@ -1070,7 +1149,7 @@ class FakeOsModule:
         gid: int,
         *,
         dir_fd: Optional[int] = None,
-        follow_symlinks: bool = True
+        follow_symlinks: bool = True,
     ) -> None:
         """Set ownership of a faked file.
 
@@ -1105,7 +1184,7 @@ class FakeOsModule:
         mode: Optional[int] = None,
         device: int = 0,
         *,
-        dir_fd: Optional[int] = None
+        dir_fd: Optional[int] = None,
     ) -> None:
         """Create a filesystem node named 'filename'.
 
@@ -1156,7 +1235,7 @@ class FakeOsModule:
         dst: AnyStr,
         target_is_directory: bool = False,
         *,
-        dir_fd: Optional[int] = None
+        dir_fd: Optional[int] = None,
     ) -> None:
         """Creates the specified symlink, pointed at the specified link target.
 
@@ -1165,12 +1244,12 @@ class FakeOsModule:
             dst: Path to the symlink to create.
             target_is_directory: Currently ignored.
             dir_fd: If not `None`, the file descriptor of a directory,
-                with `src` being relative to this directory.
+                with `dst` being relative to this directory.
 
         Raises:
             OSError:  if the file already exists.
         """
-        src = self._path_with_dir_fd(src, self.symlink, dir_fd)
+        dst = self._path_with_dir_fd(dst, self.symlink, dir_fd)
         self.filesystem.create_symlink(dst, src, create_missing_dirs=False)
 
     def link(
@@ -1179,9 +1258,10 @@ class FakeOsModule:
         dst: AnyStr,
         *,
         src_dir_fd: Optional[int] = None,
-        dst_dir_fd: Optional[int] = None
+        dst_dir_fd: Optional[int] = None,
+        follow_symlinks: Optional[bool] = None,
     ) -> None:
-        """Create a hard link at new_path, pointing at old_path.
+        """Create a hard link at dst, pointing at src.
 
         Args:
             src: An existing path to the target file.
@@ -1190,14 +1270,21 @@ class FakeOsModule:
                 with `src` being relative to this directory.
             dst_dir_fd: If not `None`, the file descriptor of a directory,
                 with `dst` being relative to this directory.
+            follow_symlinks: (bool) If True (the default), symlinks in the
+                path are traversed.
 
         Raises:
             OSError:  if something already exists at new_path.
             OSError:  if the parent directory doesn't exist.
         """
+        if IS_PYPY and follow_symlinks is not None:
+            raise OSError(errno.EINVAL, "Invalid argument: follow_symlinks")
+        if follow_symlinks is None:
+            follow_symlinks = True
+
         src = self._path_with_dir_fd(src, self.link, src_dir_fd)
         dst = self._path_with_dir_fd(dst, self.link, dst_dir_fd)
-        self.filesystem.link(src, dst)
+        self.filesystem.link(src, dst, follow_symlinks=follow_symlinks)
 
     def fsync(self, fd: int) -> None:
         """Perform fsync for a fake file (in other words, do nothing).
@@ -1339,27 +1426,40 @@ class FakeOsModule:
         return getattr(self.os_module, name)
 
 
-if sys.version_info > (3, 10):
+def handle_original_call(f: Callable) -> Callable:
+    """Decorator used for real pathlib Path methods to ensure that
+    real os functions instead of faked ones are used.
+    Applied to all non-private methods of `FakeOsModule`."""
+
+    @functools.wraps(f)
+    def wrapped(*args, **kwargs):
+        should_use_original = FakeOsModule.use_original
+
+        if not should_use_original and args:
+            self = args[0]
+            fs: FakeFilesystem = self.filesystem
+            if self.filesystem.patcher:
+                skip_names = fs.patcher.skip_names
+                if is_called_from_skipped_module(
+                    skip_names=skip_names,
+                    case_sensitive=fs.is_case_sensitive,
+                ):
+                    should_use_original = True
+
+        if should_use_original:
+            # remove the `self` argument for FakeOsModule methods
+            if args and isinstance(args[0], FakeOsModule):
+                args = args[1:]
+            return getattr(os, f.__name__)(*args, **kwargs)
 
-    def handle_original_call(f: Callable) -> Callable:
-        """Decorator used for real pathlib Path methods to ensure that
-        real os functions instead of faked ones are used.
-        Applied to all non-private methods of `FakeOsModule`."""
+        return f(*args, **kwargs)
 
-        @functools.wraps(f)
-        def wrapped(*args, **kwargs):
-            if FakeOsModule.use_original:
-                # remove the `self` argument for FakeOsModule methods
-                if args and isinstance(args[0], FakeOsModule):
-                    args = args[1:]
-                return getattr(os, f.__name__)(*args, **kwargs)
-            return f(*args, **kwargs)
+    return wrapped
 
-        return wrapped
 
-    for name, fn in inspect.getmembers(FakeOsModule, inspect.isfunction):
-        if not fn.__name__.startswith("_"):
-            setattr(FakeOsModule, name, handle_original_call(fn))
+for name, fn in inspect.getmembers(FakeOsModule, inspect.isfunction):
+    if not fn.__name__.startswith("_"):
+        setattr(FakeOsModule, name, handle_original_call(fn))
 
 
 @contextmanager
diff --git a/pyfakefs/fake_path.py b/pyfakefs/fake_path.py
index 10d6722..d421b11 100644
--- a/pyfakefs/fake_path.py
+++ b/pyfakefs/fake_path.py
@@ -12,9 +12,11 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
-""" Faked ``os.path`` module replacement. See ``fake_filesystem`` for usage.
-"""
+"""Faked ``os.path`` module replacement. See ``fake_filesystem`` for usage."""
+
 import errno
+import functools
+import inspect
 import os
 import sys
 from stat import (
@@ -23,6 +25,7 @@ from stat import (
 )
 from types import ModuleType
 from typing import (
+    Callable,
     List,
     Optional,
     Union,
@@ -36,9 +39,11 @@ from typing import (
 )
 
 from pyfakefs.helpers import (
+    is_called_from_skipped_module,
     make_string_path,
     to_string,
     matching_string,
+    to_bytes,
 )
 
 if TYPE_CHECKING:
@@ -118,9 +123,9 @@ class FakePathModule:
     def reset(cls, filesystem: "FakeFilesystem") -> None:
         cls.sep = filesystem.path_separator
         cls.altsep = filesystem.alternative_path_separator
-        cls.linesep = filesystem.line_separator()
-        cls.devnull = "nul" if filesystem.is_windows_fs else "/dev/null"
-        cls.pathsep = ";" if filesystem.is_windows_fs else ":"
+        cls.linesep = filesystem.line_separator
+        cls.devnull = filesystem.devnull
+        cls.pathsep = filesystem.pathsep
 
     def exists(self, path: AnyStr) -> bool:
         """Determine whether the file object exists within the fake filesystem.
@@ -164,10 +169,19 @@ class FakePathModule:
 
     def isabs(self, path: AnyStr) -> bool:
         """Return True if path is an absolute pathname."""
+        empty = matching_string(path, "")
         if self.filesystem.is_windows_fs:
-            path = self.splitdrive(path)[1]
+            drive, path = self.splitdrive(path)
+        else:
+            drive = empty
         path = make_string_path(path)
-        return self.filesystem.starts_with_sep(path)
+        if not self.filesystem.starts_with_sep(path):
+            return False
+        if self.filesystem.is_windows_fs and sys.version_info >= (3, 13):
+            # from Python 3.13 on, a path under Windows starting with a single separator
+            # (e.g. not a drive and not an UNC path) is no more considered absolute
+            return drive != empty
+        return True
 
     def isdir(self, path: AnyStr) -> bool:
         """Determine if path identifies a directory."""
@@ -203,6 +217,14 @@ class FakePathModule:
             """
             return self.filesystem.splitroot(path)
 
+    if sys.version_info >= (3, 13):
+
+        def isreserved(self, path):
+            if not self.filesystem.is_windows_fs:
+                raise AttributeError("module 'os' has no attribute 'isreserved'")
+
+            return self.filesystem.isreserved(path)
+
     def getmtime(self, path: AnyStr) -> float:
         """Returns the modification time of the fake file.
 
@@ -220,7 +242,9 @@ class FakePathModule:
             file_obj = self.filesystem.resolve(path)
             return file_obj.st_mtime
         except OSError:
-            self.filesystem.raise_os_error(errno.ENOENT, winerror=3)
+            self.filesystem.raise_os_error(
+                errno.ENOENT, winerror=3
+            )  # pytype: disable=bad-return-type
 
     def getatime(self, path: AnyStr) -> float:
         """Returns the last access time of the fake file.
@@ -242,7 +266,7 @@ class FakePathModule:
             file_obj = self.filesystem.resolve(path)
         except OSError:
             self.filesystem.raise_os_error(errno.ENOENT)
-        return file_obj.st_atime
+        return file_obj.st_atime  # pytype: disable=name-error
 
     def getctime(self, path: AnyStr) -> float:
         """Returns the creation time of the fake file.
@@ -261,7 +285,7 @@ class FakePathModule:
             file_obj = self.filesystem.resolve(path)
         except OSError:
             self.filesystem.raise_os_error(errno.ENOENT)
-        return file_obj.st_ctime
+        return file_obj.st_ctime  # pytype: disable=name-error
 
     def abspath(self, path: AnyStr) -> AnyStr:
         """Return the absolute version of a path."""
@@ -336,7 +360,7 @@ class FakePathModule:
         symbolic links encountered in the path.
         """
         if strict is not None and sys.version_info < (3, 10):
-            raise TypeError("realpath() got an unexpected " "keyword argument 'strict'")
+            raise TypeError("realpath() got an unexpected keyword argument 'strict'")
         if strict:
             # raises in strict mode if the file does not exist
             self.filesystem.resolve(filename)
@@ -351,8 +375,8 @@ class FakePathModule:
         """Return whether path1 and path2 point to the same file.
 
         Args:
-            path1: first file path or path object (Python >=3.6)
-            path2: second file path or path object (Python >=3.6)
+            path1: first file path or path object
+            path2: second file path or path object
 
         Raises:
             OSError: if one of the paths does not point to an existing
@@ -365,14 +389,12 @@ class FakePathModule:
     @overload
     def _join_real_path(
         self, path: str, rest: str, seen: Dict[str, Optional[str]]
-    ) -> Tuple[str, bool]:
-        ...
+    ) -> Tuple[str, bool]: ...
 
     @overload
     def _join_real_path(
         self, path: bytes, rest: bytes, seen: Dict[bytes, Optional[bytes]]
-    ) -> Tuple[bytes, bool]:
-        ...
+    ) -> Tuple[bytes, bool]: ...
 
     def _join_real_path(
         self, path: AnyStr, rest: AnyStr, seen: Dict[AnyStr, Optional[AnyStr]]
@@ -505,6 +527,14 @@ if sys.platform == "win32":
             self.filesystem = filesystem
             self.nt_module: Any = nt
 
+        def getcwd(self) -> str:
+            """Return current working directory."""
+            return to_string(self.filesystem.cwd)
+
+        def getcwdb(self) -> bytes:
+            """Return current working directory as bytes."""
+            return to_bytes(self.filesystem.cwd)
+
         if sys.version_info >= (3, 12):
 
             def _path_isdir(self, path: AnyStr) -> bool:
@@ -527,3 +557,37 @@ if sys.platform == "win32":
         def __getattr__(self, name: str) -> Any:
             """Forwards any non-faked calls to the real nt module."""
             return getattr(self.nt_module, name)
+
+
+def handle_original_call(f: Callable) -> Callable:
+    """Decorator used for real pathlib Path methods to ensure that
+    real os functions instead of faked ones are used.
+    Applied to all non-private methods of `FakePathModule`."""
+
+    @functools.wraps(f)
+    def wrapped(*args, **kwargs):
+        if args:
+            self = args[0]
+            should_use_original = self.os.use_original
+            if not should_use_original and self.filesystem.patcher:
+                skip_names = self.filesystem.patcher.skip_names
+                if is_called_from_skipped_module(
+                    skip_names=skip_names,
+                    case_sensitive=self.filesystem.is_case_sensitive,
+                ):
+                    should_use_original = True
+
+            if should_use_original:
+                # remove the `self` argument for FakePathModule methods
+                if args and isinstance(args[0], FakePathModule):
+                    args = args[1:]
+                return getattr(os.path, f.__name__)(*args, **kwargs)
+
+        return f(*args, **kwargs)
+
+    return wrapped
+
+
+for name, fn in inspect.getmembers(FakePathModule, inspect.isfunction):
+    if not fn.__name__.startswith("_"):
+        setattr(FakePathModule, name, handle_original_call(fn))
diff --git a/pyfakefs/fake_pathlib.py b/pyfakefs/fake_pathlib.py
index 6e096d1..15322da 100644
--- a/pyfakefs/fake_pathlib.py
+++ b/pyfakefs/fake_pathlib.py
@@ -28,6 +28,7 @@ Note: as the implementation is based on FakeFilesystem, all faked classes
 (including PurePosixPath, PosixPath, PureWindowsPath and WindowsPath)
 get the properties of the underlying fake filesystem.
 """
+
 import errno
 import fnmatch
 import functools
@@ -38,16 +39,24 @@ import pathlib
 import posixpath
 import re
 import sys
+import warnings
 from pathlib import PurePath
-from typing import Callable
+from typing import Callable, List, Optional
 from urllib.parse import quote_from_bytes as urlquote_from_bytes
 
 from pyfakefs import fake_scandir
-from pyfakefs.extra_packages import use_scandir
 from pyfakefs.fake_filesystem import FakeFilesystem
-from pyfakefs.fake_open import FakeFileOpen
+from pyfakefs.fake_open import fake_open
 from pyfakefs.fake_os import FakeOsModule, use_original_os
-from pyfakefs.helpers import IS_PYPY
+from pyfakefs.fake_path import FakePathModule
+from pyfakefs.helpers import IS_PYPY, is_called_from_skipped_module, FSType
+
+
+_WIN_RESERVED_NAMES = (
+    {"CON", "PRN", "AUX", "NUL"}
+    | {"COM%d" % i for i in range(1, 10)}
+    | {"LPT%d" % i for i in range(1, 10)}
+)
 
 
 def init_module(filesystem):
@@ -55,37 +64,80 @@ def init_module(filesystem):
     # pylint: disable=protected-access
     FakePath.filesystem = filesystem
     if sys.version_info < (3, 12):
-        FakePathlibModule.PureWindowsPath._flavour = _FakeWindowsFlavour(filesystem)
-        FakePathlibModule.PurePosixPath._flavour = _FakePosixFlavour(filesystem)
+        FakePathlibModule.WindowsPath._flavour = _FakeWindowsFlavour(filesystem)
+        FakePathlibModule.PosixPath._flavour = _FakePosixFlavour(filesystem)
+
+        # Pure POSIX path separators must be filesystem-independent.
+        fake_pure_posix_flavour = _FakePosixFlavour(filesystem)
+        fake_pure_posix_flavour.sep = "/"
+        fake_pure_posix_flavour.altsep = None
+        FakePathlibModule.PurePosixPath._flavour = fake_pure_posix_flavour
+
+        # Pure Windows path separators must be filesystem-independent.
+        fake_pure_nt_flavour = _FakeWindowsFlavour(filesystem)
+        fake_pure_nt_flavour.sep = "\\"
+        fake_pure_nt_flavour.altsep = "/"
+        FakePathlibModule.PureWindowsPath._flavour = fake_pure_nt_flavour
     else:
-        # in Python 3.12, the flavour is no longer an own class,
+        # in Python > 3.11, the flavour is no longer a separate class,
         # but points to the os-specific path module (posixpath/ntpath)
-        fake_os = FakeOsModule(filesystem)
-        fake_path = fake_os.path
-        FakePathlibModule.PureWindowsPath._flavour = fake_path
-        FakePathlibModule.PurePosixPath._flavour = fake_path
+        fake_os_posix = FakeOsModule(filesystem)
+        if filesystem.is_windows_fs:
+            fake_os_posix.path = FakePosixPathModule(filesystem, fake_os_posix)
+        fake_os_windows = FakeOsModule(filesystem)
+        if not filesystem.is_windows_fs:
+            fake_os_windows.path = FakeWindowsPathModule(filesystem, fake_os_windows)
+
+        parser_name = "_flavour" if sys.version_info < (3, 13) else "parser"
 
+        # Pure POSIX path properties must be filesystem independent.
+        setattr(FakePathlibModule.PurePosixPath, parser_name, fake_os_posix.path)
 
-def _wrap_strfunc(strfunc):
-    @functools.wraps(strfunc)
+        # Pure Windows path properties must be filesystem independent.
+        setattr(FakePathlibModule.PureWindowsPath, parser_name, fake_os_windows.path)
+
+
+def _wrap_strfunc(fake_fct, original_fct):
+    @functools.wraps(fake_fct)
     def _wrapped(pathobj, *args, **kwargs):
-        return strfunc(pathobj.filesystem, str(pathobj), *args, **kwargs)
+        fs: FakeFilesystem = pathobj.filesystem
+        if fs.patcher:
+            if is_called_from_skipped_module(
+                skip_names=fs.patcher.skip_names,
+                case_sensitive=fs.is_case_sensitive,
+            ):
+                return original_fct(str(pathobj), *args, **kwargs)
+        return fake_fct(fs, str(pathobj), *args, **kwargs)
 
     return staticmethod(_wrapped)
 
 
-def _wrap_binary_strfunc(strfunc):
-    @functools.wraps(strfunc)
+def _wrap_binary_strfunc(fake_fct, original_fct):
+    @functools.wraps(fake_fct)
     def _wrapped(pathobj1, pathobj2, *args):
-        return strfunc(pathobj1.filesystem, str(pathobj1), str(pathobj2), *args)
+        fs: FakeFilesystem = pathobj1.filesystem
+        if fs.patcher:
+            if is_called_from_skipped_module(
+                skip_names=fs.patcher.skip_names,
+                case_sensitive=fs.is_case_sensitive,
+            ):
+                return original_fct(str(pathobj1), str(pathobj2), *args)
+        return fake_fct(fs, str(pathobj1), str(pathobj2), *args)
 
     return staticmethod(_wrapped)
 
 
-def _wrap_binary_strfunc_reverse(strfunc):
-    @functools.wraps(strfunc)
+def _wrap_binary_strfunc_reverse(fake_fct, original_fct):
+    @functools.wraps(fake_fct)
     def _wrapped(pathobj1, pathobj2, *args):
-        return strfunc(pathobj2.filesystem, str(pathobj2), str(pathobj1), *args)
+        fs: FakeFilesystem = pathobj2.filesystem
+        if fs.patcher:
+            if is_called_from_skipped_module(
+                skip_names=fs.patcher.skip_names,
+                case_sensitive=fs.is_case_sensitive,
+            ):
+                return original_fct(str(pathobj2), str(pathobj1), *args)
+        return fake_fct(fs, str(pathobj2), str(pathobj1), *args)
 
     return staticmethod(_wrapped)
 
@@ -101,22 +153,21 @@ class _FakeAccessor(accessor):  # type: ignore[valid-type, misc]
     methods.
     """
 
-    stat = _wrap_strfunc(FakeFilesystem.stat)
+    stat = _wrap_strfunc(FakeFilesystem.stat, os.stat)
 
     lstat = _wrap_strfunc(
-        lambda fs, path: FakeFilesystem.stat(fs, path, follow_symlinks=False)
+        lambda fs, path: FakeFilesystem.stat(fs, path, follow_symlinks=False), os.lstat
     )
 
-    listdir = _wrap_strfunc(FakeFilesystem.listdir)
-
-    if use_scandir:
-        scandir = _wrap_strfunc(fake_scandir.scandir)
+    listdir = _wrap_strfunc(FakeFilesystem.listdir, os.listdir)
+    scandir = _wrap_strfunc(fake_scandir.scandir, os.scandir)
 
     if hasattr(os, "lchmod"):
         lchmod = _wrap_strfunc(
             lambda fs, path, mode: FakeFilesystem.chmod(
                 fs, path, mode, follow_symlinks=False
-            )
+            ),
+            os.lchmod,
         )
     else:
 
@@ -128,58 +179,62 @@ class _FakeAccessor(accessor):  # type: ignore[valid-type, misc]
         if "follow_symlinks" in kwargs:
             if sys.version_info < (3, 10):
                 raise TypeError(
-                    "chmod() got an unexpected keyword " "argument 'follow_symlinks'"
+                    "chmod() got an unexpected keyword argument 'follow_symlinks'"
                 )
 
             if not kwargs["follow_symlinks"] and (
                 os.chmod not in os.supports_follow_symlinks or IS_PYPY
             ):
                 raise NotImplementedError(
-                    "`follow_symlinks` for chmod() is not available " "on this system"
+                    "`follow_symlinks` for chmod() is not available on this system"
                 )
         return pathobj.filesystem.chmod(str(pathobj), *args, **kwargs)
 
-    mkdir = _wrap_strfunc(FakeFilesystem.makedir)
+    mkdir = _wrap_strfunc(FakeFilesystem.makedir, os.mkdir)
 
-    unlink = _wrap_strfunc(FakeFilesystem.remove)
+    unlink = _wrap_strfunc(FakeFilesystem.remove, os.unlink)
 
-    rmdir = _wrap_strfunc(FakeFilesystem.rmdir)
+    rmdir = _wrap_strfunc(FakeFilesystem.rmdir, os.rmdir)
 
-    rename = _wrap_binary_strfunc(FakeFilesystem.rename)
+    rename = _wrap_binary_strfunc(FakeFilesystem.rename, os.rename)
 
     replace = _wrap_binary_strfunc(
         lambda fs, old_path, new_path: FakeFilesystem.rename(
             fs, old_path, new_path, force_replace=True
-        )
+        ),
+        os.replace,
     )
 
     symlink = _wrap_binary_strfunc_reverse(
         lambda fs, fpath, target, target_is_dir: FakeFilesystem.create_symlink(
             fs, fpath, target, create_missing_dirs=False
-        )
+        ),
+        os.symlink,
     )
 
     if (3, 8) <= sys.version_info:
         link_to = _wrap_binary_strfunc(
             lambda fs, file_path, link_target: FakeFilesystem.link(
                 fs, file_path, link_target
-            )
+            ),
+            os.link,
         )
 
     if sys.version_info >= (3, 10):
         link = _wrap_binary_strfunc(
             lambda fs, file_path, link_target: FakeFilesystem.link(
                 fs, file_path, link_target
-            )
+            ),
+            os.link,
         )
 
         # this will use the fake filesystem because os is patched
         def getcwd(self):
             return os.getcwd()
 
-    readlink = _wrap_strfunc(FakeFilesystem.readlink)
+    readlink = _wrap_strfunc(FakeFilesystem.readlink, os.readlink)
 
-    utime = _wrap_strfunc(FakeFilesystem.utime)
+    utime = _wrap_strfunc(FakeFilesystem.utime, os.utime)
 
 
 _fake_accessor = _FakeAccessor()
@@ -191,9 +246,6 @@ if sys.version_info < (3, 12):
         """Fake Flavour implementation used by PurePath and _Flavour"""
 
         filesystem = None
-        sep = "/"
-        altsep = None
-        has_drv = False
 
         ext_namespace_prefix = "\\\\?\\"
 
@@ -203,10 +255,7 @@ if sys.version_info < (3, 12):
 
         def __init__(self, filesystem):
             self.filesystem = filesystem
-            self.sep = filesystem.path_separator
-            self.altsep = filesystem.alternative_path_separator
-            self.has_drv = filesystem.is_windows_fs
-            super(_FakeFlavour, self).__init__()
+            super().__init__()
 
         @staticmethod
         def _split_extended_path(path, ext_prefix=ext_namespace_prefix):
@@ -269,9 +318,13 @@ if sys.version_info < (3, 12):
 
         def splitroot(self, path, sep=None):
             """Split path into drive, root and rest."""
+            is_windows = isinstance(self, _FakeWindowsFlavour)
             if sep is None:
-                sep = self.filesystem.path_separator
-            if self.filesystem.is_windows_fs:
+                if is_windows == self.filesystem.is_windows_fs:
+                    sep = self.filesystem.path_separator
+                else:
+                    sep = self.sep
+            if is_windows:
                 return self._splitroot_with_drive(path, sep)
             return self._splitroot_posix(path, sep)
 
@@ -379,7 +432,7 @@ if sys.version_info < (3, 12):
                     return pwd.getpwnam(username).pw_dir
                 except KeyError:
                     raise RuntimeError(
-                        "Can't determine home directory " "for %r" % username
+                        "Can't determine home directory for %r" % username
                     )
 
     class _FakeWindowsFlavour(_FakeFlavour):
@@ -387,11 +440,9 @@ if sys.version_info < (3, 12):
         implementations independent of FakeFilesystem properties.
         """
 
-        reserved_names = (
-            {"CON", "PRN", "AUX", "NUL"}
-            | {"COM%d" % i for i in range(1, 10)}
-            | {"LPT%d" % i for i in range(1, 10)}
-        )
+        sep = "\\"
+        altsep = "/"
+        has_drv = True
         pathmod = ntpath
 
         def is_reserved(self, parts):
@@ -406,7 +457,7 @@ if sys.version_info < (3, 12):
             if self.filesystem.is_windows_fs and parts[0].startswith("\\\\"):
                 # UNC paths are never reserved
                 return False
-            return parts[-1].partition(".")[0].upper() in self.reserved_names
+            return parts[-1].partition(".")[0].upper() in _WIN_RESERVED_NAMES
 
         def make_uri(self, path):
             """Return a file URI for the given path"""
@@ -417,7 +468,7 @@ if sys.version_info < (3, 12):
             if len(drive) == 2 and drive[1] == ":":
                 # It's a path on a local drive => 'file:///c:/a/b'
                 rest = path.as_posix()[2:].lstrip("/")
-                return "file:///%s/%s" % (
+                return "file:///{}/{}".format(
                     drive,
                     urlquote_from_bytes(rest.encode("utf-8")),
                 )
@@ -451,7 +502,7 @@ if sys.version_info < (3, 12):
                     drv, root, parts = self.parse_parts((userhome,))
                     if parts[-1] != os.environ["USERNAME"]:
                         raise RuntimeError(
-                            "Can't determine home directory " "for %r" % username
+                            "Can't determine home directory for %r" % username
                         )
                     parts[-1] = username
                     if drv or root:
@@ -468,6 +519,9 @@ if sys.version_info < (3, 12):
         independent of FakeFilesystem properties.
         """
 
+        sep = "/"
+        altsep: Optional[str] = None
+        has_drv = False
         pathmod = posixpath
 
         def is_reserved(self, parts):
@@ -495,11 +549,41 @@ if sys.version_info < (3, 12):
                     return pwd.getpwnam(username).pw_dir
                 except KeyError:
                     raise RuntimeError(
-                        "Can't determine home directory " "for %r" % username
+                        "Can't determine home directory for %r" % username
                     )
 
         def compile_pattern(self, pattern):
             return re.compile(fnmatch.translate(pattern)).fullmatch
+else:  # Python >= 3.12
+
+    class FakePosixPathModule(FakePathModule):
+        def __init__(self, filesystem: "FakeFilesystem", os_module: "FakeOsModule"):
+            super().__init__(filesystem, os_module)
+            with self.filesystem.use_fs_type(FSType.POSIX):
+                self.reset(self.filesystem)
+
+    class FakeWindowsPathModule(FakePathModule):
+        def __init__(self, filesystem: "FakeFilesystem", os_module: "FakeOsModule"):
+            super().__init__(filesystem, os_module)
+            with self.filesystem.use_fs_type(FSType.WINDOWS):
+                self.reset(self.filesystem)
+
+    def with_fs_type(f: Callable, fs_type: FSType) -> Callable:
+        """Decorator used for fake_path methods to ensure that
+        the correct filesystem type is used."""
+
+        @functools.wraps(f)
+        def wrapped(self, *args, **kwargs):
+            with self.filesystem.use_fs_type(fs_type):
+                return f(self, *args, **kwargs)
+
+        return wrapped
+
+    # decorate all public functions to use the correct fs type
+    for fct_name in FakePathModule.dir():
+        fn = getattr(FakePathModule, fct_name)
+        setattr(FakeWindowsPathModule, fct_name, with_fs_type(fn, FSType.WINDOWS))
+        setattr(FakePosixPathModule, fct_name, with_fs_type(fn, FSType.POSIX))
 
 
 class FakePath(pathlib.Path):
@@ -511,6 +595,7 @@ class FakePath(pathlib.Path):
 
     # the underlying fake filesystem
     filesystem = None
+    skip_names: List[str] = []
 
     def __new__(cls, *args, **kwargs):
         """Creates the correct subclass based on OS."""
@@ -579,20 +664,12 @@ class FakePath(pathlib.Path):
             Args:
                 strict: If False (default) no exception is raised if the path
                     does not exist.
-                    New in Python 3.6.
 
             Raises:
-                OSError: if the path doesn't exist (strict=True or Python < 3.6)
+                OSError: if the path doesn't exist (strict=True)
             """
-            if sys.version_info >= (3, 6):
-                if strict is None:
-                    strict = False
-            else:
-                if strict is not None:
-                    raise TypeError(
-                        "resolve() got an unexpected keyword argument 'strict'"
-                    )
-                strict = True
+            if strict is None:
+                strict = False
             self._raise_on_closed()
             path = self._flavour.resolve(
                 self, strict=strict
@@ -611,8 +688,15 @@ class FakePath(pathlib.Path):
                 or permission is denied.
         """
         self._raise_on_closed()
-        return FakeFileOpen(self.filesystem)(
-            self._path(), mode, buffering, encoding, errors, newline
+        return fake_open(
+            self.filesystem,
+            self.skip_names,
+            self._path(),
+            mode,
+            buffering,
+            encoding,
+            errors,
+            newline,
         )
 
     def read_bytes(self):
@@ -622,17 +706,25 @@ class FakePath(pathlib.Path):
             OSError: if the target object is a directory, the path is
                 invalid or permission is denied.
         """
-        with FakeFileOpen(self.filesystem)(
-            self._path(), mode="rb"
-        ) as f:  # pytype: disable=attribute-error
+        with fake_open(
+            self.filesystem,
+            self.skip_names,
+            self._path(),
+            mode="rb",
+        ) as f:
             return f.read()
 
     def read_text(self, encoding=None, errors=None):
         """
         Open the fake file in text mode, read it, and close the file.
         """
-        with FakeFileOpen(self.filesystem)(  # pytype: disable=attribute-error
-            self._path(), mode="r", encoding=encoding, errors=errors
+        with fake_open(
+            self.filesystem,
+            self.skip_names,
+            self._path(),
+            mode="r",
+            encoding=encoding,
+            errors=errors,
         ) as f:
             return f.read()
 
@@ -646,9 +738,12 @@ class FakePath(pathlib.Path):
         """
         # type-check for the buffer interface before truncating the file
         view = memoryview(data)
-        with FakeFileOpen(self.filesystem)(
-            self._path(), mode="wb"
-        ) as f:  # pytype: disable=attribute-error
+        with fake_open(
+            self.filesystem,
+            self.skip_names,
+            self._path(),
+            mode="wb",
+        ) as f:
             return f.write(view)
 
     def write_text(self, data, encoding=None, errors=None, newline=None):
@@ -670,10 +765,10 @@ class FakePath(pathlib.Path):
         if not isinstance(data, str):
             raise TypeError("data must be str, not %s" % data.__class__.__name__)
         if newline is not None and sys.version_info < (3, 10):
-            raise TypeError(
-                "write_text() got an unexpected " "keyword argument 'newline'"
-            )
-        with FakeFileOpen(self.filesystem)(  # pytype: disable=attribute-error
+            raise TypeError("write_text() got an unexpected keyword argument 'newline'")
+        with fake_open(
+            self.filesystem,
+            self.skip_names,
             self._path(),
             mode="w",
             encoding=encoding,
@@ -749,34 +844,23 @@ class FakePath(pathlib.Path):
             else:
                 self.filesystem.raise_os_error(errno.EEXIST, self._path())
         else:
-            fake_file = self.open("w")
+            fake_file = self.open("w", encoding="utf8")
             fake_file.close()
             self.chmod(mode)
 
-    if sys.version_info >= (3, 12):
-        """These are reimplemented for now because the original implementation
-        checks the flavour against ntpath/posixpath.
-        """
-
-        def is_absolute(self):
-            if self.filesystem.is_windows_fs:
-                return self.drive and self.root
-            return os.path.isabs(self._path())
 
-        def is_reserved(self):
-            if not self.filesystem.is_windows_fs or not self._tail:
-                return False
-            if self._tail[0].startswith("\\\\"):
-                # UNC paths are never reserved.
-                return False
-            name = self._tail[-1].partition(".")[0].partition(":")[0].rstrip(" ")
-            return name.upper() in pathlib._WIN_RESERVED_NAMES
+def _warn_is_reserved_deprecated():
+    if sys.version_info >= (3, 13):
+        warnings.warn(
+            "pathlib.PurePath.is_reserved() is deprecated and scheduled "
+            "for removal in Python 3.15. Use os.path.isreserved() to detect "
+            "reserved paths on Windows.",
+            DeprecationWarning,
+        )
 
 
 class FakePathlibModule:
     """Uses FakeFilesystem to provide a fake pathlib module replacement.
-    Can be used to replace both the standard `pathlib` module and the
-    `pathlib2` package available on PyPi.
 
     You need a fake_filesystem to use this:
     `filesystem = fake_filesystem.FakeFilesystem()`
@@ -798,12 +882,47 @@ class FakePathlibModule:
         paths"""
 
         __slots__ = ()
+        if sys.version_info >= (3, 12):
+
+            def is_reserved(self):
+                _warn_is_reserved_deprecated()
+                return False
+
+            def is_absolute(self):
+                with os.path.filesystem.use_fs_type(FSType.POSIX):  # type: ignore[module-attr]
+                    return os.path.isabs(self)
+
+            def joinpath(self, *pathsegments):
+                with os.path.filesystem.use_fs_type(FSType.POSIX):  # type: ignore[module-attr]
+                    return super().joinpath(*pathsegments)
 
     class PureWindowsPath(PurePath):
         """A subclass of PurePath, that represents Windows filesystem paths"""
 
         __slots__ = ()
 
+        if sys.version_info >= (3, 12):
+            """These are reimplemented because the PurePath implementation
+            checks the flavour against ntpath/posixpath.
+            """
+
+            def is_reserved(self):
+                _warn_is_reserved_deprecated()
+                if sys.version_info < (3, 13):
+                    if not self._tail or self._tail[0].startswith("\\\\"):
+                        # UNC paths are never reserved.
+                        return False
+                    name = (
+                        self._tail[-1].partition(".")[0].partition(":")[0].rstrip(" ")
+                    )
+                    return name.upper() in _WIN_RESERVED_NAMES
+                with os.path.filesystem.use_fs_type(FSType.WINDOWS):  # type: ignore[module-attr]
+                    return os.path.isreserved(self)
+
+            def is_absolute(self):
+                with os.path.filesystem.use_fs_type(FSType.WINDOWS):
+                    return bool(self.drive and self.root)
+
     class WindowsPath(FakePath, PureWindowsPath):
         """A subclass of Path and PureWindowsPath that represents
         concrete Windows filesystem paths.
@@ -845,6 +964,19 @@ class FakePathlibModule:
 
             return grp.getgrgid(self.stat().st_gid).gr_name
 
+        if sys.version_info >= (3, 14):
+            # in Python 3.14, case-sensitivity is checked using an is-check
+            # (self.parser is posixpath) if not given, which we cannot fake
+            # therefore we already provide the case sensitivity under Posix
+            def glob(self, pattern, *, case_sensitive=None, recurse_symlinks=False):
+                if case_sensitive is None:
+                    case_sensitive = True
+                return super().glob(  # pytype: disable=wrong-keyword-args
+                    pattern,
+                    case_sensitive=case_sensitive,
+                    recurse_symlinks=recurse_symlinks,
+                )
+
     Path = FakePath
 
     def __getattr__(self, name):
@@ -861,6 +993,15 @@ class FakePathlibPathModule:
         if self.fake_pathlib is None:
             self.__class__.fake_pathlib = FakePathlibModule(filesystem)
 
+    @property
+    def skip_names(self):
+        return []  # not used, here to allow a setter
+
+    @skip_names.setter
+    def skip_names(self, value):
+        # this is set from the patcher and passed to the fake Path class
+        self.fake_pathlib.Path.skip_names = value
+
     def __call__(self, *args, **kwargs):
         return self.fake_pathlib.Path(*args, **kwargs)
 
@@ -885,8 +1026,10 @@ class RealPath(pathlib.Path):
             if os.name == "nt"
             else pathlib._PosixFlavour()  # type:ignore
         )  # type:ignore
-    else:
+    elif sys.version_info < (3, 13):
         _flavour = ntpath if os.name == "nt" else posixpath
+    else:
+        parser = ntpath if os.name == "nt" else posixpath
 
     def __new__(cls, *args, **kwargs):
         """Creates the correct subclass based on OS."""
@@ -915,9 +1058,9 @@ if sys.version_info > (3, 10):
 
         return wrapped
 
-    for name, fn in inspect.getmembers(RealPath, inspect.isfunction):
-        if not name.startswith("__"):
-            setattr(RealPath, name, with_original_os(fn))
+    for fct_name, fn in inspect.getmembers(RealPath, inspect.isfunction):
+        if not fct_name.startswith("__"):
+            setattr(RealPath, fct_name, with_original_os(fn))
 
 
 class RealPathlibPathModule:
diff --git a/pyfakefs/fake_scandir.py b/pyfakefs/fake_scandir.py
index cfe9f2f..308dff6 100644
--- a/pyfakefs/fake_scandir.py
+++ b/pyfakefs/fake_scandir.py
@@ -16,19 +16,14 @@ Works with both the function integrated into the `os` module since Python 3.5
 and the standalone function available in the standalone `scandir` python
 package.
 """
+
 import os
 import sys
 
-from pyfakefs.extra_packages import use_scandir_package
 from pyfakefs.helpers import to_string, make_string_path
 
-if sys.version_info >= (3, 6):
-    BaseClass = os.PathLike
-else:
-    BaseClass = object
-
 
-class DirEntry(BaseClass):
+class DirEntry(os.PathLike):
     """Emulates os.DirEntry. Note that we did not enforce keyword only
     arguments."""
 
@@ -109,10 +104,8 @@ class DirEntry(BaseClass):
                 self._statresult.st_nlink = 0
         return self._statresult
 
-    if sys.version_info >= (3, 6):
-
-        def __fspath__(self):
-            return self.path
+    def __fspath__(self):
+        return self.path
 
     if sys.version_info >= (3, 12):
 
@@ -132,11 +125,9 @@ class ScanDirIter:
     def __init__(self, filesystem, path):
         self.filesystem = filesystem
         if isinstance(path, int):
-            if not use_scandir_package and (
-                sys.version_info < (3, 7) or self.filesystem.is_windows_fs
-            ):
+            if self.filesystem.is_windows_fs:
                 raise NotImplementedError(
-                    "scandir does not support file descriptor " "path argument"
+                    "scandir does not support file descriptor path argument"
                 )
             self.abspath = self.filesystem.absnormpath(
                 self.filesystem.get_open_file(path).get_object().path
@@ -146,8 +137,8 @@ class ScanDirIter:
             path = make_string_path(path)
             self.abspath = self.filesystem.absnormpath(path)
             self.path = to_string(path)
-        entries = self.filesystem.confirmdir(self.abspath).entries
-        self.entry_iter = iter(entries)
+        entries = self.filesystem.confirmdir(self.abspath, check_exe_perm=False).entries
+        self.entry_iter = iter(tuple(entries))
 
     def __iter__(self):
         return self
@@ -162,16 +153,14 @@ class ScanDirIter:
         dir_entry._islink = self.filesystem.islink(dir_entry._abspath)
         return dir_entry
 
-    if sys.version_info >= (3, 6):
-
-        def __enter__(self):
-            return self
+    def __enter__(self):
+        return self
 
-        def __exit__(self, exc_type, exc_val, exc_tb):
-            self.close()
+    def __exit__(self, exc_type, exc_val, exc_tb):
+        self.close()
 
-        def close(self):
-            pass
+    def close(self):
+        pass
 
 
 def scandir(filesystem, path=""):
@@ -256,67 +245,8 @@ def walk(filesystem, top, topdown=True, onerror=None, followlinks=False):
                 path = filesystem.joinpaths(top_dir, directory)
                 if not followlinks and filesystem.islink(path):
                     continue
-                for contents in do_walk(path):
-                    yield contents
+                yield from do_walk(path)
             if not topdown:
                 yield top_contents
 
-    return do_walk(to_string(top), top_most=True)
-
-
-class FakeScanDirModule:
-    """Uses FakeFilesystem to provide a fake `scandir` module replacement.
-
-    .. Note:: The ``scandir`` function is a part of the standard ``os`` module
-      since Python 3.5. This class handles the separate ``scandir`` module
-      that is available on pypi.
-
-    You need a fake_filesystem to use this:
-    `filesystem = fake_filesystem.FakeFilesystem()`
-    `fake_scandir_module = fake_filesystem.FakeScanDirModule(filesystem)`
-    """
-
-    @staticmethod
-    def dir():
-        """Return the list of patched function names. Used for patching
-        functions imported from the module.
-        """
-        return "scandir", "walk"
-
-    def __init__(self, filesystem):
-        self.filesystem = filesystem
-
-    def scandir(self, path="."):
-        """Return an iterator of DirEntry objects corresponding to the entries
-        in the directory given by path.
-
-        Args:
-            path: Path to the target directory within the fake filesystem.
-
-        Returns:
-            an iterator to an unsorted list of os.DirEntry objects for
-            each entry in path.
-
-        Raises:
-            OSError: if the target is not a directory.
-        """
-        return scandir(self.filesystem, path)
-
-    def walk(self, top, topdown=True, onerror=None, followlinks=False):
-        """Perform a walk operation over the fake filesystem.
-
-        Args:
-            top: The root directory from which to begin walk.
-            topdown: Determines whether to return the tuples with the root as
-                the first entry (`True`) or as the last, after all the child
-                directory tuples (`False`).
-          onerror: If not `None`, function which will be called to handle the
-                `os.error` instance provided when `os.listdir()` fails.
-          followlinks: If `True`, symbolic links are followed.
-
-        Yields:
-            (path, directories, nondirectories) for top and each of its
-            subdirectories.  See the documentation for the builtin os module
-            for further details.
-        """
-        return walk(self.filesystem, top, topdown, onerror, followlinks)
+    return do_walk(make_string_path(to_string(top)), top_most=True)
diff --git a/pyfakefs/helpers.py b/pyfakefs/helpers.py
index 5d5d590..0e08813 100644
--- a/pyfakefs/helpers.py
+++ b/pyfakefs/helpers.py
@@ -11,14 +11,22 @@
 # limitations under the License.
 
 """Helper classes use for fake file system implementation."""
+
+import ctypes
+import importlib
 import io
 import locale
 import os
 import platform
 import stat
 import sys
+import sysconfig
 import time
+import traceback
+from collections import namedtuple
 from copy import copy
+from dataclasses import dataclass
+from enum import Enum
 from stat import S_IFLNK
 from typing import Union, Optional, Any, AnyStr, overload, cast
 
@@ -36,9 +44,22 @@ PERM_DEF = 0o777  # Default permission bits.
 PERM_DEF_FILE = 0o666  # Default permission bits (regular file)
 PERM_ALL = 0o7777  # All permission bits.
 
+STDLIB_PATH = os.path.realpath(sysconfig.get_path("stdlib"))
+PYFAKEFS_PATH = os.path.dirname(__file__)
+PYFAKEFS_TEST_PATHS = [
+    os.path.join(PYFAKEFS_PATH, "tests"),
+    os.path.join(PYFAKEFS_PATH, "pytest_tests"),
+]
+
+_OpenModes = namedtuple(
+    "_OpenModes",
+    "must_exist can_read can_write truncate append must_not_exist",
+)
+
 if sys.platform == "win32":
-    USER_ID = 1
-    GROUP_ID = 1
+    fake_id = 0 if ctypes.windll.shell32.IsUserAnAdmin() else 1
+    USER_ID = fake_id
+    GROUP_ID = fake_id
 else:
     USER_ID = os.getuid()
     GROUP_ID = os.getgid()
@@ -80,8 +101,9 @@ def set_gid(gid: int) -> None:
 def reset_ids() -> None:
     """Set the global user ID and group ID back to default values."""
     if sys.platform == "win32":
-        set_uid(1)
-        set_gid(1)
+        reset_id = 0 if ctypes.windll.shell32.IsUserAnAdmin() else 1
+        set_uid(reset_id)
+        set_gid(reset_id)
     else:
         set_uid(os.getuid())
         set_gid(os.getgid())
@@ -109,17 +131,21 @@ def is_unicode_string(val: Any) -> bool:
     return hasattr(val, "encode")
 
 
+def get_locale_encoding():
+    if sys.version_info >= (3, 11):
+        return locale.getencoding()
+    return locale.getpreferredencoding(False)
+
+
 @overload
-def make_string_path(dir_name: AnyStr) -> AnyStr:
-    ...
+def make_string_path(dir_name: AnyStr) -> AnyStr: ...
 
 
 @overload
-def make_string_path(dir_name: os.PathLike) -> str:
-    ...
+def make_string_path(dir_name: os.PathLike) -> str: ...
 
 
-def make_string_path(dir_name: AnyPath) -> AnyStr:
+def make_string_path(dir_name: AnyPath) -> AnyStr:  # type: ignore[type-var]
     return cast(AnyStr, os.fspath(dir_name))  # pytype: disable=invalid-annotation
 
 
@@ -127,7 +153,7 @@ def to_string(path: Union[AnyStr, Union[str, bytes]]) -> str:
     """Return the string representation of a byte string using the preferred
     encoding, or the string itself if path is a str."""
     if isinstance(path, bytes):
-        return path.decode(locale.getpreferredencoding(False))
+        return path.decode(get_locale_encoding())
     return path
 
 
@@ -135,7 +161,7 @@ def to_bytes(path: Union[AnyStr, Union[str, bytes]]) -> bytes:
     """Return the bytes representation of a string using the preferred
     encoding, or the byte string itself if path is a byte string."""
     if isinstance(path, str):
-        return bytes(path, locale.getpreferredencoding(False))
+        return bytes(path, get_locale_encoding())
     return path
 
 
@@ -158,18 +184,15 @@ def now():
 
 
 @overload
-def matching_string(matched: bytes, string: AnyStr) -> bytes:
-    ...
+def matching_string(matched: bytes, string: AnyStr) -> bytes: ...
 
 
 @overload
-def matching_string(matched: str, string: AnyStr) -> str:
-    ...
+def matching_string(matched: str, string: AnyStr) -> str: ...
 
 
 @overload
-def matching_string(matched: AnyStr, string: None) -> None:
-    ...
+def matching_string(matched: AnyStr, string: None) -> None: ...
 
 
 def matching_string(  # type: ignore[misc]
@@ -181,10 +204,46 @@ def matching_string(  # type: ignore[misc]
     if string is None:
         return string
     if isinstance(matched, bytes) and isinstance(string, str):
-        return string.encode(locale.getpreferredencoding(False))
+        return string.encode(get_locale_encoding())
     return string  # pytype: disable=bad-return-type
 
 
+@dataclass
+class FSProperties:
+    sep: str
+    altsep: Optional[str]
+    pathsep: str
+    linesep: str
+    devnull: str
+
+
+# pure POSIX file system properties, for use with PosixPath
+POSIX_PROPERTIES = FSProperties(
+    sep="/",
+    altsep=None,
+    pathsep=":",
+    linesep="\n",
+    devnull="/dev/null",
+)
+
+# pure Windows file system properties, for use with WindowsPath
+WINDOWS_PROPERTIES = FSProperties(
+    sep="\\",
+    altsep="/",
+    pathsep=";",
+    linesep="\r\n",
+    devnull="NUL",
+)
+
+
+class FSType(Enum):
+    """Defines which file system properties to use."""
+
+    DEFAULT = 0  # use current OS file system + modifications in fake file system
+    POSIX = 1  # pure POSIX properties, for use in PosixPath
+    WINDOWS = 2  # pure Windows properties, for use in WindowsPath
+
+
 class FakeStatResult:
     """Mimics os.stat_result for use as return type of `stat()` and similar.
     This is needed as `os.stat_result` has no possibility to set
@@ -308,7 +367,7 @@ class FakeStatResult:
     def st_file_attributes(self) -> int:
         if not self.is_windows:
             raise AttributeError(
-                "module 'os.stat_result' " "has no attribute 'st_file_attributes'"
+                "module 'os.stat_result' has no attribute 'st_file_attributes'"
             )
         mode = 0
         st_mode = self.st_mode
@@ -326,7 +385,7 @@ class FakeStatResult:
     def st_reparse_tag(self) -> int:
         if not self.is_windows or sys.version_info < (3, 8):
             raise AttributeError(
-                "module 'os.stat_result' " "has no attribute 'st_reparse_tag'"
+                "module 'os.stat_result' has no attribute 'st_reparse_tag'"
             )
         if self.st_mode & stat.S_IFLNK:
             return stat.IO_REPARSE_TAG_SYMLINK  # type: ignore[attr-defined]
@@ -418,3 +477,75 @@ class TextBufferIO(io.TextIOWrapper):
 
     def putvalue(self, value: bytes) -> None:
         self._bytestream.write(value)
+
+
+def is_called_from_skipped_module(
+    skip_names: list, case_sensitive: bool, check_open_code: bool = False
+) -> bool:
+    def starts_with(path, string):
+        if case_sensitive:
+            return path.startswith(string)
+        return path.lower().startswith(string.lower())
+
+    # in most cases we don't have skip names and won't need the overhead
+    # of analyzing the traceback, except when checking for open_code
+    if not skip_names and not check_open_code:
+        return False
+
+    stack = traceback.extract_stack()
+
+    # handle the case that we try to call the original `open_code`
+    # (since Python 3.12)
+    # The stack in this case is:
+    # -1: helpers.is_called_from_skipped_module: 'stack = traceback.extract_stack()'
+    # -2: fake_open.fake_open: 'if is_called_from_skipped_module('
+    # -3: fake_io.open: 'return fake_open('
+    # -4: fake_io.open_code : 'return self._io_module.open_code(path)'
+    if (
+        check_open_code
+        and stack[-4].name == "open_code"
+        and stack[-4].line == "return self._io_module.open_code(path)"
+    ):
+        return True
+
+    if not skip_names:
+        return False
+
+    caller_filename = next(
+        (
+            frame.filename
+            for frame in stack[::-1]
+            if not frame.filename.startswith("<frozen ")
+            and not starts_with(frame.filename, STDLIB_PATH)
+            and (
+                not starts_with(frame.filename, PYFAKEFS_PATH)
+                or any(
+                    starts_with(frame.filename, test_path)
+                    for test_path in PYFAKEFS_TEST_PATHS
+                )
+            )
+        ),
+        None,
+    )
+
+    if caller_filename:
+        caller_module_name = os.path.splitext(caller_filename)[0]
+        caller_module_name = caller_module_name.replace(os.sep, ".")
+
+        if any(
+            [
+                caller_module_name == sn or caller_module_name.endswith("." + sn)
+                for sn in skip_names
+            ]
+        ):
+            return True
+    return False
+
+
+def reload_cleanup_handler(name):
+    """Cleanup handler that reloads the module with the given name.
+    Maybe needed in cases where a module is imported locally.
+    """
+    if name in sys.modules:
+        importlib.reload(sys.modules[name])
+    return True
diff --git a/pyfakefs/extra_packages.py b/pyfakefs/legacy_packages.py
similarity index 62%
rename from pyfakefs/extra_packages.py
rename to pyfakefs/legacy_packages.py
index 23e0814..465b464 100644
--- a/pyfakefs/extra_packages.py
+++ b/pyfakefs/legacy_packages.py
@@ -11,7 +11,8 @@
 # limitations under the License.
 
 """Imports external packages that replace or emulate internal packages.
-If the external module is not present, the built-in module is imported.
+These packages are not needed with any current Python version,
+and their support in pyfakefs will be removed in a an upcoming release.
 """
 
 try:
@@ -20,18 +21,6 @@ except ImportError:
     pathlib2 = None
 
 try:
-    import scandir
-
-    use_scandir_package = True
-    use_builtin_scandir = False
+    import scandir as scandir
 except ImportError:
-    try:
-        from os import scandir  # noqa: F401
-
-        use_builtin_scandir = True
-        use_scandir_package = False
-    except ImportError:
-        use_builtin_scandir = False
-        use_scandir_package = False
-
-use_scandir = use_scandir_package or use_builtin_scandir
+    scandir = None
diff --git a/pyfakefs/mox3_stubout.py b/pyfakefs/mox3_stubout.py
index c3f3a88..6e500de 100644
--- a/pyfakefs/mox3_stubout.py
+++ b/pyfakefs/mox3_stubout.py
@@ -61,14 +61,9 @@ class StubOutForTesting:
         This method supports the case where attr_name is a staticmethod or a
         classmethod of obj.
 
-        Notes:
-          - If obj is an instance, then it is its class that will actually be
-            stubbed. Note that the method Set() does not do that: if obj is
-            an instance, it (and not its class) will be stubbed.
-          - The stubbing is using the builtin getattr and setattr. So, the
-            __get__ and __set__ will be called when stubbing (TODO: A better
-            idea would probably be to manipulate obj.__dict__ instead of
-            getattr() and setattr()).
+        If obj is an instance, then it is its class that will actually be
+        stubbed. Note that the method Set() does not do that: if obj is an
+        instance, it (and not its class) will be stubbed.
 
         Raises AttributeError if the attribute cannot be found.
         """
@@ -76,7 +71,10 @@ class StubOutForTesting:
             not inspect.isclass(obj) and attr_name in obj.__dict__
         ):
             orig_obj = obj
-            orig_attr = getattr(obj, attr_name)
+            if attr_name in obj.__dict__:
+                orig_attr = obj.__dict__[attr_name]
+            else:
+                orig_attr = None
 
         else:
             if not inspect.isclass(obj):
@@ -91,21 +89,15 @@ class StubOutForTesting:
             for cls in mro:
                 try:
                     orig_obj = cls
-                    orig_attr = getattr(obj, attr_name)
-                except AttributeError:
+                    orig_attr = obj.__dict__[attr_name]
+                except KeyError:
                     continue
 
         if orig_attr is None:
             raise AttributeError("Attribute not found.")
 
-        # Calling getattr() on a staticmethod transforms it to a 'normal'
-        # function. We need to ensure that we put it back as a staticmethod.
-        old_attribute = obj.__dict__.get(attr_name)
-        if old_attribute is not None and isinstance(old_attribute, staticmethod):
-            orig_attr = staticmethod(orig_attr)  # pytype: disable=not-callable
-
         self.stubs.append((orig_obj, attr_name, orig_attr))
-        setattr(orig_obj, attr_name, new_attr)
+        orig_obj.__dict__[attr_name] = new_attr
 
     def smart_unset_all(self):
         """Reverses all the SmartSet() calls.
@@ -116,8 +108,8 @@ class StubOutForTesting:
         """
         self.stubs.reverse()
 
-        for args in self.stubs:
-            setattr(*args)
+        for obj, attr_name, old_attr in self.stubs:
+            obj.__dict__[attr_name] = old_attr
 
         self.stubs = []
 
@@ -143,7 +135,7 @@ class StubOutForTesting:
                 old_child = classmethod(old_child.__func__)
 
         self.cache.append((parent, old_child, child_name))
-        setattr(parent, child_name, new_child)
+        parent.__dict__[child_name] = new_child
 
     def unset_all(self):
         """Reverses all the Set() calls.
@@ -158,5 +150,5 @@ class StubOutForTesting:
         self.cache.reverse()
 
         for parent, old_child, child_name in self.cache:
-            setattr(parent, child_name, old_child)
+            parent.__dict__[child_name] = old_child
         self.cache = []
diff --git a/pyfakefs/patched_packages.py b/pyfakefs/patched_packages.py
index 0d7651c..2271e94 100644
--- a/pyfakefs/patched_packages.py
+++ b/pyfakefs/patched_packages.py
@@ -14,22 +14,37 @@
 Provides patches for some commonly used modules that enable them to work
 with pyfakefs.
 """
+
 import sys
+from importlib import reload
 
 try:
     import pandas as pd
-    import pandas.io.parsers as parsers
+
+    try:
+        import pandas.io.parsers as parsers
+    except ImportError:
+        parsers = None
 except ImportError:
+    pd = None
     parsers = None
 
+
 try:
     import xlrd
 except ImportError:
     xlrd = None
 
+
 try:
-    from django.core.files import locks
+    import django
+
+    try:
+        from django.core.files import locks
+    except ImportError:
+        locks = None
 except ImportError:
+    django = None
     locks = None
 
 # From pandas v 1.2 onwards the python fs functions are used even when the engine
@@ -57,6 +72,24 @@ def get_classes_to_patch():
     return classes_to_patch
 
 
+def reload_handler(name):
+    if name in sys.modules:
+        reload(sys.modules[name])
+    return True
+
+
+def get_cleanup_handlers():
+    handlers = {}
+    if pd is not None:
+        handlers["pandas.core.arrays.arrow.extension_types"] = (
+            handle_extension_type_cleanup
+        )
+    if django is not None:
+        for module_name in django_view_modules():
+            handlers[module_name] = lambda name=module_name: reload_handler(name)
+    return handlers
+
+
 def get_fake_module_classes():
     fake_module_classes = {}
     if patch_pandas:
@@ -134,6 +167,23 @@ if patch_pandas:
             return getattr(self._parsers_module, name)
 
 
+if pd is not None:
+
+    def handle_extension_type_cleanup(_name):
+        # the module registers two extension types on load
+        # on reload it raises if the extensions have not been unregistered before
+        try:
+            import pyarrow
+
+            # the code to register these types has been in the module
+            # since it was created (in pandas 1.5)
+            pyarrow.unregister_extension_type("pandas.interval")
+            pyarrow.unregister_extension_type("pandas.period")
+        except ImportError:
+            pass
+        return False
+
+
 if locks is not None:
 
     class FakeLocks:
@@ -154,3 +204,31 @@ if locks is not None:
 
         def __getattr__(self, name):
             return getattr(self._locks_module, name)
+
+
+if django is not None:
+
+    def get_all_view_modules(urlpatterns, modules=None):
+        if modules is None:
+            modules = set()
+        for pattern in urlpatterns:
+            if hasattr(pattern, "url_patterns"):
+                get_all_view_modules(pattern.url_patterns, modules=modules)
+            else:
+                if hasattr(pattern.callback, "cls"):
+                    view = pattern.callback.cls
+                elif hasattr(pattern.callback, "view_class"):
+                    view = pattern.callback.view_class
+                else:
+                    view = pattern.callback
+                modules.add(view.__module__)
+        return modules
+
+    def django_view_modules():
+        try:
+            all_urlpatterns = __import__(
+                django.conf.settings.ROOT_URLCONF
+            ).urls.urlpatterns
+            return get_all_view_modules(all_urlpatterns)
+        except Exception:
+            return set()
diff --git a/pyfakefs/pytest_plugin.py b/pyfakefs/pytest_plugin.py
index 37b055f..1677500 100644
--- a/pyfakefs/pytest_plugin.py
+++ b/pyfakefs/pytest_plugin.py
@@ -80,3 +80,27 @@ def fs_session(request):
 def pytest_sessionfinish(session, exitstatus):
     """Make sure that the cache is cleared before the final test shutdown."""
     Patcher.clear_fs_cache()
+
+
+@pytest.hookimpl(hookwrapper=True, tryfirst=True)
+def pytest_runtest_logreport(report):
+    """Make sure that patching is not active during reporting."""
+    pause = Patcher.PATCHER is not None and report.when == "call"
+    if pause:
+        Patcher.PATCHER.pause()
+    yield
+
+
+@pytest.hookimpl(hookwrapper=True, trylast=True)
+def pytest_runtest_call(item):
+    if Patcher.PATCHER is not None:
+        Patcher.PATCHER.resume()
+    yield
+
+
+@pytest.hookimpl(hookwrapper=True, tryfirst=True)
+def pytest_runtest_teardown(item, nextitem):
+    """Make sure that patching is not active during reporting."""
+    if Patcher.PATCHER is not None:
+        Patcher.PATCHER.pause()
+    yield
diff --git a/pyfakefs/pytest_tests/data/test.parquet b/pyfakefs/pytest_tests/data/test.parquet
new file mode 100644
index 0000000..13085cd
Binary files /dev/null and b/pyfakefs/pytest_tests/data/test.parquet differ
diff --git a/pyfakefs/pytest_tests/fake_fcntl_test.py b/pyfakefs/pytest_tests/fake_fcntl_test.py
new file mode 100644
index 0000000..b566b55
--- /dev/null
+++ b/pyfakefs/pytest_tests/fake_fcntl_test.py
@@ -0,0 +1,22 @@
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
+import sys
+
+if sys.platform == "linux":
+    import fcntl
+
+    def test_unpatched_attributes_are_forwarded_to_real_fs(fs):
+        # regression test for #1074
+        with open("lock_file", "a+") as lock_file:
+            fcntl.flock(lock_file, fcntl.LOCK_SH)
+            fcntl.flock(lock_file, fcntl.LOCK_UN)
diff --git a/pyfakefs/pytest_tests/hook_test/conftest.py b/pyfakefs/pytest_tests/hook_test/conftest.py
new file mode 100644
index 0000000..615d1d2
--- /dev/null
+++ b/pyfakefs/pytest_tests/hook_test/conftest.py
@@ -0,0 +1,25 @@
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
+from pathlib import Path
+
+import pytest
+
+
+# Used for testing paused patching during reporting.
+
+
+@pytest.hookimpl
+def pytest_runtest_logreport(report):
+    if report.when == "call":
+        report_path = Path(__file__).parent / "report.txt"
+        with open(report_path, "w") as f:
+            f.write("Test")
diff --git a/pyfakefs/pytest_tests/hook_test/pytest_hook_test.py b/pyfakefs/pytest_tests/hook_test/pytest_hook_test.py
new file mode 100644
index 0000000..c338827
--- /dev/null
+++ b/pyfakefs/pytest_tests/hook_test/pytest_hook_test.py
@@ -0,0 +1,38 @@
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
+from pathlib import Path
+
+import pytest
+
+
+@pytest.fixture
+def report_path():
+    yield Path(__file__).parent / "report.txt"
+
+
+def test_1(fs):
+    pass
+
+
+def test_2_report_in_real_fs(report_path):
+    print("test_2_report_in_real_fs")
+    assert report_path.exists()
+    report_path.unlink()
+
+
+def test_3(fs):
+    pass
+
+
+def test_4_report_in_real_fs(report_path):
+    assert report_path.exists()
+    report_path.unlink()
diff --git a/pyfakefs/pytest_tests/io.py b/pyfakefs/pytest_tests/io.py
index e6ea4bf..b5a46d3 100644
--- a/pyfakefs/pytest_tests/io.py
+++ b/pyfakefs/pytest_tests/io.py
@@ -10,5 +10,5 @@ class InputStream:
         self.name = name
 
     def read(self):
-        with open(self.name, "r") as f:
+        with open(self.name) as f:
             return f.readline()
diff --git a/pyfakefs/pytest_tests/lib_using_pathlib.py b/pyfakefs/pytest_tests/lib_using_pathlib.py
new file mode 100644
index 0000000..944c471
--- /dev/null
+++ b/pyfakefs/pytest_tests/lib_using_pathlib.py
@@ -0,0 +1,5 @@
+import pathlib
+
+
+def use_pathlib(path: str):
+    return pathlib.Path(path)
diff --git a/pyfakefs/pytest_tests/local_import.py b/pyfakefs/pytest_tests/local_import.py
new file mode 100644
index 0000000..afe2676
--- /dev/null
+++ b/pyfakefs/pytest_tests/local_import.py
@@ -0,0 +1,4 @@
+def load(path: str) -> str:
+    from pyfakefs.pytest_tests import lib_using_pathlib
+
+    return lib_using_pathlib.use_pathlib(path)
diff --git a/pyfakefs/pytest_tests/pytest_check_failed_plugin_test.py b/pyfakefs/pytest_tests/pytest_check_failed_plugin_test.py
index 2725cde..806a5a9 100644
--- a/pyfakefs/pytest_tests/pytest_check_failed_plugin_test.py
+++ b/pyfakefs/pytest_tests/pytest_check_failed_plugin_test.py
@@ -2,6 +2,7 @@
 Uses the output from running pytest with pytest_plugin_failing_helper.py.
 Regression test for #381.
 """
+
 import os
 
 import pytest
diff --git a/pyfakefs/pytest_tests/pytest_doctest_test.py b/pyfakefs/pytest_tests/pytest_doctest_test.py
index 9bb9c54..2d377bf 100644
--- a/pyfakefs/pytest_tests/pytest_doctest_test.py
+++ b/pyfakefs/pytest_tests/pytest_doctest_test.py
@@ -8,7 +8,6 @@ To run these doctests, install pytest and run:
 
 Add `-s` option to enable print statements.
 """
-from __future__ import unicode_literals
 
 
 def make_file_factory(func_name, fake, result):
diff --git a/pyfakefs/pytest_tests/pytest_fixture_param_test.py b/pyfakefs/pytest_tests/pytest_fixture_param_test.py
index e1c766f..5a72782 100644
--- a/pyfakefs/pytest_tests/pytest_fixture_param_test.py
+++ b/pyfakefs/pytest_tests/pytest_fixture_param_test.py
@@ -11,7 +11,6 @@
 # limitations under the License.
 
 # Example for a test using a custom pytest fixture with an argument to Patcher
-# Needs Python >= 3.6
 import os
 
 import pytest
diff --git a/pyfakefs/pytest_tests/pytest_fixture_test.py b/pyfakefs/pytest_tests/pytest_fixture_test.py
index 8bb377b..4259a58 100644
--- a/pyfakefs/pytest_tests/pytest_fixture_test.py
+++ b/pyfakefs/pytest_tests/pytest_fixture_test.py
@@ -11,12 +11,12 @@
 # limitations under the License.
 
 # Example for a test using a custom pytest fixture with an argument to Patcher
-# Needs Python >= 3.6
 
 import pytest
 
 import pyfakefs.pytest_tests.example as example
 from pyfakefs.fake_filesystem_unittest import Patcher
+from pyfakefs.pytest_tests import unhashable
 
 
 @pytest.mark.xfail
@@ -42,6 +42,11 @@ def test_example_file_passing_using_patcher():
         check_that_example_file_is_in_fake_fs()
 
 
+def test_unhashable(fs):
+    # regression test for #923
+    print(unhashable)
+
+
 def check_that_example_file_is_in_fake_fs():
     with open(example.EXAMPLE_FILE) as file:
         assert file.read() == "stuff here"
diff --git a/pyfakefs/pytest_tests/pytest_module_fixture_test.py b/pyfakefs/pytest_tests/pytest_module_fixture_test.py
index 3140ec9..e7d30a4 100644
--- a/pyfakefs/pytest_tests/pytest_module_fixture_test.py
+++ b/pyfakefs/pytest_tests/pytest_module_fixture_test.py
@@ -21,6 +21,11 @@ def use_fs(fs_module):
 
 
 @pytest.mark.usefixtures("fs")
-def test_fs_uses_fs_module():
+def test_fs_uses_fs_module1():
     # check that `fs` uses the same filesystem as `fs_module`
     assert os.path.exists(os.path.join("foo", "bar"))
+
+
+def test_fs_uses_fs_module2(fs):
+    # check that patching was not stopped by the first test
+    assert os.path.exists(os.path.join("foo", "bar"))
diff --git a/pyfakefs/pytest_tests/pytest_plugin_failing_helper.py b/pyfakefs/pytest_tests/pytest_plugin_failing_helper.py
index 0891018..cec614c 100644
--- a/pyfakefs/pytest_tests/pytest_plugin_failing_helper.py
+++ b/pyfakefs/pytest_tests/pytest_plugin_failing_helper.py
@@ -1,4 +1,4 @@
-""" Failing test to test stacktrace output - see
+"""Failing test to test stacktrace output - see
 ``pytest_check_failed_plugin_test.py``."""
 
 
diff --git a/pyfakefs/pytest_tests/pytest_plugin_test.py b/pyfakefs/pytest_tests/pytest_plugin_test.py
index 51f95cb..1bdd4f5 100644
--- a/pyfakefs/pytest_tests/pytest_plugin_test.py
+++ b/pyfakefs/pytest_tests/pytest_plugin_test.py
@@ -1,4 +1,5 @@
 """Tests that the pytest plugin properly provides the "fs" fixture"""
+
 import os
 import tempfile
 
@@ -76,3 +77,11 @@ def test_switch_to_linux(fs):
 def test_switch_to_macos(fs):
     fs.os = OSType.MACOS
     assert os.path.exists(tempfile.gettempdir())
+
+
+def test_updatecache_problem(fs):
+    # regression test for #1096
+    filename = r"C:\source_file"
+    fs.create_file(filename)
+    with open(filename):
+        assert True
diff --git a/pyfakefs/pytest_tests/pytest_reload_pandas_test.py b/pyfakefs/pytest_tests/pytest_reload_pandas_test.py
new file mode 100644
index 0000000..bb2c49f
--- /dev/null
+++ b/pyfakefs/pytest_tests/pytest_reload_pandas_test.py
@@ -0,0 +1,34 @@
+"""Regression test for #947.
+Ensures that reloading the `pandas.core.arrays.arrow.extension_types` module succeeds.
+"""
+
+from pathlib import Path
+
+import pytest
+
+try:
+    import pandas as pd
+except ImportError:
+    pd = None
+
+try:
+    import parquet
+except ImportError:
+    parquet = None
+
+
+@pytest.mark.skipif(
+    pd is None or parquet is None, reason="pandas or parquet not installed"
+)
+def test_1(fs):
+    dir_ = Path(__file__).parent / "data"
+    fs.add_real_directory(dir_)
+    pd.read_parquet(dir_ / "test.parquet")
+
+
+@pytest.mark.skipif(
+    pd is None or parquet is None, reason="pandas or parquet not installed"
+)
+def test_2():
+    dir_ = Path(__file__).parent / "data"
+    pd.read_parquet(dir_ / "test.parquet")
diff --git a/pyfakefs/pytest_tests/segfault_test.py b/pyfakefs/pytest_tests/segfault_test.py
deleted file mode 100644
index 05f46dc..0000000
--- a/pyfakefs/pytest_tests/segfault_test.py
+++ /dev/null
@@ -1,16 +0,0 @@
-"""
-This is a regression test for #866 that shall ensure that
-shutting down the test session after this specific call does not result
-in a segmentation fault.
-"""
-import opentimelineio as otio
-
-
-def test_empty_fs(fs):
-    pass
-
-
-def test_create_clip(fs):
-    """If the fs cache is not cleared during session shutdown, a segmentation fault
-    will happen during garbage collection of the cached modules."""
-    otio.core.SerializableObjectWithMetadata(metadata={})
diff --git a/pyfakefs/pytest_tests/test_reload_local_import.py b/pyfakefs/pytest_tests/test_reload_local_import.py
new file mode 100644
index 0000000..a29e06e
--- /dev/null
+++ b/pyfakefs/pytest_tests/test_reload_local_import.py
@@ -0,0 +1,26 @@
+import pytest
+
+from pyfakefs.fake_filesystem_unittest import Patcher
+from pyfakefs.fake_pathlib import FakePathlibModule
+from pyfakefs.helpers import reload_cleanup_handler
+from pyfakefs.pytest_tests import local_import
+
+
+@pytest.fixture
+def test_fs():
+    with Patcher() as patcher:
+        patcher.cleanup_handlers["pyfakefs.pytest_tests.lib_using_pathlib"] = (
+            reload_cleanup_handler
+        )
+        yield patcher.fs
+
+
+class TestReloadCleanupHandler:
+    def test1(self, test_fs):
+        path = local_import.load("some_path")
+        assert isinstance(path, FakePathlibModule.Path)
+
+    def test2(self):
+        path = local_import.load("some_path")
+        # will fail without reload handler
+        assert not isinstance(path, FakePathlibModule.Path)
diff --git a/pyfakefs/pytest_tests/unhashable.py b/pyfakefs/pytest_tests/unhashable.py
new file mode 100644
index 0000000..8d84855
--- /dev/null
+++ b/pyfakefs/pytest_tests/unhashable.py
@@ -0,0 +1,19 @@
+import sys
+import types
+
+
+class Unhashable(types.ModuleType):
+    """
+    Unhashable module, used for regression test for  #923.
+    """
+
+    @property
+    def Unhashable(self):
+        return self
+
+    def __eq__(self, other):
+        raise NotImplementedError("Cannot compare unhashable")
+
+
+if sys.modules[__name__] is not Unhashable:
+    sys.modules[__name__] = Unhashable("unhashable")
diff --git a/pyfakefs/tests/all_tests.py b/pyfakefs/tests/all_tests.py
index 36945af..2042884 100644
--- a/pyfakefs/tests/all_tests.py
+++ b/pyfakefs/tests/all_tests.py
@@ -32,6 +32,7 @@ from pyfakefs.tests import (
     fake_pathlib_test,
     fake_tempfile_test,
     patched_packages_test,
+    fake_legacy_modules_test,
     mox3_stubout_test,
 )
 
@@ -57,6 +58,7 @@ class AllTests(unittest.TestSuite):
                 loader.loadTestsFromModule(dynamic_patch_test),
                 loader.loadTestsFromModule(fake_pathlib_test),
                 loader.loadTestsFromModule(patched_packages_test),
+                loader.loadTestsFromModule(fake_legacy_modules_test),
             ]
         )
         return self
diff --git a/pyfakefs/tests/all_tests_without_extra_packages.py b/pyfakefs/tests/all_tests_without_extra_packages.py
index 8927802..822e7ce 100644
--- a/pyfakefs/tests/all_tests_without_extra_packages.py
+++ b/pyfakefs/tests/all_tests_without_extra_packages.py
@@ -16,16 +16,10 @@ Excludes tests using external scandir package."""
 import sys
 import unittest
 
-from pyfakefs import extra_packages
+from pyfakefs import legacy_packages
 
-if extra_packages.use_scandir_package:
-    extra_packages.use_scandir_package = False
-    try:
-        from os import scandir
-    except ImportError:
-        scandir = None
-    extra_packages.scandir = scandir
-    extra_packages.use_scandir = scandir
+legacy_packages.scandir = None
+legacy_packages.pathlib2 = None
 
 from pyfakefs.tests.all_tests import AllTests  # noqa: E402
 
diff --git a/pyfakefs/tests/dynamic_patch_test.py b/pyfakefs/tests/dynamic_patch_test.py
index bb8ac40..749caa1 100644
--- a/pyfakefs/tests/dynamic_patch_test.py
+++ b/pyfakefs/tests/dynamic_patch_test.py
@@ -13,6 +13,7 @@
 """
 Tests for patching modules loaded after `setUpPyfakefs()`.
 """
+
 import pathlib
 import unittest
 
@@ -27,7 +28,7 @@ class TestPyfakefsUnittestBase(fake_filesystem_unittest.TestCase):
 
 class DynamicImportPatchTest(TestPyfakefsUnittestBase):
     def __init__(self, methodName="runTest"):
-        super(DynamicImportPatchTest, self).__init__(methodName)
+        super().__init__(methodName)
 
     def test_os_patch(self):
         import os
@@ -59,7 +60,7 @@ class DynamicImportPatchTest(TestPyfakefsUnittestBase):
     def test_pathlib_path_patch(self):
         file_path = "test.txt"
         path = pathlib.Path(file_path)
-        with path.open("w") as f:
+        with path.open("w", encoding="utf8") as f:
             f.write("test")
 
         self.assertTrue(self.fs.exists(file_path))
diff --git a/pyfakefs/tests/example.py b/pyfakefs/tests/example.py
index 4ab9921..01b464a 100644
--- a/pyfakefs/tests/example.py
+++ b/pyfakefs/tests/example.py
@@ -61,13 +61,13 @@ def create_file(path):
     >>> create_file('/test/file.txt')
     >>> os.path.exists('/test/file.txt')
     True
-    >>> with open('/test/file.txt') as f:
+    >>> with open('/test/file.txt', encoding='utf8') as f:
     ...     f.readlines()
     ["This is test file '/test/file.txt'.\\n", \
 'It was created using open().\\n']
     """
-    with open(path, "w") as f:
-        f.write("This is test file '{0}'.\n".format(path))
+    with open(path, "w", encoding="utf8") as f:
+        f.write(f"This is test file '{path}'.\n")
         f.write("It was created using open().\n")
 
 
diff --git a/pyfakefs/tests/example_test.py b/pyfakefs/tests/example_test.py
index 126bbe7..83e301f 100644
--- a/pyfakefs/tests/example_test.py
+++ b/pyfakefs/tests/example_test.py
@@ -32,10 +32,14 @@ import sys
 import unittest
 
 from pyfakefs import fake_filesystem_unittest
-from pyfakefs.extra_packages import use_scandir_package
+from pyfakefs.legacy_packages import scandir
 from pyfakefs.tests import example  # The module under test
 
 
+# Work around pyupgrade auto-rewriting `io.open()` to `open()`.
+io_open = io.open
+
+
 def load_tests(loader, tests, ignore):
     """Load the pyfakefs/example.py doctest tests into unittest."""
     return fake_filesystem_unittest.load_doctests(loader, tests, ignore, example)
@@ -62,7 +66,7 @@ class TestExample(fake_filesystem_unittest.TestCase):  # pylint: disable=R0904
 
         # This is before setUpPyfakefs(), so still using the real file system
         self.filepath = os.path.realpath(__file__)
-        with io.open(self.filepath, "rb") as f:
+        with io_open(self.filepath, "rb") as f:
             self.real_contents = f.read()
 
         self.setUpPyfakefs()
@@ -85,7 +89,7 @@ class TestExample(fake_filesystem_unittest.TestCase):  # pylint: disable=R0904
 
     def test_delete_file(self):
         """Test example.delete_file() which uses `os.remove()`."""
-        self.fs.create_file("/test/full.txt", contents="First line\n" "Second Line\n")
+        self.fs.create_file("/test/full.txt", contents="First line\nSecond Line\n")
         self.assertTrue(os.path.exists("/test/full.txt"))
         example.delete_file("/test/full.txt")
         self.assertFalse(os.path.exists("/test/full.txt"))
@@ -143,9 +147,7 @@ class TestExample(fake_filesystem_unittest.TestCase):  # pylint: disable=R0904
         self.assertTrue(entries[1].is_symlink())
         self.assertTrue(entries[2].is_file())
 
-    @unittest.skipIf(
-        not use_scandir_package, "Testing only if scandir module is installed"
-    )
+    @unittest.skipIf(scandir is None, "Testing only if scandir module is installed")
     def test_scandir_scandir(self):
         """Test example.scandir() which uses `scandir.scandir()`.
 
diff --git a/pyfakefs/tests/fake_filesystem_glob_test.py b/pyfakefs/tests/fake_filesystem_glob_test.py
index 1ca141f..19dd142 100644
--- a/pyfakefs/tests/fake_filesystem_glob_test.py
+++ b/pyfakefs/tests/fake_filesystem_glob_test.py
@@ -14,8 +14,10 @@
 
 """Test for glob using fake_filesystem."""
 
+import contextlib
 import glob
 import os
+import sys
 import unittest
 
 from pyfakefs import fake_filesystem_unittest
@@ -71,7 +73,12 @@ class FakeGlobUnitTest(fake_filesystem_unittest.TestCase):
         self.assertEqual(["/[Temp]"], glob.glob("/*emp*"))
 
     def test_glob1(self):
-        self.assertEqual(["[Temp]"], glob.glob1("/", "*Tem*"))
+        with (
+            contextlib.nullcontext()
+            if sys.version_info < (3, 13)
+            else self.assertWarns(DeprecationWarning)
+        ):
+            self.assertEqual(["[Temp]"], glob.glob1("/", "*Tem*"))
 
     def test_has_magic(self):
         self.assertTrue(glob.has_magic("["))
diff --git a/pyfakefs/tests/fake_filesystem_shutil_test.py b/pyfakefs/tests/fake_filesystem_shutil_test.py
index 83d4672..209de51 100644
--- a/pyfakefs/tests/fake_filesystem_shutil_test.py
+++ b/pyfakefs/tests/fake_filesystem_shutil_test.py
@@ -17,6 +17,7 @@
 Note that almost all of the functionality is delegated to the real `shutil`
 and works correctly with the fake filesystem because of the faked `os` module.
 """
+
 import os
 import shutil
 import sys
@@ -137,7 +138,7 @@ class FakeShutilModuleTest(RealFsTestCase):
         self.create_file(os.path.join(dir_path, "bar"))
         file_path = os.path.join(dir_path, "baz")
         self.create_file(file_path)
-        with open(file_path):
+        with open(file_path, encoding="utf8"):
             shutil.rmtree(dir_path)
         self.assertFalse(os.path.exists(file_path))
 
@@ -148,7 +149,7 @@ class FakeShutilModuleTest(RealFsTestCase):
         self.create_file(os.path.join(dir_path, "bar"))
         file_path = os.path.join(dir_path, "baz")
         self.create_file(file_path)
-        with open(file_path):
+        with open(file_path, encoding="utf8"):
             with self.assertRaises(OSError):
                 shutil.rmtree(dir_path)
         self.assertTrue(os.path.exists(dir_path))
@@ -191,6 +192,15 @@ class FakeShutilModuleTest(RealFsTestCase):
         self.assertFalse(NonLocal.errorHandled)
         self.assertEqual(NonLocal.errorPath, "")
 
+    def test_rmtree_in_windows(self):
+        # regression test for #979
+        self.check_windows_only()
+        base_path = self.make_path("foo", "bar")
+        self.os.makedirs(self.os.path.join(base_path, "res"))
+        self.assertTrue(self.os.path.exists(base_path))
+        shutil.rmtree(base_path)
+        self.assertFalse(self.os.path.exists(base_path))
+
     def test_copy(self):
         src_file = self.make_path("xyzzy")
         dst_file = self.make_path("xyzzy_copy")
@@ -228,7 +238,7 @@ class FakeShutilModuleTest(RealFsTestCase):
         src_stat = os.stat(src_file)
         dst_stat = os.stat(dst_file)
         self.assertEqual(src_stat.st_mode, dst_stat.st_mode)
-        self.assertAlmostEqual(src_stat.st_atime, dst_stat.st_atime, places=2)
+        self.assertAlmostEqual(src_stat.st_atime, dst_stat.st_atime, places=0)
         self.assertAlmostEqual(src_stat.st_mtime, dst_stat.st_mtime, places=2)
 
     @unittest.skipIf(IS_PYPY, "Functionality not supported in PyPy")
@@ -255,7 +265,7 @@ class FakeShutilModuleTest(RealFsTestCase):
         src_stat = os.stat(src_file)
         dst_stat = os.stat(dst_file)
         self.assertEqual(src_stat.st_mode, dst_stat.st_mode)
-        self.assertAlmostEqual(src_stat.st_atime, dst_stat.st_atime, places=2)
+        self.assertAlmostEqual(src_stat.st_atime, dst_stat.st_atime, places=0)
         self.assertAlmostEqual(src_stat.st_mtime, dst_stat.st_mtime, places=2)
 
     def test_copy2_directory(self):
@@ -273,7 +283,7 @@ class FakeShutilModuleTest(RealFsTestCase):
         src_stat = os.stat(src_file)
         dst_stat = os.stat(dst_file)
         self.assertEqual(src_stat.st_mode, dst_stat.st_mode)
-        self.assertAlmostEqual(src_stat.st_atime, dst_stat.st_atime, places=2)
+        self.assertAlmostEqual(src_stat.st_atime, dst_stat.st_atime, places=0)
         self.assertAlmostEqual(src_stat.st_mtime, dst_stat.st_mtime, places=2)
 
     def test_copytree(self):
@@ -401,7 +411,7 @@ class RealShutilModuleTest(FakeShutilModuleTest):
 
 class FakeCopyFileTest(RealFsTestCase):
     def tearDown(self):
-        super(FakeCopyFileTest, self).tearDown()
+        super().tearDown()
 
     def test_common_case(self):
         src_file = self.make_path("xyzzy")
diff --git a/pyfakefs/tests/fake_filesystem_test.py b/pyfakefs/tests/fake_filesystem_test.py
index 696f8a8..9af21ee 100644
--- a/pyfakefs/tests/fake_filesystem_test.py
+++ b/pyfakefs/tests/fake_filesystem_test.py
@@ -17,8 +17,11 @@
 import contextlib
 import errno
 import os
+import pathlib
+import shutil
 import stat
 import sys
+import tempfile
 import unittest
 from unittest.mock import patch
 
@@ -229,6 +232,10 @@ class NormalizePathTest(TestCase):
         self.filesystem.cwd = "/foo"
         self.assertEqual("/foo/bar", self.filesystem.absnormpath(path))
 
+    def test_cwd_from_pathlib_path(self):
+        self.filesystem.cwd = pathlib.Path("/foo/bar")
+        self.assertEqual("/foo/bar", self.filesystem.cwd)
+
     def test_absolute_path_remains_unchanged(self):
         path = "foo/bar"
         self.assertEqual(self.root_name + path, self.filesystem.absnormpath(path))
@@ -513,6 +520,20 @@ class FakeFilesystemUnitTest(TestCase):
         self.assertEqual(os.path.basename(path), new_dir.name)
         self.assertTrue(stat.S_IFDIR & new_dir.st_mode)
 
+    def test_create_dir_umask(self):
+        old_umask = self.filesystem.umask
+        self.filesystem.umask = 0o22
+        path = "foo/bar/baz"
+        self.filesystem.create_dir(path, perm_bits=0o777)
+        new_dir = self.filesystem.get_object(path)
+        self.assertEqual(stat.S_IFDIR | 0o755, new_dir.st_mode)
+
+        path = "foo/bar/boo"
+        self.filesystem.create_dir(path, perm_bits=0o777, apply_umask=False)
+        new_dir = self.filesystem.get_object(path)
+        self.assertEqual(stat.S_IFDIR | 0o777, new_dir.st_mode)
+        self.filesystem.umask = old_umask
+
     def test_create_directory_already_exists_error(self):
         path = "foo/bar/baz"
         self.filesystem.create_dir(path)
@@ -581,8 +602,9 @@ class FakeFilesystemUnitTest(TestCase):
         new_file = self.filesystem.get_object(path)
         self.assertEqual(os.path.basename(path), new_file.name)
         if IS_WIN:
-            self.assertEqual(1, new_file.st_uid)
-            self.assertEqual(1, new_file.st_gid)
+            fake_id = 0 if is_root() else 1
+            self.assertEqual(fake_id, new_file.st_uid)
+            self.assertEqual(fake_id, new_file.st_gid)
         else:
             self.assertEqual(os.getuid(), new_file.st_uid)
             self.assertEqual(os.getgid(), new_file.st_gid)
@@ -603,7 +625,7 @@ class FakeFilesystemUnitTest(TestCase):
         fake_open = fake_filesystem.FakeFileOpen(self.filesystem)
         path = "foo/bar/baz"
         self.filesystem.create_file(path, contents=None)
-        with fake_open(path) as f:
+        with fake_open(path, encoding="utf8") as f:
             self.assertEqual("", f.read())
 
     def test_create_file_with_incorrect_mode_type(self):
@@ -953,8 +975,12 @@ class FakePathModuleTest(TestCase):
         self.filesystem.is_windows_fs = True
         self.assertTrue(self.path.isabs("C:!foo"))
         self.assertTrue(self.path.isabs(b"C:!foo"))
-        self.assertTrue(self.path.isabs("!"))
-        self.assertTrue(self.path.isabs(b"!"))
+        if sys.version_info < (3, 13):
+            self.assertTrue(self.path.isabs("!"))
+            self.assertTrue(self.path.isabs(b"!"))
+        else:
+            self.assertFalse(self.path.isabs("!"))
+            self.assertFalse(self.path.isabs(b"!"))
 
     def test_relpath(self):
         path_foo = "!path!to!foo"
@@ -1062,7 +1088,9 @@ class FakePathModuleTest(TestCase):
         components = [b"foo", b"bar", b"baz"]
         self.assertEqual(b"foo!bar!baz", self.path.join(*components))
 
-    @unittest.skipIf(sys.platform != "win32", "Windows specific test")
+    @unittest.skipIf(
+        sys.platform != "win32" or sys.version_info < (3, 8), "Windows specific test"
+    )
     @patch.dict(os.environ, {"USERPROFILE": r"C:\Users\John"})
     def test_expand_user_windows(self):
         self.assertEqual(self.path.expanduser("~"), "C:!Users!John")
@@ -1232,7 +1260,7 @@ class FakePathModuleTest(TestCase):
         if private_path_function:
             self.assertTrue(
                 hasattr(self.path, private_path_function),
-                "Get a real os.path function " "not implemented in fake os.path",
+                "Get a real os.path function not implemented in fake os.path",
             )
         self.assertFalse(hasattr(self.path, "nonexistent"))
 
@@ -1244,6 +1272,22 @@ class FakePathModuleTest(TestCase):
             ("", "!!", "foo!!bar"), self.filesystem.splitroot("!!foo!!bar")
         )
 
+    @unittest.skipIf(sys.version_info < (3, 13), "Introduced in Python 3.13")
+    @unittest.skipIf(TestCase.is_windows, "Posix specific behavior")
+    def test_is_reserved_posix(self):
+        self.assertFalse(self.filesystem.isreserved("!dev"))
+        self.assertFalse(self.filesystem.isreserved("!"))
+        self.assertFalse(self.filesystem.isreserved("COM1"))
+        self.assertFalse(self.filesystem.isreserved("nul.txt"))
+
+    @unittest.skipIf(sys.version_info < (3, 13), "Introduced in Python 3.13")
+    @unittest.skipIf(not TestCase.is_windows, "Windows specific behavior")
+    def test_is_reserved_windows(self):
+        self.assertFalse(self.filesystem.isreserved("!dev"))
+        self.assertFalse(self.filesystem.isreserved("!"))
+        self.assertTrue(self.filesystem.isreserved("COM1"))
+        self.assertTrue(self.filesystem.isreserved("nul.txt"))
+
 
 class PathManipulationTestBase(TestCase):
     def setUp(self):
@@ -1645,7 +1689,7 @@ class DiskSpaceTest(TestCase):
         self.fs.add_mount_point("!mount", total_size)
 
         def create_too_large_file():
-            with self.open("!mount!file", "w") as dest:
+            with self.open("!mount!file", "w", encoding="utf8") as dest:
                 dest.write("a" * (total_size + 1))
 
         with self.assertRaises(OSError):
@@ -1653,7 +1697,7 @@ class DiskSpaceTest(TestCase):
 
         self.assertEqual(0, self.fs.get_disk_usage("!mount").used)
 
-        with self.open("!mount!file", "w") as dest:
+        with self.open("!mount!file", "w", encoding="utf8") as dest:
             dest.write("a" * total_size)
 
         self.assertEqual(total_size, self.fs.get_disk_usage("!mount").used)
@@ -1727,7 +1771,7 @@ class DiskSpaceTest(TestCase):
             self.fs.create_file("!foo!bar", contents=b"a" * 100)
         except OSError:
             self.fail(
-                "File with contents fitting into disk space " "could not be written."
+                "File with contents fitting into disk space could not be written."
             )
 
         self.assertEqual(initial_usage.used + 100, self.fs.get_disk_usage().used)
@@ -1819,7 +1863,7 @@ class DiskSpaceTest(TestCase):
             self.fs.create_file("!mount_unlimited!foo", st_size=1000000)
         except OSError:
             self.fail(
-                "File with contents fitting into " "disk space could not be written."
+                "File with contents fitting into disk space could not be written."
             )
 
     def test_that_disk_usage_of_correct_mount_point_is_used(self):
@@ -1878,50 +1922,50 @@ class DiskSpaceTest(TestCase):
         self.assertEqual(dest_file.contents, source_file.contents)
 
     def test_diskusage_after_open_write(self):
-        with self.open("bar.txt", "w") as f:
+        with self.open("bar.txt", "w", encoding="utf8") as f:
             f.write("a" * 60)
             f.flush()
         self.assertEqual(60, self.fs.get_disk_usage()[1])
 
     def test_disk_full_after_reopened(self):
-        with self.open("bar.txt", "w") as f:
+        with self.open("bar.txt", "w", encoding="utf8") as f:
             f.write("a" * 60)
-        with self.open("bar.txt") as f:
+        with self.open("bar.txt", encoding="utf8") as f:
             self.assertEqual("a" * 60, f.read())
         with self.raises_os_error(errno.ENOSPC):
-            with self.open("bar.txt", "w") as f:
+            with self.open("bar.txt", "w", encoding="utf8") as f:
                 f.write("b" * 110)
                 with self.raises_os_error(errno.ENOSPC):
                     f.flush()
-        with self.open("bar.txt") as f:
+        with self.open("bar.txt", encoding="utf8") as f:
             self.assertEqual("", f.read())
 
     def test_disk_full_append(self):
         file_path = "bar.txt"
-        with self.open(file_path, "w") as f:
+        with self.open(file_path, "w", encoding="utf8") as f:
             f.write("a" * 60)
-        with self.open(file_path) as f:
+        with self.open(file_path, encoding="utf8") as f:
             self.assertEqual("a" * 60, f.read())
         with self.raises_os_error(errno.ENOSPC):
-            with self.open(file_path, "a") as f:
+            with self.open(file_path, "a", encoding="utf8") as f:
                 f.write("b" * 41)
                 with self.raises_os_error(errno.ENOSPC):
                     f.flush()
-        with self.open("bar.txt") as f:
+        with self.open("bar.txt", encoding="utf8") as f:
             self.assertEqual(f.read(), "a" * 60)
 
     def test_disk_full_after_reopened_rplus_seek(self):
-        with self.open("bar.txt", "w") as f:
+        with self.open("bar.txt", "w", encoding="utf8") as f:
             f.write("a" * 60)
-        with self.open("bar.txt") as f:
+        with self.open("bar.txt", encoding="utf8") as f:
             self.assertEqual(f.read(), "a" * 60)
         with self.raises_os_error(errno.ENOSPC):
-            with self.open("bar.txt", "r+") as f:
+            with self.open("bar.txt", "r+", encoding="utf8") as f:
                 f.seek(50)
                 f.write("b" * 60)
                 with self.raises_os_error(errno.ENOSPC):
                     f.flush()
-        with self.open("bar.txt") as f:
+        with self.open("bar.txt", encoding="utf8") as f:
             self.assertEqual(f.read(), "a" * 60)
 
 
@@ -2044,10 +2088,91 @@ class RealFileSystemAccessTest(RealFsTestCase):
         with self.raises_os_error(errno.EEXIST):
             self.filesystem.add_real_file(real_file_path)
 
-    def test_existing_fake_directory_raises(self):
-        self.filesystem.create_dir(self.root_path)
-        with self.raises_os_error(errno.EEXIST):
-            self.filesystem.add_real_directory(self.root_path)
+    @contextlib.contextmanager
+    def create_real_paths(self):
+        temp_directory = tempfile.mkdtemp()
+        real_dir_root = os.path.join(temp_directory, "root")
+        try:
+            for dir_name in ("foo", "bar"):
+                real_dir = os.path.join(real_dir_root, dir_name)
+                os.makedirs(real_dir, exist_ok=True)
+                with open(
+                    os.path.join(real_dir, "test.txt"), "w", encoding="utf8"
+                ) as f:
+                    f.write("test")
+                sub_dir = os.path.join(real_dir, "sub")
+                os.makedirs(sub_dir, exist_ok=True)
+                with open(os.path.join(sub_dir, "sub.txt"), "w", encoding="utf8") as f:
+                    f.write("sub")
+            yield real_dir_root
+        finally:
+            shutil.rmtree(temp_directory, ignore_errors=True)
+
+    def test_existing_fake_directory_is_merged_lazily(self):
+        self.filesystem.create_file(os.path.join("/", "root", "foo", "test1.txt"))
+        self.filesystem.create_dir(os.path.join("root", "baz"))
+        with self.create_real_paths() as root_dir:
+            self.filesystem.add_real_directory(root_dir, target_path="/root")
+            self.assertTrue(
+                self.filesystem.exists(os.path.join("root", "foo", "test.txt"))
+            )
+            self.assertTrue(
+                self.filesystem.exists(os.path.join("root", "foo", "test1.txt"))
+            )
+            self.assertTrue(
+                self.filesystem.exists(os.path.join("root", "bar", "sub", "sub.txt"))
+            )
+            self.assertTrue(self.filesystem.exists(os.path.join("root", "baz")))
+
+    def test_existing_fake_directory_is_merged(self):
+        self.filesystem.create_file(os.path.join("/", "root", "foo", "test1.txt"))
+        self.filesystem.create_dir(os.path.join("root", "baz"))
+        with self.create_real_paths() as root_dir:
+            self.filesystem.add_real_directory(
+                root_dir, target_path="/root", lazy_read=False
+            )
+            self.assertTrue(
+                self.filesystem.exists(os.path.join("root", "foo", "test.txt"))
+            )
+            self.assertTrue(
+                self.filesystem.exists(os.path.join("root", "foo", "test1.txt"))
+            )
+            self.assertTrue(
+                self.filesystem.exists(os.path.join("root", "bar", "sub", "sub.txt"))
+            )
+            self.assertTrue(self.filesystem.exists(os.path.join("root", "baz")))
+
+    def test_fake_files_cannot_be_overwritten(self):
+        self.filesystem.create_file(os.path.join("/", "root", "foo", "test.txt"))
+        with self.create_real_paths() as root_dir:
+            with self.raises_os_error(errno.EEXIST):
+                self.filesystem.add_real_directory(root_dir, target_path="/root")
+
+    def test_cannot_overwrite_file_with_dir(self):
+        self.filesystem.create_file(os.path.join("/", "root", "foo"))
+        with self.create_real_paths() as root_dir:
+            with self.raises_os_error(errno.ENOTDIR):
+                self.filesystem.add_real_directory(root_dir, target_path="/root/")
+
+    def test_cannot_overwrite_symlink_with_dir(self):
+        self.filesystem.create_symlink(
+            os.path.join("/", "root", "foo"), os.path.join("/", "root", "link")
+        )
+        with self.create_real_paths() as root_dir:
+            with self.raises_os_error(errno.EEXIST):
+                self.filesystem.add_real_directory(root_dir, target_path="/root/")
+
+    def test_symlink_is_merged(self):
+        self.skip_if_symlink_not_supported()
+        self.filesystem.create_dir(os.path.join("/", "root", "foo"))
+        with self.create_real_paths() as root_dir:
+            link_path = os.path.join(root_dir, "link.txt")
+            target_path = os.path.join("foo", "sub", "sub.txt")
+            os.symlink(target_path, link_path)
+            self.filesystem.add_real_directory(root_dir, target_path="/root")
+            fake_link_path = os.path.join("/", "root", "link.txt")
+            self.assertTrue(self.filesystem.exists(fake_link_path))
+            self.assertTrue(self.filesystem.islink(fake_link_path))
 
     def check_fake_file_stat(self, fake_file, real_file_path, target_path=None):
         if target_path is None or target_path == real_file_path:
@@ -2121,7 +2246,7 @@ class RealFileSystemAccessTest(RealFsTestCase):
         # regression test for #470
         real_file_path = os.path.abspath(__file__)
         self.filesystem.add_real_file(real_file_path, read_only=False)
-        with self.fake_open(real_file_path, "w") as f:
+        with self.fake_open(real_file_path, "w", encoding="utf8") as f:
             f.write("foo")
 
         with self.fake_open(real_file_path, "rb") as f:
@@ -2172,14 +2297,23 @@ class RealFileSystemAccessTest(RealFsTestCase):
         for link in symlinks:
             os.symlink(link[0], link[1])
 
-        yield
-
-        for link in symlinks:
-            os.unlink(link[1])
+        try:
+            yield
+        finally:
+            for link in symlinks:
+                os.unlink(link[1])
+
+    @staticmethod
+    def _setup_temp_directory():
+        real_directory = tempfile.mkdtemp()
+        os.mkdir(os.path.join(real_directory, "fixtures"))
+        with open(os.path.join(real_directory, "all_tests.py"), "w"):
+            pass
+        return real_directory
 
     def test_add_existing_real_directory_symlink(self):
         fake_open = fake_filesystem.FakeFileOpen(self.filesystem)
-        real_directory = os.path.join(self.root_path, "pyfakefs", "tests")
+        real_directory = self._setup_temp_directory()
         symlinks = [
             (
                 "..",
@@ -2207,7 +2341,7 @@ class RealFileSystemAccessTest(RealFsTestCase):
 
         self.filesystem.create_file("/etc/something")
 
-        with fake_open("/etc/something", "w") as f:
+        with fake_open("/etc/something", "w", encoding="utf8") as f:
             f.write("good morning")
 
         try:
@@ -2225,9 +2359,7 @@ class RealFileSystemAccessTest(RealFsTestCase):
         self.assertTrue(
             self.filesystem.exists(
                 os.path.join(
-                    self.root_path,
-                    "pyfakefs",
-                    "tests",
+                    real_directory,
                     "fixtures/symlink_dir_relative",
                 )
             )
@@ -2235,9 +2367,7 @@ class RealFileSystemAccessTest(RealFsTestCase):
         self.assertTrue(
             self.filesystem.exists(
                 os.path.join(
-                    self.root_path,
-                    "pyfakefs",
-                    "tests",
+                    real_directory,
                     "fixtures/symlink_dir_relative/all_tests.py",
                 )
             )
@@ -2245,9 +2375,7 @@ class RealFileSystemAccessTest(RealFsTestCase):
         self.assertTrue(
             self.filesystem.exists(
                 os.path.join(
-                    self.root_path,
-                    "pyfakefs",
-                    "tests",
+                    real_directory,
                     "fixtures/symlink_file_relative",
                 )
             )
@@ -2257,9 +2385,7 @@ class RealFileSystemAccessTest(RealFsTestCase):
         self.assertTrue(
             self.filesystem.exists(
                 os.path.join(
-                    self.root_path,
-                    "pyfakefs",
-                    "tests",
+                    real_directory,
                     "fixtures/symlink_dir_absolute",
                 )
             )
@@ -2267,9 +2393,7 @@ class RealFileSystemAccessTest(RealFsTestCase):
         self.assertTrue(
             self.filesystem.exists(
                 os.path.join(
-                    self.root_path,
-                    "pyfakefs",
-                    "tests",
+                    real_directory,
                     "fixtures/symlink_dir_absolute/all_tests.py",
                 )
             )
@@ -2277,9 +2401,7 @@ class RealFileSystemAccessTest(RealFsTestCase):
         self.assertTrue(
             self.filesystem.exists(
                 os.path.join(
-                    self.root_path,
-                    "pyfakefs",
-                    "tests",
+                    real_directory,
                     "fixtures/symlink_file_absolute",
                 )
             )
@@ -2289,9 +2411,7 @@ class RealFileSystemAccessTest(RealFsTestCase):
         self.assertTrue(
             self.filesystem.exists(
                 os.path.join(
-                    self.root_path,
-                    "pyfakefs",
-                    "tests",
+                    real_directory,
                     "fixtures/symlink_file_absolute_outside",
                 )
             )
@@ -2299,18 +2419,17 @@ class RealFileSystemAccessTest(RealFsTestCase):
         self.assertEqual(
             fake_open(
                 os.path.join(
-                    self.root_path,
-                    "pyfakefs",
-                    "tests",
+                    real_directory,
                     "fixtures/symlink_file_absolute_outside",
-                )
+                ),
+                encoding="utf8",
             ).read(),
             "good morning",
         )
 
     def test_add_existing_real_directory_symlink_target_path(self):
-        self.skip_if_symlink_not_supported(force_real_fs=True)
-        real_directory = os.path.join(self.root_path, "pyfakefs", "tests")
+        self.skip_if_symlink_not_supported()
+        real_directory = self._setup_temp_directory()
         symlinks = [
             (
                 "..",
@@ -2334,8 +2453,8 @@ class RealFileSystemAccessTest(RealFsTestCase):
         self.assertTrue(self.filesystem.exists("/path/fixtures/symlink_file_relative"))
 
     def test_add_existing_real_directory_symlink_lazy_read(self):
-        self.skip_if_symlink_not_supported(force_real_fs=True)
-        real_directory = os.path.join(self.root_path, "pyfakefs", "tests")
+        self.skip_if_symlink_not_supported()
+        real_directory = self._setup_temp_directory()
         symlinks = [
             (
                 "..",
@@ -2364,11 +2483,6 @@ class RealFileSystemAccessTest(RealFsTestCase):
                 self.filesystem.exists("/path/fixtures/symlink_file_relative")
             )
 
-    def test_add_existing_real_directory_tree_to_existing_path(self):
-        self.filesystem.create_dir("/foo/bar")
-        with self.raises_os_error(errno.EEXIST):
-            self.filesystem.add_real_directory(self.root_path, target_path="/foo/bar")
-
     def test_add_existing_real_directory_tree_to_other_path(self):
         self.filesystem.add_real_directory(self.root_path, target_path="/foo/bar")
         self.assertFalse(
@@ -2418,7 +2532,7 @@ class RealFileSystemAccessTest(RealFsTestCase):
         self.filesystem.set_disk_usage(disk_size, real_dir_path)
         self.filesystem.add_real_directory(real_dir_path)
 
-        # the directory contents have not been read, the the disk usage
+        # the directory contents have not been read, the disk usage
         # has not changed
         self.assertEqual(disk_size, self.filesystem.get_disk_usage(real_dir_path).free)
         # checking for existence shall read the directory contents
@@ -2508,14 +2622,14 @@ class FileSideEffectTests(TestCase):
     def test_side_effect_called(self):
         fake_open = fake_filesystem.FakeFileOpen(self.filesystem)
         self.side_effect_called = False
-        with fake_open("/a/b/file_one", "w") as handle:
+        with fake_open("/a/b/file_one", "w", encoding="utf8") as handle:
             handle.write("foo")
         self.assertTrue(self.side_effect_called)
 
     def test_side_effect_file_object(self):
         fake_open = fake_filesystem.FakeFileOpen(self.filesystem)
         self.side_effect_called = False
-        with fake_open("/a/b/file_one", "w") as handle:
+        with fake_open("/a/b/file_one", "w", encoding="utf8") as handle:
             handle.write("foo")
         self.assertEqual(self.side_effect_file_object_content, "foo")
 
diff --git a/pyfakefs/tests/fake_filesystem_unittest_test.py b/pyfakefs/tests/fake_filesystem_unittest_test.py
index 86f1ae6..24d6e78 100644
--- a/pyfakefs/tests/fake_filesystem_unittest_test.py
+++ b/pyfakefs/tests/fake_filesystem_unittest_test.py
@@ -17,7 +17,9 @@
 """
 Test the :py:class`pyfakefs.fake_filesystem_unittest.TestCase` base class.
 """
+
 import glob
+import importlib.util
 import io
 import multiprocessing
 import os
@@ -28,6 +30,8 @@ import sys
 import tempfile
 import unittest
 import warnings
+from contextlib import redirect_stdout
+from io import StringIO
 from pathlib import Path
 from unittest import TestCase, mock
 
@@ -48,18 +52,22 @@ if sys.version_info < (3, 12):
     from distutils.dir_util import copy_tree, remove_tree
 
 
+# Work around pyupgrade auto-rewriting `io.open()` to `open()`.
+io_open = io.open
+
+
 class TestPatcher(TestCase):
     def test_context_manager(self):
         with Patcher() as patcher:
             patcher.fs.create_file("/foo/bar", contents="test")
-            with open("/foo/bar") as f:
+            with open("/foo/bar", encoding="utf8") as f:
                 contents = f.read()
             self.assertEqual("test", contents)
 
     @patchfs
     def test_context_decorator(self, fake_fs):
         fake_fs.create_file("/foo/bar", contents="test")
-        with open("/foo/bar") as f:
+        with open("/foo/bar", encoding="utf8") as f:
             contents = f.read()
         self.assertEqual("test", contents)
 
@@ -69,7 +77,7 @@ class TestPatchfsArgumentOrder(TestCase):
     @mock.patch("os.system")
     def test_argument_order1(self, fake_fs, patched_system):
         fake_fs.create_file("/foo/bar", contents="test")
-        with open("/foo/bar") as f:
+        with open("/foo/bar", encoding="utf8") as f:
             contents = f.read()
         self.assertEqual("test", contents)
         os.system("foo")
@@ -79,7 +87,7 @@ class TestPatchfsArgumentOrder(TestCase):
     @patchfs
     def test_argument_order2(self, patched_system, fake_fs):
         fake_fs.create_file("/foo/bar", contents="test")
-        with open("/foo/bar") as f:
+        with open("/foo/bar", encoding="utf8") as f:
             contents = f.read()
         self.assertEqual("test", contents)
         os.system("foo")
@@ -98,26 +106,26 @@ class TestPyfakefsUnittest(TestPyfakefsUnittestBase):  # pylint: disable=R0904
     def test_open(self):
         """Fake `open()` function is bound"""
         self.assertFalse(os.path.exists("/fake_file.txt"))
-        with open("/fake_file.txt", "w") as f:
+        with open("/fake_file.txt", "w", encoding="utf8") as f:
             f.write("This test file was created using the open() function.\n")
         self.assertTrue(self.fs.exists("/fake_file.txt"))
-        with open("/fake_file.txt") as f:
+        with open("/fake_file.txt", encoding="utf8") as f:
             content = f.read()
         self.assertEqual(
-            "This test file was created using the " "open() function.\n",
+            "This test file was created using the open() function.\n",
             content,
         )
 
     def test_io_open(self):
         """Fake io module is bound"""
         self.assertFalse(os.path.exists("/fake_file.txt"))
-        with io.open("/fake_file.txt", "w") as f:
-            f.write("This test file was created using the" " io.open() function.\n")
+        with io_open("/fake_file.txt", "w", encoding="utf8") as f:
+            f.write("This test file was created using the io.open() function.\n")
         self.assertTrue(self.fs.exists("/fake_file.txt"))
-        with open("/fake_file.txt") as f:
+        with open("/fake_file.txt", encoding="utf8") as f:
             content = f.read()
         self.assertEqual(
-            "This test file was created using the " "io.open() function.\n",
+            "This test file was created using the io.open() function.\n",
             content,
         )
 
@@ -156,7 +164,7 @@ class TestPyfakefsUnittest(TestPyfakefsUnittestBase):  # pylint: disable=R0904
 
     def test_fakepathlib(self):
         p = pathlib.Path("/fake_file.txt")
-        with p.open("w") as f:
+        with p.open("w", encoding="utf8") as f:
             f.write("text")
         is_windows = sys.platform.startswith("win")
         if is_windows:
@@ -228,14 +236,12 @@ class TestPatchingImports(TestPyfakefsUnittestBase):
         stat_result = pyfakefs.tests.import_as_example.file_stat2(file_path)
         self.assertEqual(3, stat_result.st_size)
 
-    @unittest.skipIf(sys.version_info >= (3, 12), "Currently not working in 3.12")
     def test_import_open_as_other_name(self):
         file_path = "/foo/bar"
         self.fs.create_file(file_path, contents=b"abc")
         contents = pyfakefs.tests.import_as_example.file_contents1(file_path)
         self.assertEqual("abc", contents)
 
-    @unittest.skipIf(sys.version_info >= (3, 12), "Currently not working in 3.12")
     def test_import_io_open_as_other_name(self):
         file_path = "/foo/bar"
         self.fs.create_file(file_path, contents=b"abc")
@@ -398,10 +404,6 @@ class AdditionalSkipNamesTest(fake_filesystem_unittest.TestCase):
         self.fs.create_file("foo")
         self.assertFalse(pyfakefs.tests.import_as_example.check_if_exists7("foo"))
 
-    @unittest.skipIf(
-        sys.version_info >= (3, 12),
-        "Skip modules currently not working for open in 3.12",
-    )
     def test_open_succeeds(self):
         pyfakefs.tests.import_as_example.open_this_file()
 
@@ -447,10 +449,6 @@ class AdditionalSkipNamesModuleTest(fake_filesystem_unittest.TestCase):
         self.fs.create_file("foo")
         self.assertFalse(pyfakefs.tests.import_as_example.check_if_exists7("foo"))
 
-    @unittest.skipIf(
-        sys.version_info >= (3, 12),
-        "Skip modules currently not working for open in 3.12",
-    )
     def test_open_succeeds(self):
         pyfakefs.tests.import_as_example.open_this_file()
 
@@ -458,6 +456,36 @@ class AdditionalSkipNamesModuleTest(fake_filesystem_unittest.TestCase):
         pyfakefs.tests.import_as_example.return_this_file_path()
 
 
+class RuntimeSkipModuleTest(fake_filesystem_unittest.TestCase):
+    """Emulates skipping a module using RUNTIME_SKIPMODULES.
+    Not all functionality implemented for skip modules will work here."""
+
+    def setUp(self):
+        Patcher.RUNTIME_SKIPMODULES.update(
+            {"pyfakefs.tests.import_as_example": ["pyfakefs.tests.import_"]}
+        )
+        self.setUpPyfakefs()
+
+    def tearDown(self):
+        del self.patcher.RUNTIME_SKIPMODULES["pyfakefs.tests.import_as_example"]
+
+    def test_fake_path_does_not_exist1(self):
+        self.fs.create_file("foo")
+        self.assertFalse(pyfakefs.tests.import_as_example.check_if_exists1("foo"))
+
+    def test_fake_path_does_not_exist2(self):
+        self.fs.create_file("foo")
+        self.assertFalse(pyfakefs.tests.import_as_example.check_if_exists2("foo"))
+
+    def test_fake_path_does_not_exist3(self):
+        self.fs.create_file("foo")
+        self.assertFalse(pyfakefs.tests.import_as_example.check_if_exists3("foo"))
+
+    def test_fake_path_does_not_exist4(self):
+        self.fs.create_file("foo")
+        self.assertFalse(pyfakefs.tests.import_as_example.check_if_exists4("foo"))
+
+
 class FakeExampleModule:
     """Used to patch a function that uses system-specific functions that
     cannot be patched automatically."""
@@ -538,18 +566,13 @@ class NoRootUserTest(fake_filesystem_unittest.TestCase):
         self.fs.create_file(file_path)
         os.chmod(file_path, 0o400)
         with self.assertRaises(OSError):
-            open(file_path, "w")
+            open(file_path, "w", encoding="utf8")
 
 
 class PauseResumeTest(fake_filesystem_unittest.TestCase):
     def setUp(self):
-        self.real_temp_file = None
         self.setUpPyfakefs()
 
-    def tearDown(self):
-        if self.real_temp_file is not None:
-            self.real_temp_file.close()
-
     def test_pause_resume(self):
         fake_temp_file = tempfile.NamedTemporaryFile()
         self.assertTrue(self.fs.exists(fake_temp_file.name))
@@ -557,11 +580,11 @@ class PauseResumeTest(fake_filesystem_unittest.TestCase):
         self.pause()
         self.assertTrue(self.fs.exists(fake_temp_file.name))
         self.assertFalse(os.path.exists(fake_temp_file.name))
-        self.real_temp_file = tempfile.NamedTemporaryFile()
-        self.assertFalse(self.fs.exists(self.real_temp_file.name))
-        self.assertTrue(os.path.exists(self.real_temp_file.name))
+        real_temp_file = tempfile.NamedTemporaryFile()
+        self.assertFalse(self.fs.exists(real_temp_file.name))
+        self.assertTrue(os.path.exists(real_temp_file.name))
         self.resume()
-        self.assertFalse(os.path.exists(self.real_temp_file.name))
+        self.assertFalse(os.path.exists(real_temp_file.name))
         self.assertTrue(os.path.exists(fake_temp_file.name))
 
     def test_pause_resume_fs(self):
@@ -574,15 +597,15 @@ class PauseResumeTest(fake_filesystem_unittest.TestCase):
         self.fs.pause()
         self.assertTrue(self.fs.exists(fake_temp_file.name))
         self.assertFalse(os.path.exists(fake_temp_file.name))
-        self.real_temp_file = tempfile.NamedTemporaryFile()
-        self.assertFalse(self.fs.exists(self.real_temp_file.name))
-        self.assertTrue(os.path.exists(self.real_temp_file.name))
+        real_temp_file = tempfile.NamedTemporaryFile()
+        self.assertFalse(self.fs.exists(real_temp_file.name))
+        self.assertTrue(os.path.exists(real_temp_file.name))
         # pause does nothing if already paused
         self.fs.pause()
-        self.assertFalse(self.fs.exists(self.real_temp_file.name))
-        self.assertTrue(os.path.exists(self.real_temp_file.name))
+        self.assertFalse(self.fs.exists(real_temp_file.name))
+        self.assertTrue(os.path.exists(real_temp_file.name))
         self.fs.resume()
-        self.assertFalse(os.path.exists(self.real_temp_file.name))
+        self.assertFalse(os.path.exists(real_temp_file.name))
         self.assertTrue(os.path.exists(fake_temp_file.name))
 
     def test_pause_resume_contextmanager(self):
@@ -592,10 +615,10 @@ class PauseResumeTest(fake_filesystem_unittest.TestCase):
         with Pause(self):
             self.assertTrue(self.fs.exists(fake_temp_file.name))
             self.assertFalse(os.path.exists(fake_temp_file.name))
-            self.real_temp_file = tempfile.NamedTemporaryFile()
-            self.assertFalse(self.fs.exists(self.real_temp_file.name))
-            self.assertTrue(os.path.exists(self.real_temp_file.name))
-        self.assertFalse(os.path.exists(self.real_temp_file.name))
+            real_temp_file = tempfile.NamedTemporaryFile()
+            self.assertFalse(self.fs.exists(real_temp_file.name))
+            self.assertTrue(os.path.exists(real_temp_file.name))
+        self.assertFalse(os.path.exists(real_temp_file.name))
         self.assertTrue(os.path.exists(fake_temp_file.name))
 
     def test_pause_resume_fs_contextmanager(self):
@@ -605,10 +628,10 @@ class PauseResumeTest(fake_filesystem_unittest.TestCase):
         with Pause(self.fs):
             self.assertTrue(self.fs.exists(fake_temp_file.name))
             self.assertFalse(os.path.exists(fake_temp_file.name))
-            self.real_temp_file = tempfile.NamedTemporaryFile()
-            self.assertFalse(self.fs.exists(self.real_temp_file.name))
-            self.assertTrue(os.path.exists(self.real_temp_file.name))
-        self.assertFalse(os.path.exists(self.real_temp_file.name))
+            real_temp_file = tempfile.NamedTemporaryFile()
+            self.assertFalse(self.fs.exists(real_temp_file.name))
+            self.assertTrue(os.path.exists(real_temp_file.name))
+        self.assertFalse(os.path.exists(real_temp_file.name))
         self.assertTrue(os.path.exists(fake_temp_file.name))
 
     def test_pause_resume_without_patcher(self):
@@ -616,6 +639,13 @@ class PauseResumeTest(fake_filesystem_unittest.TestCase):
         with self.assertRaises(RuntimeError):
             fs.resume()
 
+    def test_that_tempfile_is_patched_after_resume(fs):
+        """Regression test for #1098"""
+        fs.pause()
+        fs.resume()
+        with tempfile.NamedTemporaryFile():
+            pass
+
 
 class PauseResumePatcherTest(fake_filesystem_unittest.TestCase):
     def test_pause_resume(self):
@@ -761,10 +791,6 @@ class PathlibTest(TestCase):
 
 
 class TestDeprecationSuppression(fake_filesystem_unittest.TestCase):
-    @unittest.skipIf(
-        sys.version_info[1] == 6,
-        "Test fails for Python 3.6 for unknown reason",
-    )
     def test_no_deprecation_warning(self):
         """Ensures that deprecation warnings are suppressed during module
         lookup, see #542.
@@ -791,6 +817,7 @@ def load_configs(configs):
     return retval
 
 
+@unittest.skipIf(sys.version_info < (3, 8), "open_code new in Python 3.8")
 class AutoPatchOpenCodeTestCase(fake_filesystem_unittest.TestCase):
     """Test patching open_code in auto mode, see issue #554."""
 
@@ -810,6 +837,17 @@ class AutoPatchOpenCodeTestCase(fake_filesystem_unittest.TestCase):
     def test_run_module(self):
         load_configs([self.config_module])
 
+    def import_foo(self):
+        spec = importlib.util.spec_from_file_location("bar", "/foo/bar.py")
+        mod = importlib.util.module_from_spec(spec)
+        spec.loader.exec_module(mod)
+
+    def test_exec_module_in_fake_fs(self):
+        self.fs.create_file("/foo/bar.py", contents="print('hello')")
+        with redirect_stdout(StringIO()) as stdout:
+            self.import_foo()
+        assert stdout.getvalue() == "hello\n"
+
 
 class TestOtherFS(fake_filesystem_unittest.TestCase):
     def setUp(self):
@@ -822,11 +860,11 @@ class TestOtherFS(fake_filesystem_unittest.TestCase):
         if self.fs.is_windows_fs:
             self.fs.is_macos = False
         self.fs.add_real_file(__file__)
-        with open(__file__) as f:
+        with open(__file__, encoding="utf8") as f:
             self.assertTrue(f.read())
         home = Path.home()
         os.chdir(home)
-        with open(__file__) as f:
+        with open(__file__, encoding="utf8") as f:
             self.assertTrue(f.read())
 
     def test_windows(self):
@@ -844,7 +882,7 @@ class TestOtherFS(fake_filesystem_unittest.TestCase):
         self.assertEqual("/", os.altsep)
         self.assertEqual(";", os.pathsep)
         self.assertEqual("\r\n", os.linesep)
-        self.assertEqual("nul", os.devnull)
+        self.assertEqual("NUL", os.devnull)
 
     def test_linux(self):
         self.fs.os = OSType.LINUX
@@ -889,6 +927,13 @@ class TestOtherFS(fake_filesystem_unittest.TestCase):
         os.chdir(folder)
         self.assertTrue(os.path.exists(str(file_path.relative_to(folder))))
 
+    @unittest.skipIf(sys.platform != "win32", "Windows-specific test")
+    def test_tempfile_access(self):
+        # regression test for #912
+        self.fs.os = OSType.LINUX
+        tmp_file = tempfile.TemporaryFile()
+        assert tmp_file
+
 
 @unittest.skipIf(sys.platform != "win32", "Windows-specific behavior")
 class TestAbsolutePathOnWindows(fake_filesystem_unittest.TestCase):
@@ -907,7 +952,7 @@ class TestClassSetup(fake_filesystem_unittest.TestCase):
 
     def test_using_fs_functions(self):
         self.assertTrue(os.path.exists("foo/bar"))
-        with open("foo/bar") as f:
+        with open("foo/bar", encoding="utf8") as f:
             contents = f.read()
         self.assertEqual("test", contents)
 
@@ -917,5 +962,68 @@ class TestClassSetup(fake_filesystem_unittest.TestCase):
         self.assertEqual("test", f.contents)
 
 
+class TestTempPathCreation(fake_filesystem_unittest.TestCase):
+    """Regression test for #965. Checks that the temp file system
+    is properly created with a root-owned root path.
+    """
+
+    def setUp(self):
+        self.setUpPyfakefs()
+
+    def check_write_tmp_after_reset(self, os_type):
+        self.fs.os = os_type
+        # Mark '/' to be modifiable by only root
+        os.chown("/", 0, 0)
+        os.chmod("/", 0b111_101_101)
+        with tempfile.TemporaryFile("wb") as f:
+            assert f.write(b"foo") == 3
+
+    def test_write_tmp_linux(self):
+        self.check_write_tmp_after_reset(OSType.LINUX)
+
+    def test_write_tmp_macos(self):
+        self.check_write_tmp_after_reset(OSType.MACOS)
+
+    def test_write_tmp_windows(self):
+        self.check_write_tmp_after_reset(OSType.WINDOWS)
+
+
+@unittest.skipIf(sys.version_info < (3, 8), "Not available before Python 3.8")
+class FakeImportTest(fake_filesystem_unittest.TestCase):
+    """Checks that a fake module can be imported in AUTO patch mode."""
+
+    def setUp(self):
+        self.setUpPyfakefs(patch_open_code=PatchMode.AUTO)
+
+    def test_simple_fake_import(self):
+        fake_module_path = Path("/") / "site-packages" / "fake_module.py"
+        self.fs.create_file(fake_module_path, contents="number = 42")
+        sys.path.insert(0, str(fake_module_path.parent))
+        module = importlib.import_module("fake_module")
+        del sys.path[0]
+        assert module.__name__ == "fake_module"
+        assert module.number == 42
+
+    def test_fake_import_dotted_module(self):
+        fake_pkg_path = Path("/") / "site-packages"
+        self.fs.create_file(fake_pkg_path / "fakepkg" / "__init__.py")
+        fake_module_path = fake_pkg_path / "fakepkg" / "fake_module.py"
+        self.fs.create_file(fake_module_path, contents="number = 42")
+        sys.path.insert(0, str(fake_pkg_path))
+        module = importlib.import_module("fakepkg.fake_module")
+        del sys.path[0]
+        assert module.__name__ == "fakepkg.fake_module"
+        assert module.number == 42
+
+    def test_fake_relative_import(self):
+        fake_module_path = Path("site-packages") / "fake_module.py"
+        self.fs.create_file(fake_module_path, contents="number = 42")
+        sys.path.insert(0, str(fake_module_path.parent))
+        module = importlib.import_module("fake_module")
+        del sys.path[0]
+        assert module.__name__ == "fake_module"
+        assert module.number == 42
+
+
 if __name__ == "__main__":
     unittest.main()
diff --git a/pyfakefs/tests/fake_filesystem_vs_real_test.py b/pyfakefs/tests/fake_filesystem_vs_real_test.py
index 3cc8f6c..c0dc5ee 100644
--- a/pyfakefs/tests/fake_filesystem_vs_real_test.py
+++ b/pyfakefs/tests/fake_filesystem_vs_real_test.py
@@ -65,10 +65,10 @@ class FakeFilesystemVsRealTest(TestCase):
             os.mkdir(real_path)
             self.fake_os.mkdir(fake_path)
         if file_type == "f":
-            fh = open(real_path, "w")
+            fh = open(real_path, "w", encoding="utf8")
             fh.write(contents or "")
             fh.close()
-            fh = self.fake_open(fake_path, "w")
+            fh = self.fake_open(fake_path, "w", encoding="utf8")
             fh.write(contents or "")
             fh.close()
         # b for binary file
@@ -179,7 +179,7 @@ class FakeFilesystemVsRealTest(TestCase):
         def _error_class(exc):
             if exc:
                 if hasattr(exc, "errno"):
-                    return "{}({})".format(exc.__class__.__name__, exc.errno)
+                    return f"{exc.__class__.__name__}({exc.errno})"
                 return exc.__class__.__name__
             return "None"
 
@@ -192,18 +192,18 @@ class FakeFilesystemVsRealTest(TestCase):
         # is almost always different because of the file paths.
         if _error_class(real_err) != _error_class(fake_err):
             if real_err is None:
-                return "%s: real version returned %s, fake raised %s" % (
+                return "{}: real version returned {}, fake raised {}".format(
                     method_call,
                     real_value,
                     _error_class(fake_err),
                 )
             if fake_err is None:
-                return "%s: real version raised %s, fake returned %s" % (
+                return "{}: real version raised {}, fake returned {}".format(
                     method_call,
                     _error_class(real_err),
                     fake_value,
                 )
-            return "%s: real version raised %s, fake raised %s" % (
+            return "{}: real version raised {}, fake raised {}".format(
                 method_call,
                 _error_class(real_err),
                 _error_class(fake_err),
@@ -211,7 +211,7 @@ class FakeFilesystemVsRealTest(TestCase):
         real_errno = _get_errno(real_err)
         fake_errno = _get_errno(fake_err)
         if real_errno != fake_errno:
-            return "%s(%s): both raised %s, real errno %s, fake errno %s" % (
+            return "{}({}): both raised {}, real errno {}, fake errno {}".format(
                 method_name,
                 path,
                 _error_class(real_err),
@@ -230,7 +230,7 @@ class FakeFilesystemVsRealTest(TestCase):
                 real_value = real_value[len(self.real_base) :]
                 fake_value = fake_value[len(self.fake_base) :]
         if real_value != fake_value:
-            return "%s: real return %s, fake returned %s" % (
+            return "{}: real return {}, fake returned {}".format(
                 method_call,
                 real_value,
                 fake_value,
@@ -318,8 +318,11 @@ class FakeFilesystemVsRealTest(TestCase):
         Returns:
             A description of the difference in behavior, or None.
         """
-        with open(path, mode) as real_fh:
-            with self.fake_open(path, mode) as fake_fh:
+        kwargs = {}
+        if "b" not in mode:
+            kwargs["encoding"] = "utf8"
+        with open(path, mode, **kwargs) as real_fh:
+            with self.fake_open(path, mode, **kwargs) as fake_fh:
                 return self._compare_behaviors(
                     method_name, data, real_fh, fake_fh, method_returns_data
                 )
@@ -469,7 +472,7 @@ class FakeFilesystemVsRealTest(TestCase):
             )
 
         if not is_exception_equal:
-            msg = "Behaviors don't match on open with args %s & kwargs %s.\n" % (
+            msg = "Behaviors don't match on open with args {} & kwargs {}.\n".format(
                 args,
                 kwargs,
             )
diff --git a/pyfakefs/tests/fake_legacy_modules_test.py b/pyfakefs/tests/fake_legacy_modules_test.py
new file mode 100644
index 0000000..cce2a30
--- /dev/null
+++ b/pyfakefs/tests/fake_legacy_modules_test.py
@@ -0,0 +1,118 @@
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
+import unittest
+
+from pyfakefs.fake_filesystem_unittest import TestCase
+from pyfakefs.fake_legacy_modules import FakeScanDirModule, FakePathlib2Module
+from pyfakefs.legacy_packages import pathlib2, scandir
+from pyfakefs.tests.fake_os_test import FakeScandirTest
+from pyfakefs.tests.fake_pathlib_test import (
+    FakePathlibInitializationTest,
+    FakePathlibPathFileOperationTest,
+    FakePathlibFileObjectPropertyTest,
+    FakePathlibUsageInOsFunctionsTest,
+)
+
+
+class DeprecationWarningTest(TestCase):
+    def setUp(self):
+        self.setUpPyfakefs()
+
+    @unittest.skipIf(scandir is None, "The scandir package is not installed")
+    def test_scandir_warning(self):
+        FakeScanDirModule.has_warned = False
+        with self.assertWarns(DeprecationWarning):
+            scandir.scandir("/")
+
+    @unittest.skipIf(pathlib2 is None, "The pathlib2 package is not installed")
+    def test_pathlib2_warning(self):
+        FakePathlib2Module.has_warned = False
+        with self.assertWarns(DeprecationWarning):
+            pathlib2.Path("/foo")
+
+
+@unittest.skipIf(scandir is None, "The scandir package is not installed")
+class FakeScandirPackageTest(FakeScandirTest):
+    def used_scandir(self):
+        import pyfakefs.fake_legacy_modules
+
+        def fake_scan_dir(p):
+            return pyfakefs.fake_legacy_modules.FakeScanDirModule(
+                self.filesystem
+            ).scandir(p)
+
+        return fake_scan_dir
+
+    def test_path_like(self):
+        unittest.skip("Path-like objects not available in scandir package")
+
+
+class RealScandirPackageTest(FakeScandirPackageTest):
+    def used_scandir(self):
+        from scandir import scandir
+
+        return scandir
+
+    def use_real_fs(self):
+        return True
+
+
+@unittest.skipIf(pathlib2 is None, "The pathlib2 package is not installed")
+class FakePathlib2InitializationTest(FakePathlibInitializationTest):
+    def used_pathlib(self):
+        return pathlib2
+
+
+class RealPathlib2InitializationTest(FakePathlib2InitializationTest):
+    def use_real_fs(self):
+        return True
+
+
+@unittest.skipIf(pathlib2 is None, "The pathlib2 package is not installed")
+class FakePathlib2FileObjectPropertyTest(FakePathlibFileObjectPropertyTest):
+    def used_pathlib(self):
+        return pathlib2
+
+
+class RealPathlib2FileObjectPropertyTest(FakePathlib2FileObjectPropertyTest):
+    def use_real_fs(self):
+        return True
+
+
+@unittest.skipIf(pathlib2 is None, "The pathlib2 package is not installed")
+class FakePathlib2PathFileOperationTest(FakePathlibPathFileOperationTest):
+    def used_pathlib(self):
+        return pathlib2
+
+    def test_is_junction(self):
+        unittest.skip("is_junction not available in pathlib2")
+
+
+class RealPathlibPath2FileOperationTest(FakePathlib2PathFileOperationTest):
+    def use_real_fs(self):
+        return True
+
+
+@unittest.skipIf(pathlib2 is None, "The pathlib2 package is not installed")
+class FakePathlib2UsageInOsFunctionsTest(FakePathlibUsageInOsFunctionsTest):
+    def used_pathlib(self):
+        return pathlib2
+
+
+class RealPathlib2UsageInOsFunctionsTest(FakePathlib2UsageInOsFunctionsTest):
+    def use_real_fs(self):
+        return True
+
+
+if __name__ == "__main__":
+    unittest.main(verbosity=2)
diff --git a/pyfakefs/tests/fake_open_test.py b/pyfakefs/tests/fake_open_test.py
index d04bb79..f5ffa87 100644
--- a/pyfakefs/tests/fake_open_test.py
+++ b/pyfakefs/tests/fake_open_test.py
@@ -17,7 +17,6 @@
 
 import errno
 import io
-import locale
 import os
 import stat
 import sys
@@ -25,15 +24,16 @@ import time
 import unittest
 
 from pyfakefs import fake_filesystem, helpers
-from pyfakefs.helpers import is_root, IS_PYPY
+from pyfakefs.helpers import is_root, IS_PYPY, get_locale_encoding
 from pyfakefs.fake_io import FakeIoModule
-from pyfakefs.fake_filesystem_unittest import PatchMode
+from pyfakefs.fake_filesystem_unittest import PatchMode, Patcher
+from pyfakefs.tests.skipped_pathlib import read_open
 from pyfakefs.tests.test_utils import RealFsTestCase
 
 
 class FakeFileOpenTestBase(RealFsTestCase):
     def setUp(self):
-        super(FakeFileOpenTestBase, self).setUp()
+        super().setUp()
         if self.use_real_fs():
             self.open = io.open
         else:
@@ -46,11 +46,11 @@ class FakeFileOpenTestBase(RealFsTestCase):
 
 class FakeFileOpenTest(FakeFileOpenTestBase):
     def setUp(self):
-        super(FakeFileOpenTest, self).setUp()
+        super().setUp()
         self.orig_time = time.time
 
     def tearDown(self):
-        super(FakeFileOpenTest, self).tearDown()
+        super().tearDown()
         time.time = self.orig_time
 
     def test_open_no_parent_dir(self):
@@ -64,13 +64,13 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
         file_path = "boo!far"
         self.os.mkdir(file_dir)
         self.open = fake_filesystem.FakeFileOpen(self.filesystem, delete_on_close=True)
-        with self.open(file_path, "w"):
+        with self.open(file_path, "w", encoding="utf8"):
             self.assertTrue(self.filesystem.exists(file_path))
         self.assertFalse(self.filesystem.exists(file_path))
 
     def test_no_delete_on_close_by_default(self):
         file_path = self.make_path("czar")
-        with self.open(file_path, "w"):
+        with self.open(file_path, "w", encoding="utf8"):
             self.assertTrue(self.os.path.exists(file_path))
         self.assertTrue(self.os.path.exists(file_path))
 
@@ -79,7 +79,7 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
         self.open = fake_filesystem.FakeFileOpen(self.filesystem, delete_on_close=True)
         file_path = "foo"
         self.assertFalse(self.os.path.exists(file_path))
-        with self.open(file_path, "w"):
+        with self.open(file_path, "w", encoding="utf8"):
             self.assertTrue(self.os.path.exists(file_path))
         # After the 'with' statement, the close() method should have been
         # called.
@@ -92,13 +92,13 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
         # usually not UTF-8, but something like Latin1, depending on the locale
         text_fractions = "Ümläüts"
         try:
-            with self.open(file_path, "w") as f:
+            with self.open(file_path, "w", encoding=get_locale_encoding()) as f:
                 f.write(text_fractions)
         except UnicodeEncodeError:
             # see https://github.com/pytest-dev/pyfakefs/issues/623
             self.skipTest("This test does not work with an ASCII locale")
 
-        with self.open(file_path) as f:
+        with self.open(file_path, encoding=get_locale_encoding()) as f:
             contents = f.read()
         self.assertEqual(contents, text_fractions)
 
@@ -117,16 +117,14 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
         file_path = self.make_path("foo")
         str_contents = "Äsgül"
         try:
-            with self.open(file_path, "w") as f:
+            with self.open(file_path, "w", encoding=get_locale_encoding()) as f:
                 f.write(str_contents)
-        except UnicodeEncodeError:
+            with self.open(file_path, "rb") as f:
+                contents = f.read()
+            self.assertEqual(str_contents, contents.decode(get_locale_encoding()))
+        except UnicodeError:
             # see https://github.com/pytest-dev/pyfakefs/issues/623
             self.skipTest("This test does not work with an ASCII locale")
-        with self.open(file_path, "rb") as f:
-            contents = f.read()
-        self.assertEqual(
-            str_contents, contents.decode(locale.getpreferredencoding(False))
-        )
 
     def test_open_valid_file(self):
         contents = [
@@ -137,7 +135,7 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
         ]
         file_path = self.make_path("bar.txt")
         self.create_file(file_path, contents="".join(contents))
-        with self.open(file_path) as fake_file:
+        with self.open(file_path, encoding="utf8") as fake_file:
             self.assertEqual(contents, fake_file.readlines())
 
     def test_open_valid_args(self):
@@ -148,10 +146,15 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
         file_path = self.make_path("abbey_road", "maxwell")
         self.create_file(file_path, contents="".join(contents))
 
-        with self.open(file_path, buffering=1) as f:
+        with self.open(file_path, encoding="utf8", buffering=1) as f:
             self.assertEqual(contents, f.readlines())
         with self.open(
-            file_path, buffering=1, errors="strict", newline="\n", opener=None
+            file_path,
+            encoding="utf8",
+            buffering=1,
+            errors="strict",
+            newline="\n",
+            opener=None,
         ) as f:
             expected_contents = [
                 contents[0][:-1] + self.os.linesep,
@@ -169,7 +172,7 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
         file_path = self.make_path("bar.txt")
         self.create_file(file_path, contents="".join(contents))
         self.os.chdir(self.base_path)
-        with self.open(file_path) as f:
+        with self.open(file_path, encoding="utf8") as f:
             self.assertEqual(contents, f.readlines())
 
     def test_iterate_over_file(self):
@@ -179,7 +182,7 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
         ]
         file_path = self.make_path("abbey_road", "maxwell")
         self.create_file(file_path, contents="\n".join(contents))
-        with self.open(file_path) as fake_file:
+        with self.open(file_path, encoding="utf8") as fake_file:
             result = [line.rstrip() for line in fake_file]
         self.assertEqual(contents, result)
 
@@ -188,7 +191,7 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
         result = []
         file_path = self.make_path("foo.txt")
         self.create_file(file_path, contents="".join(contents))
-        with self.open(file_path) as fake_file:
+        with self.open(file_path, encoding="utf8") as fake_file:
             result.append(next(fake_file))
             result.append(next(fake_file))
         self.assertEqual(contents, result)
@@ -214,10 +217,10 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
         file_dir = self.make_path("abbey_road")
         file_path = self.os.path.join(file_dir, "here_comes_the_sun")
         self.os.mkdir(file_dir)
-        with self.open(file_path, "w") as fake_file:
+        with self.open(file_path, "w", encoding="utf8") as fake_file:
             for line in contents:
                 fake_file.write(line + "\n")
-        with self.open(file_path) as fake_file:
+        with self.open(file_path, encoding="utf8") as fake_file:
             result = [line.rstrip() for line in fake_file]
         self.assertEqual(contents, result)
 
@@ -230,10 +233,10 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
         file_dir = self.make_path("abbey_road")
         file_path = self.os.path.join(file_dir, "here_comes_the_sun")
         self.os.mkdir(file_dir)
-        with self.open(file_path, "a") as fake_file:
+        with self.open(file_path, "a", encoding="utf8") as fake_file:
             for line in contents:
                 fake_file.write(line + "\n")
-        with self.open(file_path) as fake_file:
+        with self.open(file_path, encoding="utf8") as fake_file:
             result = [line.rstrip() for line in fake_file]
         self.assertEqual(contents, result)
 
@@ -249,9 +252,9 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
         file_path = self.os.path.join(file_dir, "bar")
         self.os.mkdir(file_dir)
         contents = "String contents"
-        with self.open(file_path, "x") as fake_file:
+        with self.open(file_path, "x", encoding="utf8") as fake_file:
             fake_file.write(contents)
-        with self.open(file_path) as fake_file:
+        with self.open(file_path, encoding="utf8") as fake_file:
             self.assertEqual(contents, fake_file.read())
 
     def test_exclusive_create_binary_file(self):
@@ -271,24 +274,24 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
             "Only these lines",
             "should be in the file.",
         ]
-        with self.open(file_path, "w") as fake_file:
+        with self.open(file_path, "w", encoding="utf8") as fake_file:
             for line in new_contents:
                 fake_file.write(line + "\n")
-        with self.open(file_path) as fake_file:
+        with self.open(file_path, encoding="utf8") as fake_file:
             result = [line.rstrip() for line in fake_file]
         self.assertEqual(new_contents, result)
 
     def test_append_existing_file(self):
         file_path = self.make_path("appendfile")
         contents = [
-            "Contents of original file" "Appended contents",
+            "Contents of original fileAppended contents",
         ]
 
         self.create_file(file_path, contents=contents[0])
-        with self.open(file_path, "a") as fake_file:
+        with self.open(file_path, "a", encoding="utf8") as fake_file:
             for line in contents[1:]:
                 fake_file.write(line + "\n")
-        with self.open(file_path) as fake_file:
+        with self.open(file_path, encoding="utf8") as fake_file:
             result = [line.rstrip() for line in fake_file]
         self.assertEqual(contents, result)
 
@@ -297,10 +300,10 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
         file_path = self.make_path("wplus_file")
         self.create_file(file_path, contents="old contents")
         self.assertTrue(self.os.path.exists(file_path))
-        with self.open(file_path, "r") as fake_file:
+        with self.open(file_path, "r", encoding="utf8") as fake_file:
             self.assertEqual("old contents", fake_file.read())
         # actual tests
-        with self.open(file_path, "w+") as fake_file:
+        with self.open(file_path, "w+", encoding="utf8") as fake_file:
             fake_file.write("new contents")
             fake_file.seek(0)
             self.assertTrue("new contents", fake_file.read())
@@ -310,10 +313,10 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
         file_path = self.make_path("wplus_file")
         self.create_file(file_path, contents="old contents")
         self.assertTrue(self.os.path.exists(file_path))
-        with self.open(file_path, "r") as fake_file:
+        with self.open(file_path, "r", encoding="utf8") as fake_file:
             self.assertEqual("old contents", fake_file.read())
         # actual tests
-        with self.open(file_path, "w+") as fake_file:
+        with self.open(file_path, "w+", encoding="utf8") as fake_file:
             fake_file.seek(0)
             self.assertEqual("", fake_file.read())
 
@@ -327,7 +330,7 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
         additional_contents = ["These new lines\n", "like you a lot.\n"]
         file_path = self.make_path("appendfile")
         self.create_file(file_path, contents="".join(contents))
-        with self.open(file_path, "a") as fake_file:
+        with self.open(file_path, "a", encoding="utf8") as fake_file:
             with self.assertRaises(io.UnsupportedOperation):
                 fake_file.read(0)
             with self.assertRaises(io.UnsupportedOperation):
@@ -338,14 +341,14 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
             fake_file.seek(0)
             self.assertEqual(0, fake_file.tell())
             fake_file.writelines(additional_contents)
-        with self.open(file_path) as fake_file:
+        with self.open(file_path, encoding="utf8") as fake_file:
             self.assertEqual(contents + additional_contents, fake_file.readlines())
 
     def check_append_with_aplus(self):
         file_path = self.make_path("aplus_file")
         self.create_file(file_path, contents="old contents")
         self.assertTrue(self.os.path.exists(file_path))
-        with self.open(file_path, "r") as fake_file:
+        with self.open(file_path, "r", encoding="utf8") as fake_file:
             self.assertEqual("old contents", fake_file.read())
 
         if self.filesystem:
@@ -353,7 +356,7 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
             self.open = fake_filesystem.FakeFileOpen(
                 self.filesystem, delete_on_close=True
             )
-        with self.open(file_path, "a+") as fake_file:
+        with self.open(file_path, "a+", encoding="utf8") as fake_file:
             self.assertEqual(12, fake_file.tell())
             fake_file.write("new contents")
             self.assertEqual(24, fake_file.tell())
@@ -373,10 +376,10 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
         file_path = self.make_path("aplus_file")
         self.create_file(file_path, contents="old contents")
         self.assertTrue(self.os.path.exists(file_path))
-        with self.open(file_path, "r") as fake_file:
+        with self.open(file_path, "r", encoding="utf8") as fake_file:
             self.assertEqual("old contents", fake_file.read())
         # actual tests
-        with self.open(file_path, "a+") as fake_file:
+        with self.open(file_path, "a+", encoding="utf8") as fake_file:
             fake_file.seek(0)
             fake_file.write("new contents")
             fake_file.seek(0)
@@ -385,7 +388,7 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
 
     def test_read_empty_file_with_aplus(self):
         file_path = self.make_path("aplus_file")
-        with self.open(file_path, "a+") as fake_file:
+        with self.open(file_path, "a+", encoding="utf8") as fake_file:
             self.assertEqual("", fake_file.read())
 
     def test_read_with_rplus(self):
@@ -393,10 +396,10 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
         file_path = self.make_path("rplus_file")
         self.create_file(file_path, contents="old contents here")
         self.assertTrue(self.os.path.exists(file_path))
-        with self.open(file_path, "r") as fake_file:
+        with self.open(file_path, "r", encoding="utf8") as fake_file:
             self.assertEqual("old contents here", fake_file.read())
         # actual tests
-        with self.open(file_path, "r+") as fake_file:
+        with self.open(file_path, "r+", encoding="utf8") as fake_file:
             self.assertEqual("old contents here", fake_file.read())
             fake_file.seek(0)
             fake_file.write("new contents")
@@ -418,11 +421,11 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
         file_path = self.make_path("target_file")
         self.create_with_permission(file_path, 0o700)
         # actual tests
-        self.open(file_path, "r").close()
-        self.open(file_path, "w").close()
-        self.open(file_path, "w+").close()
+        self.open(file_path, "r", encoding="utf8").close()
+        self.open(file_path, "w", encoding="utf8").close()
+        self.open(file_path, "w+", encoding="utf8").close()
         with self.assertRaises(ValueError):
-            self.open(file_path, "INV")
+            self.open(file_path, "INV", encoding="utf8")
 
     def test_open_flags400(self):
         # set up
@@ -430,13 +433,13 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
         file_path = self.make_path("target_file")
         self.create_with_permission(file_path, 0o400)
         # actual tests
-        self.open(file_path, "r").close()
+        self.open(file_path, "r", encoding="utf8").close()
         if not is_root():
             self.assert_raises_os_error(errno.EACCES, self.open, file_path, "w")
             self.assert_raises_os_error(errno.EACCES, self.open, file_path, "w+")
         else:
-            self.open(file_path, "w").close()
-            self.open(file_path, "w+").close()
+            self.open(file_path, "w", encoding="utf8").close()
+            self.open(file_path, "w+", encoding="utf8").close()
 
     def test_open_flags200(self):
         # set up
@@ -444,15 +447,15 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
         file_path = self.make_path("target_file")
         self.create_with_permission(file_path, 0o200)
         # actual tests
-        self.open(file_path, "w").close()
+        self.open(file_path, "w", encoding="utf8").close()
         if not is_root():
             with self.assertRaises(OSError):
-                self.open(file_path, "r")
+                self.open(file_path, "r", encoding="utf8")
             with self.assertRaises(OSError):
-                self.open(file_path, "w+")
+                self.open(file_path, "w+", encoding="utf8")
         else:
-            self.open(file_path, "r").close()
-            self.open(file_path, "w+").close()
+            self.open(file_path, "r", encoding="utf8").close()
+            self.open(file_path, "w+", encoding="utf8").close()
 
     def test_open_flags100(self):
         # set up
@@ -462,15 +465,15 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
         # actual tests
         if not is_root():
             with self.assertRaises(OSError):
-                self.open(file_path, "r")
+                self.open(file_path, "r", encoding="utf8")
             with self.assertRaises(OSError):
-                self.open(file_path, "w")
+                self.open(file_path, "w", encoding="utf8")
             with self.assertRaises(OSError):
-                self.open(file_path, "w+")
+                self.open(file_path, "w+", encoding="utf8")
         else:
-            self.open(file_path, "r").close()
-            self.open(file_path, "w").close()
-            self.open(file_path, "w+").close()
+            self.open(file_path, "r", encoding="utf8").close()
+            self.open(file_path, "w", encoding="utf8").close()
+            self.open(file_path, "w+", encoding="utf8").close()
 
     def test_follow_link_read(self):
         self.skip_if_symlink_not_supported()
@@ -480,7 +483,7 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
         self.create_file(target, contents=target_contents)
         self.create_symlink(link_path, target)
         self.assert_equal_paths(target, self.os.readlink(link_path))
-        fh = self.open(link_path, "r")
+        fh = self.open(link_path, "r", encoding="utf8")
         got_contents = fh.read()
         fh.close()
         self.assertEqual(target_contents, got_contents)
@@ -493,9 +496,9 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
         self.create_symlink(link_path, target)
         self.assertFalse(self.os.path.exists(target))
 
-        with self.open(link_path, "w") as fh:
+        with self.open(link_path, "w", encoding="utf8") as fh:
             fh.write(target_contents)
-        with self.open(target, "r") as fh:
+        with self.open(target, "r", encoding="utf8") as fh:
             got_contents = fh.read()
         self.assertEqual(target_contents, got_contents)
 
@@ -516,9 +519,9 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
         self.assertFalse(self.os.path.exists(target))
 
         target_contents = "real baz contents"
-        with self.open(link_path, "w") as fh:
+        with self.open(link_path, "w", encoding="utf8") as fh:
             fh.write(target_contents)
-        with self.open(target, "r") as fh:
+        with self.open(target, "r", encoding="utf8") as fh:
             got_contents = fh.read()
         self.assertEqual(target_contents, got_contents)
 
@@ -539,9 +542,9 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
         third_path = self.make_path("some_file3")
         self.create_file(third_path, contents="contents here3")
 
-        with self.open(first_path) as fake_file1:
-            with self.open(second_path) as fake_file2:
-                with self.open(third_path) as fake_file3:
+        with self.open(first_path, encoding="utf8") as fake_file1:
+            with self.open(second_path, encoding="utf8") as fake_file2:
+                with self.open(third_path, encoding="utf8") as fake_file3:
                     fileno2 = fake_file2.fileno()
                     self.assertGreater(fileno2, fake_file1.fileno())
                     self.assertGreater(fake_file3.fileno(), fileno2)
@@ -551,12 +554,12 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
         self.create_file(first_path, contents="contents here1")
         second_path = self.make_path("some_file2")
         self.create_file(second_path, contents="contents here2")
-        with self.open(first_path) as fake_file1:
-            with self.open(second_path) as fake_file2:
-                with self.open(first_path) as fake_file1a:
+        with self.open(first_path, encoding="utf8") as fake_file1:
+            with self.open(second_path, encoding="utf8") as fake_file2:
+                with self.open(first_path, encoding="utf8") as fake_file1a:
                     fileno2 = fake_file2.fileno()
-                    self.assertGreater(fileno2, fake_file1.fileno())
-                    self.assertGreater(fake_file1a.fileno(), fileno2)
+                    self.assertNotEqual(fileno2, fake_file1.fileno())
+                    self.assertNotEqual(fake_file1a.fileno(), fileno2)
 
     def test_reused_file_descriptors_do_not_affect_others(self):
         first_path = self.make_path("some_file1")
@@ -566,17 +569,17 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
         third_path = self.make_path("some_file3")
         self.create_file(third_path, contents="contents here3")
 
-        with self.open(first_path, "r") as fake_file1:
-            with self.open(second_path, "r") as fake_file2:
-                fake_file3 = self.open(third_path, "r")
-                fake_file1a = self.open(first_path, "r")
+        with self.open(first_path, "r", encoding="utf8") as fake_file1:
+            with self.open(second_path, "r", encoding="utf8") as fake_file2:
+                fake_file3 = self.open(third_path, "r", encoding="utf8")
+                fake_file1a = self.open(first_path, "r", encoding="utf8")
                 fileno1 = fake_file1.fileno()
                 fileno2 = fake_file2.fileno()
                 fileno3 = fake_file3.fileno()
                 fileno4 = fake_file1a.fileno()
 
-        with self.open(second_path, "r") as fake_file2:
-            with self.open(first_path, "r") as fake_file1b:
+        with self.open(second_path, "r", encoding="utf8") as fake_file2:
+            with self.open(first_path, "r", encoding="utf8") as fake_file1b:
                 self.assertEqual(fileno1, fake_file2.fileno())
                 self.assertEqual(fileno2, fake_file1b.fileno())
                 self.assertEqual(fileno3, fake_file3.fileno())
@@ -588,8 +591,8 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
         file_path = self.make_path("some_file")
         self.create_file(file_path)
 
-        with self.open(file_path, "a") as writer:
-            with self.open(file_path, "r") as reader:
+        with self.open(file_path, "a", encoding="utf8") as writer:
+            with self.open(file_path, "r", encoding="utf8") as reader:
                 writes = [
                     "hello",
                     "world\n",
@@ -642,17 +645,17 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
         file_path = self.make_path("some_file")
         self.create_file(file_path)
 
-        with self.open(file_path, "a") as fh:
+        with self.open(file_path, "a", encoding="utf8") as fh:
             with self.assertRaises(OSError):
                 fh.read()
             with self.assertRaises(OSError):
                 fh.readlines()
-        with self.open(file_path, "w") as fh:
+        with self.open(file_path, "w", encoding="utf8") as fh:
             with self.assertRaises(OSError):
                 fh.read()
             with self.assertRaises(OSError):
                 fh.readlines()
-        with self.open(file_path, "r") as fh:
+        with self.open(file_path, "r", encoding="utf8") as fh:
             with self.assertRaises(OSError):
                 fh.truncate()
             with self.assertRaises(OSError):
@@ -661,7 +664,7 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
                 fh.writelines(["con", "tents"])
 
         def _iterator_open(mode):
-            with self.open(file_path, mode) as f:
+            with self.open(file_path, mode, encoding="utf8") as f:
                 for _ in f:
                     pass
 
@@ -705,14 +708,14 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
         self.skip_real_fs()
         device_path = "device"
         self.filesystem.create_file(device_path, stat.S_IFBLK | helpers.PERM_ALL)
-        with self.open(device_path, "r") as fh:
+        with self.open(device_path, "r", encoding="utf8") as fh:
             self.assertEqual("", fh.read())
 
     def test_truncate_flushes_contents(self):
         # Regression test for #285
         file_path = self.make_path("baz")
         self.create_file(file_path)
-        with self.open(file_path, "w") as f0:
+        with self.open(file_path, "w", encoding="utf8") as f0:
             f0.write("test")
             f0.truncate()
             self.assertEqual(4, self.os.path.getsize(file_path))
@@ -720,8 +723,8 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
     def test_update_other_instances_of_same_file_on_flush(self):
         # Regression test for #302
         file_path = self.make_path("baz")
-        with self.open(file_path, "w") as f0:
-            with self.open(file_path, "w") as f1:
+        with self.open(file_path, "w", encoding="utf8") as f0:
+            with self.open(file_path, "w", encoding="utf8") as f1:
                 f0.write("test")
                 f0.truncate()
                 f1.flush()
@@ -730,7 +733,7 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
     def test_getsize_after_truncate(self):
         # Regression test for #412
         file_path = self.make_path("foo")
-        with self.open(file_path, "a") as f:
+        with self.open(file_path, "a", encoding="utf8") as f:
             f.write("a")
             f.seek(0)
             f.truncate()
@@ -742,7 +745,7 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
     def test_st_size_after_truncate(self):
         # Regression test for #412
         file_path = self.make_path("foo")
-        with self.open(file_path, "a") as f:
+        with self.open(file_path, "a", encoding="utf8") as f:
             f.write("a")
             f.truncate()
             f.write("b")
@@ -753,7 +756,7 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
         # Regression test for #286
         file_path = self.make_path("baz")
         self.create_file(file_path)
-        with self.open(file_path) as f0:
+        with self.open(file_path, encoding="utf8") as f0:
             f0.seek(2)
             f0.read()
             self.assertEqual(2, f0.tell())
@@ -764,7 +767,7 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
             raise unittest.SkipTest("Different exceptions with PyPy")
         file_path = self.make_path("foo")
         self.create_file(file_path, contents=b"test")
-        fake_file = self.open(file_path, "r")
+        fake_file = self.open(file_path, "r", encoding="utf8")
         fake_file.close()
         with self.assertRaises(ValueError):
             fake_file.read(1)
@@ -787,7 +790,7 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
             raise unittest.SkipTest("Different exceptions with PyPy")
         file_path = self.make_path("foo")
         f0 = self.os.open(file_path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC)
-        fake_file = self.open(file_path, "r")
+        fake_file = self.open(file_path, "r", encoding="utf8")
         fake_file.close()
         with self.assertRaises(ValueError):
             fake_file.read(1)
@@ -799,7 +802,7 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
         # Regression test for #288
         self.check_macos_only()
         file_path = self.make_path("foo")
-        with self.open(file_path, "w") as f0:
+        with self.open(file_path, "w", encoding="utf8") as f0:
             f0.write("test")
             self.assertEqual(4, f0.tell())
             self.assertEqual(4, self.os.path.getsize(file_path))
@@ -808,7 +811,7 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
         # Regression test for #288
         self.check_linux_and_windows()
         file_path = self.make_path("foo")
-        with self.open(file_path, "w") as f0:
+        with self.open(file_path, "w", encoding="utf8") as f0:
             f0.write("test")
             self.assertEqual(4, f0.tell())
             self.assertEqual(4, self.os.path.getsize(file_path))
@@ -817,7 +820,7 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
         # Regression test for #278
         self.check_posix_only()
         file_path = self.make_path("foo")
-        with self.open(file_path, "a+") as f0:
+        with self.open(file_path, "a+", encoding="utf8") as f0:
             f0.write("test")
             self.assertEqual("", f0.read())
             self.assertEqual(4, self.os.path.getsize(file_path))
@@ -826,7 +829,7 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
         # Regression test for #278
         self.check_windows_only()
         file_path = self.make_path("foo")
-        with self.open(file_path, "w+") as f0:
+        with self.open(file_path, "w+", encoding="utf8") as f0:
             f0.write("test")
             f0.read()
             self.assertEqual(4, self.os.path.getsize(file_path))
@@ -834,7 +837,7 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
     def test_seek_flushes(self):
         # Regression test for #290
         file_path = self.make_path("foo")
-        with self.open(file_path, "w") as f0:
+        with self.open(file_path, "w", encoding="utf8") as f0:
             f0.write("test")
             self.assertEqual(0, self.os.path.getsize(file_path))
             f0.seek(3)
@@ -843,7 +846,7 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
     def test_truncate_flushes(self):
         # Regression test for #291
         file_path = self.make_path("foo")
-        with self.open(file_path, "a") as f0:
+        with self.open(file_path, "a", encoding="utf8") as f0:
             f0.write("test")
             self.assertEqual(0, self.os.path.getsize(file_path))
             f0.truncate()
@@ -852,7 +855,7 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
     def check_seek_outside_and_truncate_sets_size(self, mode):
         # Regression test for #294 and #296
         file_path = self.make_path("baz")
-        with self.open(file_path, mode) as f0:
+        with self.open(file_path, mode, encoding="utf8") as f0:
             f0.seek(1)
             f0.truncate()
             self.assertEqual(1, f0.tell())
@@ -871,11 +874,11 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
 
     def test_closed(self):
         file_path = self.make_path("foo")
-        f = self.open(file_path, "w")
+        f = self.open(file_path, "w", encoding="utf8")
         self.assertFalse(f.closed)
         f.close()
         self.assertTrue(f.closed)
-        f = self.open(file_path)
+        f = self.open(file_path, encoding="utf8")
         self.assertFalse(f.closed)
         f.close()
         self.assertTrue(f.closed)
@@ -883,9 +886,9 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
     def test_closing_closed_file_does_nothing(self):
         # Regression test for #299
         file_path = self.make_path("baz")
-        f0 = self.open(file_path, "w")
+        f0 = self.open(file_path, "w", encoding="utf8")
         f0.close()
-        with self.open(file_path) as f1:
+        with self.open(file_path, encoding="utf8") as f1:
             # would close f1 if not handled
             f0.close()
             self.assertEqual("", f1.read())
@@ -904,8 +907,8 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
     def test_truncate_flushes_zeros(self):
         # Regression test for #301
         file_path = self.make_path("baz")
-        with self.open(file_path, "w") as f0:
-            with self.open(file_path) as f1:
+        with self.open(file_path, "w", encoding="utf8") as f0:
+            with self.open(file_path, encoding="utf8") as f1:
                 f0.seek(1)
                 f0.truncate()
                 self.assertEqual("\0", f1.read())
@@ -926,9 +929,9 @@ class FakeFileOpenTest(FakeFileOpenTestBase):
 
     def test_write_devnull(self):
         for mode in ("r+", "w", "w+", "a", "a+"):
-            with self.open(self.os.devnull, mode) as f:
+            with self.open(self.os.devnull, mode, encoding="utf8") as f:
                 f.write("test")
-            with self.open(self.os.devnull) as f:
+            with self.open(self.os.devnull, encoding="utf8") as f:
                 self.assertEqual("", f.read())
 
     def test_utf16_text(self):
@@ -957,7 +960,15 @@ class FakeFileOpenWithOpenerTest(FakeFileOpenTestBase):
     def test_use_opener_with_read(self):
         file_path = self.make_path("foo")
         self.create_file(file_path, contents="test")
-        with self.open(file_path, opener=self.opener) as f:
+        with self.open(file_path, encoding="utf8", opener=self.opener) as f:
+            assert f.read() == "test"
+            with self.assertRaises(OSError):
+                f.write("foo")
+
+    def test_no_opener_with_read(self):
+        file_path = self.make_path("foo")
+        self.create_file(file_path, contents="test")
+        with self.open(file_path, encoding="utf8") as f:
             assert f.read() == "test"
             with self.assertRaises(OSError):
                 f.write("foo")
@@ -965,75 +976,75 @@ class FakeFileOpenWithOpenerTest(FakeFileOpenTestBase):
     def test_use_opener_with_read_plus(self):
         file_path = self.make_path("foo")
         self.create_file(file_path, contents="test")
-        with self.open(file_path, "r+", opener=self.opener) as f:
+        with self.open(file_path, "r+", encoding="utf8", opener=self.opener) as f:
             assert f.read() == "test"
             assert f.write("bar") == 3
-        with self.open(file_path) as f:
+        with self.open(file_path, encoding="utf8") as f:
             assert f.read() == "testbar"
 
     def test_use_opener_with_write(self):
         file_path = self.make_path("foo")
         self.create_file(file_path, contents="foo")
-        with self.open(file_path, "w", opener=self.opener) as f:
+        with self.open(file_path, "w", encoding="utf8", opener=self.opener) as f:
             with self.assertRaises(OSError):
                 f.read()
             assert f.write("bar") == 3
-        with self.open(file_path) as f:
+        with self.open(file_path, encoding="utf8") as f:
             assert f.read() == "bar"
 
     def test_use_opener_with_write_plus(self):
         file_path = self.make_path("foo")
         self.create_file(file_path, contents="test")
-        with self.open(file_path, "w+", opener=self.opener) as f:
+        with self.open(file_path, "w+", encoding="utf8", opener=self.opener) as f:
             assert f.read() == ""
             assert f.write("bar") == 3
-        with self.open(file_path) as f:
+        with self.open(file_path, encoding="utf8") as f:
             assert f.read() == "bar"
 
     def test_use_opener_with_append(self):
         file_path = self.make_path("foo")
         self.create_file(file_path, contents="foo")
-        with self.open(file_path, "a", opener=self.opener) as f:
+        with self.open(file_path, "a", encoding="utf8", opener=self.opener) as f:
             assert f.write("bar") == 3
             with self.assertRaises(OSError):
                 f.read()
-        with self.open(file_path) as f:
+        with self.open(file_path, encoding="utf8") as f:
             assert f.read() == "foobar"
 
     def test_use_opener_with_append_plus(self):
         file_path = self.make_path("foo")
         self.create_file(file_path, contents="foo")
-        with self.open(file_path, "a+", opener=self.opener) as f:
+        with self.open(file_path, "a+", encoding="utf8", opener=self.opener) as f:
             assert f.read() == ""
             assert f.write("bar") == 3
-        with self.open(file_path) as f:
+        with self.open(file_path, encoding="utf8") as f:
             assert f.read() == "foobar"
 
     def test_use_opener_with_exclusive_write(self):
         file_path = self.make_path("foo")
         self.create_file(file_path, contents="test")
         with self.assertRaises(OSError):
-            self.open(file_path, "x", opener=self.opener)
+            self.open(file_path, "x", encoding="utf8", opener=self.opener)
 
         file_path = self.make_path("bar")
-        with self.open(file_path, "x", opener=self.opener) as f:
+        with self.open(file_path, "x", encoding="utf8", opener=self.opener) as f:
             assert f.write("bar") == 3
             with self.assertRaises(OSError):
                 f.read()
-        with self.open(file_path) as f:
+        with self.open(file_path, encoding="utf8") as f:
             assert f.read() == "bar"
 
     def test_use_opener_with_exclusive_plus(self):
         file_path = self.make_path("foo")
         self.create_file(file_path, contents="test")
         with self.assertRaises(OSError):
-            self.open(file_path, "x+", opener=self.opener)
+            self.open(file_path, "x+", encoding="utf8", opener=self.opener)
 
         file_path = self.make_path("bar")
-        with self.open(file_path, "x+", opener=self.opener) as f:
+        with self.open(file_path, "x+", encoding="utf8", opener=self.opener) as f:
             assert f.write("bar") == 3
             assert f.read() == ""
-        with self.open(file_path) as f:
+        with self.open(file_path, encoding="utf8") as f:
             assert f.read() == "bar"
 
 
@@ -1045,7 +1056,7 @@ class RealFileOpenWithOpenerTest(FakeFileOpenWithOpenerTest):
 @unittest.skipIf(sys.version_info < (3, 8), "open_code only present since Python 3.8")
 class FakeFilePatchedOpenCodeTest(FakeFileOpenTestBase):
     def setUp(self):
-        super(FakeFilePatchedOpenCodeTest, self).setUp()
+        super().setUp()
         if self.use_real_fs():
             self.open_code = io.open_code
         else:
@@ -1055,7 +1066,7 @@ class FakeFilePatchedOpenCodeTest(FakeFileOpenTestBase):
     def tearDown(self):
         if not self.use_real_fs():
             self.filesystem.patch_open_code = False
-        super(FakeFilePatchedOpenCodeTest, self).tearDown()
+        super().tearDown()
 
     @unittest.skipIf(IS_PYPY, "Different behavior in PyPy")
     def test_invalid_path(self):
@@ -1093,7 +1104,7 @@ class RealPatchedFileOpenCodeTest(FakeFilePatchedOpenCodeTest):
 @unittest.skipIf(sys.version_info < (3, 8), "open_code only present since Python 3.8")
 class FakeFileUnpatchedOpenCodeTest(FakeFileOpenTestBase):
     def setUp(self):
-        super(FakeFileUnpatchedOpenCodeTest, self).setUp()
+        super().setUp()
         if self.use_real_fs():
             self.open_code = io.open_code
         else:
@@ -1137,7 +1148,7 @@ class BufferingModeTest(FakeFileOpenTestBase):
     def test_no_buffering_not_allowed_in_textmode(self):
         file_path = self.make_path("buffertest.txt")
         with self.assertRaises(ValueError):
-            self.open(file_path, "w", buffering=0)
+            self.open(file_path, "w", encoding="utf8", buffering=0)
 
     def test_default_buffering_no_flush(self):
         file_path = self.make_path("buffertest.bin")
@@ -1191,95 +1202,95 @@ class BufferingModeTest(FakeFileOpenTestBase):
 
     def test_writing_text_with_line_buffer(self):
         file_path = self.make_path("buffertest.bin")
-        with self.open(file_path, "w", buffering=1) as f:
+        with self.open(file_path, "w", encoding="utf8", buffering=1) as f:
             f.write("test" * 100)
-            with self.open(file_path, "r") as r:
+            with self.open(file_path, "r", encoding="utf8") as r:
                 x = r.read()
                 # no new line - not written
                 self.assertEqual(0, len(x))
             f.write("\ntest")
-            with self.open(file_path, "r") as r:
+            with self.open(file_path, "r", encoding="utf8") as r:
                 x = r.read()
                 # new line - buffer written
                 self.assertEqual(405, len(x))
             f.write("test" * 10)
-            with self.open(file_path, "r") as r:
+            with self.open(file_path, "r", encoding="utf8") as r:
                 x = r.read()
                 # buffer not filled - not written
                 self.assertEqual(405, len(x))
             f.write("\ntest")
-            with self.open(file_path, "r") as r:
+            with self.open(file_path, "r", encoding="utf8") as r:
                 x = r.read()
                 # new line - buffer written
                 self.assertEqual(450, len(x))
 
     def test_writing_large_text_with_line_buffer(self):
         file_path = self.make_path("buffertest.bin")
-        with self.open(file_path, "w", buffering=1) as f:
+        with self.open(file_path, "w", encoding="utf8", buffering=1) as f:
             f.write("test" * 4000)
-            with self.open(file_path, "r") as r:
+            with self.open(file_path, "r", encoding="utf8") as r:
                 x = r.read()
                 # buffer larger than default - written
                 self.assertEqual(16000, len(x))
             f.write("test")
-            with self.open(file_path, "r") as r:
+            with self.open(file_path, "r", encoding="utf8") as r:
                 x = r.read()
                 # buffer not filled - not written
                 self.assertEqual(16000, len(x))
             f.write("\ntest")
-            with self.open(file_path, "r") as r:
+            with self.open(file_path, "r", encoding="utf8") as r:
                 x = r.read()
                 # new line - buffer written
                 self.assertEqual(16009, len(x))
             f.write("\ntest")
-            with self.open(file_path, "r") as r:
+            with self.open(file_path, "r", encoding="utf8") as r:
                 x = r.read()
                 # another new line - buffer written
                 self.assertEqual(16014, len(x))
 
     def test_writing_text_with_default_buffer(self):
         file_path = self.make_path("buffertest.txt")
-        with self.open(file_path, "w") as f:
+        with self.open(file_path, "w", encoding="utf8") as f:
             f.write("test" * 5)
-            with self.open(file_path, "r") as r:
+            with self.open(file_path, "r", encoding="utf8") as r:
                 x = r.read()
                 # buffer not filled - not written
                 self.assertEqual(0, len(x))
             f.write("\ntest")
-            with self.open(file_path, "r") as r:
+            with self.open(file_path, "r", encoding="utf8") as r:
                 x = r.read()
                 # buffer exceeded, but new buffer (400) not - previous written
                 self.assertEqual(0, len(x))
             f.write("test" * 10)
-            with self.open(file_path, "r") as r:
+            with self.open(file_path, "r", encoding="utf8") as r:
                 x = r.read()
                 # buffer not filled - not written
                 self.assertEqual(0, len(x))
             f.write("\ntest")
-            with self.open(file_path, "r") as r:
+            with self.open(file_path, "r", encoding="utf8") as r:
                 x = r.read()
                 self.assertEqual(0, len(x))
 
     def test_writing_text_with_specific_buffer(self):
         file_path = self.make_path("buffertest.txt")
-        with self.open(file_path, "w", buffering=2) as f:
+        with self.open(file_path, "w", encoding="utf8", buffering=2) as f:
             f.write("a" * 8000)
-            with self.open(file_path, "r") as r:
+            with self.open(file_path, "r", encoding="utf8") as r:
                 x = r.read()
                 # buffer not filled - not written
                 self.assertEqual(0, len(x))
             f.write("test")
-            with self.open(file_path, "r") as r:
+            with self.open(file_path, "r", encoding="utf8") as r:
                 x = r.read()
                 # buffer exceeded, but new buffer (400) not - previous written
                 self.assertEqual(0, len(x))
             f.write("test")
-            with self.open(file_path, "r") as r:
+            with self.open(file_path, "r", encoding="utf8") as r:
                 x = r.read()
                 # buffer not filled - not written
                 self.assertEqual(0, len(x))
             f.write("test")
-            with self.open(file_path, "r") as r:
+            with self.open(file_path, "r", encoding="utf8") as r:
                 x = r.read()
                 self.assertEqual(0, len(x))
         # with self.open(file_path, "r") as r:
@@ -1366,7 +1377,7 @@ class OpenFileWithEncodingTest(FakeFileOpenTestBase):
     an explicit text encoding."""
 
     def setUp(self):
-        super(OpenFileWithEncodingTest, self).setUp()
+        super().setUp()
         self.file_path = self.make_path("foo")
 
     def test_write_str_read_bytes(self):
@@ -1434,7 +1445,7 @@ class OpenFileWithEncodingTest(FakeFileOpenTestBase):
 
     def test_create_file_with_append(self):
         contents = [
-            "Allons enfants de la Patrie," "Le jour de gloire est arrivé!",
+            "Allons enfants de la Patrie,Le jour de gloire est arrivé!",
             "Contre nous de la tyrannie,",
             "L’étendard sanglant est levé.",
         ]
@@ -1447,7 +1458,7 @@ class OpenFileWithEncodingTest(FakeFileOpenTestBase):
 
     def test_append_existing_file(self):
         contents = [
-            "Оригинальное содержание" "Дополнительное содержание",
+            "Оригинальное содержаниеДополнительное содержание",
         ]
         self.create_file(self.file_path, contents=contents[0], encoding="cyrillic")
         with self.open(self.file_path, "a", encoding="cyrillic") as fake_file:
@@ -1525,27 +1536,27 @@ class OpenRealFileWithEncodingTest(OpenFileWithEncodingTest):
 
 class FakeFileOpenLineEndingTest(FakeFileOpenTestBase):
     def setUp(self):
-        super(FakeFileOpenLineEndingTest, self).setUp()
+        super().setUp()
 
     def test_read_default_newline_mode(self):
         file_path = self.make_path("some_file")
         for contents in (b"1\n2", b"1\r\n2", b"1\r2"):
             self.create_file(file_path, contents=contents)
-            with self.open(file_path, mode="r") as f:
+            with self.open(file_path, mode="r", encoding="utf8") as f:
                 self.assertEqual(["1\n", "2"], f.readlines())
-            with self.open(file_path, mode="r") as f:
+            with self.open(file_path, mode="r", encoding="utf8") as f:
                 self.assertEqual("1\n2", f.read())
             with self.open(file_path, mode="rb") as f:
                 self.assertEqual(contents, f.read())
 
     def test_write_universal_newline_mode(self):
         file_path = self.make_path("some_file")
-        with self.open(file_path, "w") as f:
+        with self.open(file_path, "w", encoding="utf8") as f:
             f.write("1\n2")
         with self.open(file_path, mode="rb") as f:
             self.assertEqual(b"1" + self.os.linesep.encode() + b"2", f.read())
 
-        with self.open(file_path, "w") as f:
+        with self.open(file_path, "w", encoding="utf8") as f:
             f.write("1\r\n2")
         with self.open(file_path, mode="rb") as f:
             self.assertEqual(b"1\r" + self.os.linesep.encode() + b"2", f.read())
@@ -1554,26 +1565,26 @@ class FakeFileOpenLineEndingTest(FakeFileOpenTestBase):
         file_path = self.make_path("some_file")
         file_contents = b"1\r\n2\n3\r4"
         self.create_file(file_path, contents=file_contents)
-        with self.open(file_path, mode="r", newline="") as f:
+        with self.open(file_path, mode="r", encoding="utf8", newline="") as f:
             self.assertEqual("1\r\n2\n3\r4", f.read())
-        with self.open(file_path, mode="r", newline="\r") as f:
+        with self.open(file_path, mode="r", encoding="utf8", newline="\r") as f:
             self.assertEqual("1\r\n2\n3\r4", f.read())
-        with self.open(file_path, mode="r", newline="\n") as f:
+        with self.open(file_path, mode="r", encoding="utf8", newline="\n") as f:
             self.assertEqual("1\r\n2\n3\r4", f.read())
-        with self.open(file_path, mode="r", newline="\r\n") as f:
+        with self.open(file_path, mode="r", encoding="utf8", newline="\r\n") as f:
             self.assertEqual("1\r\n2\n3\r4", f.read())
 
     def test_readlines_with_newline_arg(self):
         file_path = self.make_path("some_file")
         file_contents = b"1\r\n2\n3\r4"
         self.create_file(file_path, contents=file_contents)
-        with self.open(file_path, mode="r", newline="") as f:
+        with self.open(file_path, mode="r", encoding="utf8", newline="") as f:
             self.assertEqual(["1\r\n", "2\n", "3\r", "4"], f.readlines())
-        with self.open(file_path, mode="r", newline="\r") as f:
+        with self.open(file_path, mode="r", encoding="utf8", newline="\r") as f:
             self.assertEqual(["1\r", "\n2\n3\r", "4"], f.readlines())
-        with self.open(file_path, mode="r", newline="\n") as f:
+        with self.open(file_path, mode="r", encoding="utf8", newline="\n") as f:
             self.assertEqual(["1\r\n", "2\n", "3\r4"], f.readlines())
-        with self.open(file_path, mode="r", newline="\r\n") as f:
+        with self.open(file_path, mode="r", encoding="utf8", newline="\r\n") as f:
             self.assertEqual(["1\r\n", "2\n3\r4"], f.readlines())
 
     @unittest.skipIf(sys.version_info >= (3, 10), "U flag no longer supported")
@@ -1581,11 +1592,11 @@ class FakeFileOpenLineEndingTest(FakeFileOpenTestBase):
         file_path = self.make_path("some_file")
         file_contents = b"1\r\n2\n3\r4"
         self.create_file(file_path, contents=file_contents)
-        with self.open(file_path, mode="r", newline="\r") as f:
+        with self.open(file_path, mode="r", encoding="utf8", newline="\r") as f:
             self.assertEqual("1\r\n2\n3\r4", f.read())
-        with self.open(file_path, mode="r", newline="\r") as f:
+        with self.open(file_path, mode="r", encoding="utf8", newline="\r") as f:
             self.assertEqual("1\r\n2\n3\r4", f.read())
-        with self.open(file_path, mode="U", newline="\r") as f:
+        with self.open(file_path, mode="U", encoding="utf8", newline="\r") as f:
             self.assertEqual("1\r\n2\n3\r4", f.read())
 
     @unittest.skipIf(sys.version_info < (3, 11), "U flag still supported")
@@ -1594,26 +1605,26 @@ class FakeFileOpenLineEndingTest(FakeFileOpenTestBase):
         file_contents = b"1\r\n2\n3\r4"
         self.create_file(file_path, contents=file_contents)
         with self.assertRaises(ValueError):
-            self.open(file_path, mode="U", newline="\r")
+            self.open(file_path, mode="U", encoding="utf8", newline="\r")
 
     def test_write_with_newline_arg(self):
         file_path = self.make_path("some_file")
-        with self.open(file_path, "w", newline="") as f:
+        with self.open(file_path, "w", encoding="utf8", newline="") as f:
             f.write("1\r\n2\n3\r4")
         with self.open(file_path, mode="rb") as f:
             self.assertEqual(b"1\r\n2\n3\r4", f.read())
 
-        with self.open(file_path, "w", newline="\n") as f:
+        with self.open(file_path, "w", encoding="utf8", newline="\n") as f:
             f.write("1\r\n2\n3\r4")
         with self.open(file_path, mode="rb") as f:
             self.assertEqual(b"1\r\n2\n3\r4", f.read())
 
-        with self.open(file_path, "w", newline="\r\n") as f:
+        with self.open(file_path, "w", encoding="utf8", newline="\r\n") as f:
             f.write("1\r\n2\n3\r4")
         with self.open(file_path, mode="rb") as f:
             self.assertEqual(b"1\r\r\n2\r\n3\r4", f.read())
 
-        with self.open(file_path, "w", newline="\r") as f:
+        with self.open(file_path, "w", encoding="utf8", newline="\r") as f:
             f.write("1\r\n2\n3\r4")
         with self.open(file_path, mode="rb") as f:
             self.assertEqual(b"1\r\r2\r3\r4", f.read())
@@ -1645,7 +1656,7 @@ class RealFileOpenLineEndingTest(FakeFileOpenLineEndingTest):
 
 class FakeFileOpenLineEndingWithEncodingTest(FakeFileOpenTestBase):
     def setUp(self):
-        super(FakeFileOpenLineEndingWithEncodingTest, self).setUp()
+        super().setUp()
 
     def test_read_standard_newline_mode(self):
         file_path = self.make_path("some_file")
@@ -1737,16 +1748,16 @@ class OpenWithFileDescriptorTest(FakeFileOpenTestBase):
         file_path = self.make_path("this", "file")
         self.create_file(file_path)
         fd = self.os.open(file_path, os.O_CREAT)
-        self.assertEqual(fd, self.open(fd, "r").fileno())
+        self.assertEqual(fd, self.open(fd, "r", encoding="utf8").fileno())
 
     def test_closefd_with_file_descriptor(self):
         file_path = self.make_path("this", "file")
         self.create_file(file_path)
         fd = self.os.open(file_path, os.O_CREAT)
-        fh = self.open(fd, "r", closefd=False)
+        fh = self.open(fd, "r", encoding="utf8", closefd=False)
         fh.close()
         self.assertIsNotNone(self.filesystem.open_files[fd])
-        fh = self.open(fd, "r", closefd=True)
+        fh = self.open(fd, "r", encoding="utf8", closefd=True)
         fh.close()
         self.assertIsNone(self.filesystem.open_files[fd])
 
@@ -1758,12 +1769,15 @@ class OpenWithRealFileDescriptorTest(FakeFileOpenTestBase):
 
 class OpenWithFlagsTestBase(FakeFileOpenTestBase):
     def setUp(self):
-        super(OpenWithFlagsTestBase, self).setUp()
+        super().setUp()
         self.file_path = self.make_path("some_file")
         self.file_contents = None
 
     def open_file(self, mode):
-        return self.open(self.file_path, mode=mode)
+        kwargs = {"mode": mode}
+        if "b" not in mode:
+            kwargs["encoding"] = "utf8"
+        return self.open(self.file_path, **kwargs)
 
     def open_file_and_seek(self, mode):
         fake_file = self.open(self.file_path, mode=mode)
@@ -1781,7 +1795,7 @@ class OpenWithFlagsTestBase(FakeFileOpenTestBase):
 
 class OpenWithBinaryFlagsTest(OpenWithFlagsTestBase):
     def setUp(self):
-        super(OpenWithBinaryFlagsTest, self).setUp()
+        super().setUp()
         self.file_contents = b"real binary contents: \x1f\x8b"
         self.create_file(self.file_path, contents=self.file_contents)
 
@@ -1816,7 +1830,7 @@ class RealOpenWithBinaryFlagsTest(OpenWithBinaryFlagsTest):
 
 class OpenWithTextModeFlagsTest(OpenWithFlagsTestBase):
     def setUp(self):
-        super(OpenWithTextModeFlagsTest, self).setUp()
+        super().setUp()
         self.setUpFileSystem()
 
     def setUpFileSystem(self):
@@ -1873,16 +1887,16 @@ class OpenWithInvalidFlagsRealFsTest(OpenWithInvalidFlagsTest):
 
 class ResolvePathTest(FakeFileOpenTestBase):
     def write_to_file(self, file_name):
-        with self.open(file_name, "w") as fh:
+        with self.open(file_name, "w", encoding="utf8") as fh:
             fh.write("x")
 
     def test_none_filepath_raises_type_error(self):
         with self.assertRaises(TypeError):
-            self.open(None, "w")
+            self.open(None, "w", encoding="utf8")
 
     def test_empty_filepath_raises_io_error(self):
         with self.assertRaises(OSError):
-            self.open("", "w")
+            self.open("", "w", encoding="utf8")
 
     def test_normal_path(self):
         file_path = self.make_path("foo")
@@ -2011,7 +2025,7 @@ class ResolvePathTest(FakeFileOpenTestBase):
         self.create_symlink(link_path, "link")
         self.create_symlink(self.make_path("foo", "link"), "baz")
         self.write_to_file(self.make_path("foo", "baz"))
-        fh = self.open(link_path, "r")
+        fh = self.open(link_path, "r", encoding="utf8")
         self.assertEqual("x", fh.read())
 
     def test_write_link_to_link(self):
@@ -2091,5 +2105,12 @@ class RealResolvePathTest(ResolvePathTest):
         return True
 
 
+class SkipOpenTest(unittest.TestCase):
+    def test_open_in_skipped_module(self):
+        with Patcher(additional_skip_names=["skipped_pathlib"]):
+            contents = read_open("skipped_pathlib.py")
+            self.assertTrue(contents.startswith("# Licensed under the Apache License"))
+
+
 if __name__ == "__main__":
     unittest.main()
diff --git a/pyfakefs/tests/fake_os_test.py b/pyfakefs/tests/fake_os_test.py
index 6b48bbf..6395248 100644
--- a/pyfakefs/tests/fake_os_test.py
+++ b/pyfakefs/tests/fake_os_test.py
@@ -21,8 +21,6 @@ import stat
 import sys
 import unittest
 
-from pyfakefs.helpers import IN_DOCKER, IS_PYPY, get_uid, get_gid
-
 from pyfakefs import fake_filesystem, fake_os, fake_open, fake_file
 from pyfakefs.fake_filesystem import (
     FakeFileOpen,
@@ -30,21 +28,25 @@ from pyfakefs.fake_filesystem import (
     set_uid,
     set_gid,
 )
-from pyfakefs.extra_packages import (
-    use_scandir,
-    use_scandir_package,
-    use_builtin_scandir,
-)
-
+from pyfakefs.helpers import IN_DOCKER, IS_PYPY, get_uid, get_gid, reset_ids
 from pyfakefs.tests.test_utils import TestCase, RealFsTestCase
 
 
 class FakeOsModuleTestBase(RealFsTestCase):
+    def setUp(self):
+        super().setUp()
+        self.umask = self.os.umask(0o022)
+
+    def tearDown(self):
+        self.os.umask(self.umask)
+
     def createTestFile(self, path):
         self.create_file(path)
         self.assertTrue(self.os.path.exists(path))
         st = self.os.stat(path)
-        self.assertEqual(0o666, stat.S_IMODE(st.st_mode))
+        # under Windows, the umask has no effect
+        mode = 0o666 if self.is_windows_fs else 0o0644
+        self.assertEqual(mode, stat.S_IMODE(st.st_mode))
         self.assertTrue(st.st_mode & stat.S_IFREG)
         self.assertFalse(st.st_mode & stat.S_IFDIR)
 
@@ -52,14 +54,15 @@ class FakeOsModuleTestBase(RealFsTestCase):
         self.create_dir(path)
         self.assertTrue(self.os.path.exists(path))
         st = self.os.stat(path)
-        self.assertEqual(0o777, stat.S_IMODE(st.st_mode))
+        mode = 0o777 if self.is_windows_fs else 0o755
+        self.assertEqual(mode, stat.S_IMODE(st.st_mode))
         self.assertFalse(st.st_mode & stat.S_IFREG)
         self.assertTrue(st.st_mode & stat.S_IFDIR)
 
 
 class FakeOsModuleTest(FakeOsModuleTestBase):
     def setUp(self):
-        super(FakeOsModuleTest, self).setUp()
+        super().setUp()
         self.rwx = self.os.R_OK | self.os.W_OK | self.os.X_OK
         self.rw = self.os.R_OK | self.os.W_OK
 
@@ -178,9 +181,9 @@ class FakeOsModuleTest(FakeOsModuleTestBase):
     def test_fdopen(self):
         file_path1 = self.make_path("some_file1")
         self.create_file(file_path1, contents="contents here1")
-        with self.open(file_path1, "r") as fake_file1:
+        with self.open(file_path1, "r", encoding="utf8") as fake_file1:
             fileno = fake_file1.fileno()
-            fake_file2 = self.os.fdopen(fileno)
+            fake_file2 = self.os.fdopen(fileno, encoding="utf8")
             self.assertNotEqual(fake_file2, fake_file1)
 
         with self.assertRaises(TypeError):
@@ -190,7 +193,8 @@ class FakeOsModuleTest(FakeOsModuleTestBase):
 
     def test_out_of_range_fdopen(self):
         # test some file descriptor that is clearly out of range
-        self.assert_raises_os_error(errno.EBADF, self.os.fdopen, 500)
+        kwargs = {"encoding": "utf8"}
+        self.assert_raises_os_error(errno.EBADF, self.os.fdopen, 500, **kwargs)
 
     def test_closed_file_descriptor(self):
         first_path = self.make_path("some_file1")
@@ -200,9 +204,9 @@ class FakeOsModuleTest(FakeOsModuleTestBase):
         self.create_file(second_path, contents="contents here2")
         self.create_file(third_path, contents="contents here3")
 
-        fake_file1 = self.open(first_path, "r")
-        fake_file2 = self.open(second_path, "r")
-        fake_file3 = self.open(third_path, "r")
+        fake_file1 = self.open(first_path, "r", encoding="utf8")
+        fake_file2 = self.open(second_path, "r", encoding="utf8")
+        fake_file3 = self.open(third_path, "r", encoding="utf8")
         fileno1 = fake_file1.fileno()
         fileno2 = fake_file2.fileno()
         fileno3 = fake_file3.fileno()
@@ -212,34 +216,64 @@ class FakeOsModuleTest(FakeOsModuleTestBase):
         self.assertEqual(fileno1, fake_file1.fileno())
         self.assertEqual(fileno3, fake_file3.fileno())
 
-        with self.os.fdopen(fileno1) as f:
+        with self.os.fdopen(fileno1, encoding="utf8") as f:
             self.assertFalse(f is fake_file1)
-        with self.os.fdopen(fileno3) as f:
+        with self.os.fdopen(fileno3, encoding="utf8") as f:
             self.assertFalse(f is fake_file3)
-        self.assert_raises_os_error(errno.EBADF, self.os.fdopen, fileno2)
+        kwargs = {"encoding": "utf8"}
+        self.assert_raises_os_error(errno.EBADF, self.os.fdopen, fileno2, **kwargs)
+
+    def test_fdopen_twice(self):
+        # regression test for #997
+        file_path = self.make_path("some_file1")
+        self.create_file(file_path, contents="contents here1")
+        fake_file = self.open(file_path, "r", encoding="utf8")
+        fd = fake_file.fileno()
+        # note: we need to assign the files to objects,
+        # otherwise the file will be closed immediately in the CPython implementation
+        # note that this case is not (and will probably not be) handled in pyfakefs
+        file1 = self.open(fd, encoding="utf8")  # noqa: F841
+        file2 = self.open(fd, encoding="utf8")  # noqa: F841
 
-    def test_fdopen_mode(self):
-        self.skip_real_fs()
-        file_path1 = self.make_path("some_file1")
-        self.create_file(file_path1, contents="contents here1")
-        self.os.chmod(file_path1, (stat.S_IFREG | 0o666) ^ stat.S_IWRITE)
+        self.os.close(fd)
 
-        fake_file1 = self.open(file_path1, "r")
-        fileno1 = fake_file1.fileno()
-        self.os.fdopen(fileno1)
-        self.os.fdopen(fileno1, "r")
-        if not is_root():
-            with self.assertRaises(OSError):
-                self.os.fdopen(fileno1, "w")
-        else:
-            self.os.fdopen(fileno1, "w")
-            self.os.close(fileno1)
+    def test_open_fd_write_mode_for_ro_file(self):
+        # Create a writable file handle to a read-only file, see #967
+        file_path = self.make_path("file.txt")
+        fd = self.os.open(file_path, os.O_CREAT | os.O_WRONLY, 0o555)
+        with self.open(fd, "w", encoding="utf8") as out:
+            out.write("hey")
+        with self.open(file_path, encoding="utf8") as f:
+            assert f.read() == "hey"
+        self.os.chmod(file_path, 0o655)
+
+    def test_open_fd_read_mode_for_ro_file(self):
+        # Create a read-only handle to a read-only file, see #967
+        file_path = self.make_path("file.txt")
+        fd = self.os.open(file_path, os.O_CREAT | os.O_RDONLY, 0x555)
+        # Attempt to open a write stream to the underlying file
+        out = self.open(fd, "wb")
+        out.flush()  # Does not fail: The buffer is empty, so no write()
+
+        # Fails: Tries to flush a non-empty buffer
+        out.write(b"a")  # file.write() may fail by an implicit flush!
+        with self.assertRaises(OSError) as cm:
+            out.flush()
+        assert cm.exception.errno == errno.EBADF
+
+        # Fails: Tries to flush() again
+        with self.assertRaises(OSError) as cm:
+            out.close()
+        assert cm.exception.errno == errno.EBADF
+
+        out.close()  # Okay: The file is already closed
+        self.os.chmod(file_path, 0o655)
 
     def test_fstat(self):
         directory = self.make_path("xyzzy")
         file_path = self.os.path.join(directory, "plugh")
         self.create_file(file_path, contents="ABCDE")
-        with self.open(file_path) as file_obj:
+        with self.open(file_path, encoding="utf8") as file_obj:
             fileno = file_obj.fileno()
             self.assertTrue(stat.S_IFREG & self.os.fstat(fileno)[stat.ST_MODE])
             self.assertTrue(stat.S_IFREG & self.os.fstat(fileno).st_mode)
@@ -307,7 +341,7 @@ class FakeOsModuleTest(FakeOsModuleTestBase):
         file_path = self.make_path("foo", "bar")
         self.create_file(file_path)
 
-        with self.open(file_path) as f:
+        with self.open(file_path, encoding="utf8") as f:
             self.assertTrue(stat.S_IFREG & self.os.stat(f.filedes)[stat.ST_MODE])
 
     def test_stat_no_follow_symlinks_posix(self):
@@ -528,7 +562,7 @@ class FakeOsModuleTest(FakeOsModuleTestBase):
         self.create_file(file_path, contents=file_contents)
         self.create_symlink(link_path, file_path)
 
-        with self.open(file_path) as f:
+        with self.open(file_path, encoding="utf8") as f:
             self.assertEqual(len(file_contents), self.os.lstat(f.filedes)[stat.ST_SIZE])
 
     def test_stat_non_existent_file(self):
@@ -565,6 +599,44 @@ class FakeOsModuleTest(FakeOsModuleTestBase):
         self.check_windows_only()
         self.check_open_raises_with_trailing_separator(errno.EINVAL)
 
+    @unittest.skipIf(not hasattr(os, "O_DIRECTORY"), "opening directory not supported")
+    def test_open_with_o_directory(self):
+        self.check_posix_only()
+        with self.assertRaises(FileNotFoundError):
+            self.os.open("bogus", os.O_RDONLY | os.O_DIRECTORY)
+        file_path = self.make_path("file.txt")
+        self.create_file(file_path, contents="foo")
+        with self.assertRaises(NotADirectoryError):
+            self.os.open(file_path, os.O_RDONLY | os.O_DIRECTORY)
+        dir_path = self.make_path("dir")
+        self.create_dir(dir_path)
+        with self.assertRaises(IsADirectoryError):
+            self.os.open(dir_path, os.O_RDWR | os.O_DIRECTORY)
+
+    @unittest.skipIf(not hasattr(os, "O_NOFOLLOW"), "NOFOLLOW attribute not supported")
+    def test_open_nofollow_symlink_raises(self):
+        self.skip_if_symlink_not_supported()
+        file_path = self.make_path("file.txt")
+        self.create_file(file_path, contents="foo")
+        link_path = self.make_path("link")
+        self.create_symlink(link_path, file_path)
+        with self.assertRaises(OSError) as cm:
+            self.os.open(link_path, os.O_RDONLY | os.O_NOFOLLOW)
+        assert cm.exception.errno == errno.ELOOP
+
+    @unittest.skipIf(not hasattr(os, "O_NOFOLLOW"), "NOFOLLOW attribute not supported")
+    def test_open_nofollow_symlink_as_parent_works(self):
+        self.skip_if_symlink_not_supported()
+        dir_path = self.make_path("dir")
+        self.create_dir(dir_path)
+        link_path = self.make_path("link")
+        self.create_symlink(link_path, dir_path)
+        file_path = self.os.path.join(link_path, "file.txt")
+        self.create_file(file_path, contents="foo")
+        fd = self.os.open(file_path, os.O_RDONLY | os.O_NOFOLLOW)
+        self.assertGreater(fd, 0)
+        self.os.close(fd)
+
     def test_lexists_with_trailing_separator_linux_windows(self):
         self.check_linux_and_windows()
         self.skip_if_symlink_not_supported()
@@ -826,6 +898,7 @@ class FakeOsModuleTest(FakeOsModuleTestBase):
 
     def test_remove_file_with_read_permission_raises_in_windows(self):
         self.check_windows_only()
+        self.skip_root()
         path = self.make_path("foo", "bar")
         self.create_file(path)
         self.os.chmod(path, 0o444)
@@ -867,7 +940,7 @@ class FakeOsModuleTest(FakeOsModuleTestBase):
         self.check_windows_only()
         path = self.make_path("foo", "bar")
         self.create_file(path)
-        with self.open(path, "r"):
+        with self.open(path, "r", encoding="utf8"):
             self.assert_raises_os_error(errno.EACCES, self.os.remove, path)
         self.assertTrue(self.os.path.exists(path))
 
@@ -875,7 +948,7 @@ class FakeOsModuleTest(FakeOsModuleTestBase):
         self.check_posix_only()
         path = self.make_path("foo", "bar")
         self.create_file(path)
-        self.open(path, "r")
+        self.open(path, "r", encoding="utf8")
         self.os.remove(path)
         self.assertFalse(self.os.path.exists(path))
 
@@ -1296,8 +1369,8 @@ class FakeOsModuleTest(FakeOsModuleTestBase):
 
     def check_append_mode_tell_after_truncate(self, tell_result):
         file_path = self.make_path("baz")
-        with self.open(file_path, "w") as f0:
-            with self.open(file_path, "a") as f1:
+        with self.open(file_path, "w", encoding="utf8") as f0:
+            with self.open(file_path, "a", encoding="utf8") as f1:
                 f1.write("abcde")
                 f0.seek(2)
                 f0.truncate()
@@ -1318,14 +1391,14 @@ class FakeOsModuleTest(FakeOsModuleTestBase):
     def test_tell_after_seek_in_append_mode(self):
         # Regression test for #363
         file_path = self.make_path("foo")
-        with self.open(file_path, "a") as f:
+        with self.open(file_path, "a", encoding="utf8") as f:
             f.seek(1)
             self.assertEqual(1, f.tell())
 
     def test_tell_after_seekback_in_append_mode(self):
         # Regression test for #414
         file_path = self.make_path("foo")
-        with self.open(file_path, "a") as f:
+        with self.open(file_path, "a", encoding="utf8") as f:
             f.write("aa")
             f.seek(1)
             self.assertEqual(1, f.tell())
@@ -1568,7 +1641,7 @@ class FakeOsModuleTest(FakeOsModuleTestBase):
         self.assertTrue(self.filesystem.exists("/%s" % directory))
         self.os.chdir(directory)
         self.os.mkdir(directory)
-        self.assertTrue(self.filesystem.exists("/%s/%s" % (directory, directory)))
+        self.assertTrue(self.filesystem.exists(f"/{directory}/{directory}"))
         self.os.chdir(directory)
         self.os.mkdir("../abccb")
         self.assertTrue(self.os.path.exists("/%s/abccb" % directory))
@@ -1589,7 +1662,7 @@ class FakeOsModuleTest(FakeOsModuleTestBase):
     def test_mkdir_raises_if_no_parent(self):
         """mkdir raises exception if parent directory does not exist."""
         parent = "xyzzy"
-        directory = "%s/foo" % (parent,)
+        directory = f"{parent}/foo"
         self.assertFalse(self.os.path.exists(parent))
         self.assert_raises_os_error(errno.ENOENT, self.os.mkdir, directory)
 
@@ -1816,6 +1889,14 @@ class FakeOsModuleTest(FakeOsModuleTestBase):
         self.assert_raises_os_error(errno.ENOENT, self.os.makedirs, "", exist_ok=False)
         self.assert_raises_os_error(errno.ENOENT, self.os.makedirs, "", exist_ok=True)
 
+    def test_makedirs_with_relative_paths(self):
+        # regression test for #987
+        path = self.make_path("base", "foo", "..", "bar")
+        self.os.makedirs(path)
+        self.assertTrue(self.os.path.isdir(self.make_path("base", "bar")))
+        self.assertTrue(self.os.path.isdir(self.make_path("base", "foo")))
+        self.assertFalse(self.os.path.isdir(self.make_path("base", "foo", "bar")))
+
     # test fsync and fdatasync
     def test_fsync_raises_on_non_int(self):
         with self.assertRaises(TypeError):
@@ -1838,7 +1919,7 @@ class FakeOsModuleTest(FakeOsModuleTestBase):
         self.check_posix_only()
         test_file_path = self.make_path("test_file")
         self.create_file(test_file_path, contents="dummy file contents")
-        with self.open(test_file_path, "r") as test_file:
+        with self.open(test_file_path, "r", encoding="utf8") as test_file:
             test_fd = test_file.fileno()
             # Test that this doesn't raise anything
             self.os.fsync(test_fd)
@@ -1849,13 +1930,13 @@ class FakeOsModuleTest(FakeOsModuleTestBase):
         self.check_windows_only()
         test_file_path = self.make_path("test_file")
         self.create_file(test_file_path, contents="dummy file contents")
-        with self.open(test_file_path, "r+") as test_file:
+        with self.open(test_file_path, "r+", encoding="utf8") as test_file:
             test_fd = test_file.fileno()
             # Test that this doesn't raise anything
             self.os.fsync(test_fd)
             # And just for sanity, double-check that this still raises
             self.assert_raises_os_error(errno.EBADF, self.os.fsync, test_fd + 500)
-        with self.open(test_file_path, "r") as test_file:
+        with self.open(test_file_path, "r", encoding="utf8") as test_file:
             test_fd = test_file.fileno()
             self.assert_raises_os_error(errno.EBADF, self.os.fsync, test_fd)
 
@@ -1864,7 +1945,7 @@ class FakeOsModuleTest(FakeOsModuleTestBase):
         self.check_linux_only()
         test_file_path = self.make_path("test_file")
         self.create_file(test_file_path, contents="dummy file contents")
-        test_file = self.open(test_file_path, "r")
+        test_file = self.open(test_file_path, "r", encoding="utf8")
         test_fd = test_file.fileno()
         # Test that this doesn't raise anything
         self.os.fdatasync(test_fd)
@@ -1944,8 +2025,11 @@ class FakeOsModuleTest(FakeOsModuleTestBase):
         self.assertTrue(self.os.access(link_path, self.os.F_OK, follow_symlinks=False))
         self.assertTrue(self.os.access(link_path, self.os.R_OK, follow_symlinks=False))
         self.assertTrue(self.os.access(link_path, self.os.W_OK, follow_symlinks=False))
-        self.assertTrue(self.os.access(link_path, self.os.X_OK, follow_symlinks=False))
-        self.assertTrue(self.os.access(link_path, self.rwx, follow_symlinks=False))
+        if not self.is_windows_fs:
+            self.assertTrue(
+                self.os.access(link_path, self.os.X_OK, follow_symlinks=False)
+            )
+            self.assertTrue(self.os.access(link_path, self.rwx, follow_symlinks=False))
         self.assertTrue(self.os.access(link_path, self.rw, follow_symlinks=False))
 
     def test_access_non_existent_file(self):
@@ -1980,16 +2064,37 @@ class FakeOsModuleTest(FakeOsModuleTestBase):
         self.assertFalse(st.st_mode & stat.S_IFDIR)
 
     def test_chmod_uses_open_fd_as_path(self):
-        self.check_posix_only()
+        if sys.version_info < (3, 13):
+            self.check_posix_only()
         self.skip_real_fs()
         self.assert_raises_os_error(errno.EBADF, self.os.chmod, 5, 0o6543)
         path = self.make_path("some_file")
         self.createTestFile(path)
 
-        with self.open(path) as f:
-            self.os.chmod(f.filedes, 0o6543)
+        with self.open(path, encoding="utf8") as f:
+            st = self.os.stat(f.fileno())
+            # use a mode that will work under Windows
+            self.os.chmod(f.filedes, 0o444)
             st = self.os.stat(path)
-            self.assert_mode_equal(0o6543, st.st_mode)
+            self.assert_mode_equal(0o444, st.st_mode)
+            # fchmod should work the same way
+            self.os.fchmod(f.filedes, 0o666)
+            st = self.os.stat(path)
+            self.assert_mode_equal(0o666, st.st_mode)
+
+    @unittest.skipIf(
+        sys.version_info >= (3, 13), "also available under Windows since Python 3.13"
+    )
+    def test_chmod_uses_open_fd_as_path_not_available_under_windows(self):
+        self.check_windows_only()
+        self.skip_real_fs()
+        path = self.make_path("some_file")
+        self.createTestFile(path)
+        with self.open(path, encoding="utf8") as f:
+            with self.assertRaises(TypeError):
+                self.os.chmod(f.fileno(), 0o666)
+            with self.assertRaises(AttributeError):
+                self.os.fchmod(f.fileno(), 0o666)
 
     def test_chmod_follow_symlink(self):
         self.check_posix_only()
@@ -2006,7 +2111,10 @@ class FakeOsModuleTest(FakeOsModuleTestBase):
         self.assertEqual(stat.S_IMODE(0o700), stat.S_IMODE(st.st_mode) & 0o700)
 
     def test_chmod_no_follow_symlink(self):
-        self.check_posix_only()
+        if sys.version_info < (3, 13):
+            self.check_posix_only()
+        else:
+            self.skip_if_symlink_not_supported()
         path = self.make_path("some_file")
         self.createTestFile(path)
         link_path = self.make_path("link_to_some_file")
@@ -2017,9 +2125,11 @@ class FakeOsModuleTest(FakeOsModuleTestBase):
         else:
             self.os.chmod(link_path, 0o6543, follow_symlinks=False)
             st = self.os.stat(link_path)
-            self.assert_mode_equal(0o666, st.st_mode)
+            mode = 0o644 if self.is_macos else 0o666
+            self.assert_mode_equal(mode, st.st_mode)
             st = self.os.stat(link_path, follow_symlinks=False)
-            self.assert_mode_equal(0o6543, st.st_mode)
+            mode = 0o444 if self.is_windows_fs else 0o6543
+            self.assert_mode_equal(mode, st.st_mode)
 
     def test_lchmod(self):
         """lchmod shall behave like chmod with follow_symlinks=True."""
@@ -2032,7 +2142,7 @@ class FakeOsModuleTest(FakeOsModuleTestBase):
         self.os.lchmod(link_path, 0o6543)
 
         st = self.os.stat(link_path)
-        self.assert_mode_equal(0o666, st.st_mode)
+        self.assert_mode_equal(0o644, st.st_mode)
         st = self.os.lstat(link_path)
         self.assert_mode_equal(0o6543, st.st_mode)
 
@@ -2090,7 +2200,7 @@ class FakeOsModuleTest(FakeOsModuleTestBase):
         file_path = self.make_path("foo", "bar")
         self.create_file(file_path)
 
-        with self.open(file_path) as f:
+        with self.open(file_path, encoding="utf8") as f:
             self.os.chown(f.filedes, 100, 101)
             st = self.os.stat(file_path)
             self.assertEqual(st[stat.ST_UID], 100)
@@ -2139,6 +2249,27 @@ class FakeOsModuleTest(FakeOsModuleTestBase):
         self.assertFalse(self.os.path.exists(file_path))
         self.assert_raises_os_error(errno.ENOENT, self.os.chown, file_path, 100, 100)
 
+    def test_fail_add_entry_to_readonly_dir(self):
+        # regression test for #959
+        self.check_posix_only()
+        self.skip_real_fs()  # cannot change owner to root
+        if is_root():
+            self.skipTest("Non-root test only")
+
+        # create directory owned by root with permissions 0o755 (rwxr-xr-x)
+        ro_dir = self.make_path("readonly-dir")
+        self.create_dir(ro_dir, perm=0o755)
+        self.os.chown(ro_dir, 0, 0)
+
+        # adding a new entry to the readonly subdirectory should fail
+        with self.assertRaises(PermissionError):
+            with self.open(f"{ro_dir}/file.txt", "w", encoding="utf8"):
+                pass
+        file_path = self.make_path("file.txt")
+        self.create_file(file_path)
+        with self.assertRaises(PermissionError):
+            self.os.link(file_path, self.os.path.join(ro_dir, "file.txt"))
+
     def test_classify_directory_contents(self):
         """Directory classification should work correctly."""
         root_directory = self.make_path("foo")
@@ -2477,7 +2608,7 @@ class FakeOsModuleTest(FakeOsModuleTestBase):
         self.skip_if_symlink_not_supported()
         file_path = self.make_path("foo")
         link_path = self.make_path("link")
-        with self.open(file_path, "w"):
+        with self.open(file_path, "w", encoding="utf8"):
             self.assert_raises_os_error(
                 error, self.os.link, file_path + self.os.sep, link_path
             )
@@ -2495,7 +2626,7 @@ class FakeOsModuleTest(FakeOsModuleTestBase):
         self.check_posix_only()
         path0 = self.make_path("foo") + self.os.sep
         path1 = self.make_path("bar")
-        with self.open(path1, "w"):
+        with self.open(path1, "w", encoding="utf8"):
             self.assert_raises_os_error(errno.ENOENT, self.os.link, path1, path0)
 
     def test_link_to_path_ending_with_sep_windows(self):
@@ -2503,14 +2634,14 @@ class FakeOsModuleTest(FakeOsModuleTestBase):
         self.skip_if_symlink_not_supported()
         path0 = self.make_path("foo") + self.os.sep
         path1 = self.make_path("bar")
-        with self.open(path1, "w"):
+        with self.open(path1, "w", encoding="utf8"):
             self.os.link(path1, path0)
             self.assertTrue(self.os.path.exists(path1))
 
     def check_rename_to_path_ending_with_sep(self, error):
         # Regression tests for #400
         file_path = self.make_path("foo")
-        with self.open(file_path, "w"):
+        with self.open(file_path, "w", encoding="utf8"):
             self.assert_raises_os_error(
                 error, self.os.rename, file_path + self.os.sep, file_path
             )
@@ -2601,7 +2732,7 @@ class FakeOsModuleTest(FakeOsModuleTestBase):
         self.os.unlink(file1_path)
         # assert that second file exists, and its contents are the same
         self.assertTrue(self.os.path.exists(file2_path))
-        with self.open(file2_path) as f:
+        with self.open(file2_path, encoding="utf8") as f:
             self.assertEqual(f.read(), contents1)
 
     def test_link_update(self):
@@ -2615,13 +2746,13 @@ class FakeOsModuleTest(FakeOsModuleTestBase):
         self.create_file(file1_path, contents=contents1)
         self.os.link(file1_path, file2_path)
         # assert that the second file contains contents1
-        with self.open(file2_path) as f:
+        with self.open(file2_path, encoding="utf8") as f:
             self.assertEqual(f.read(), contents1)
         # update the first file
-        with self.open(file1_path, "w") as f:
+        with self.open(file1_path, "w", encoding="utf8") as f:
             f.write(contents2)
         # assert that second file contains contents2
-        with self.open(file2_path) as f:
+        with self.open(file2_path, encoding="utf8") as f:
             self.assertEqual(f.read(), contents2)
 
     def test_link_non_existent_parent(self):
@@ -2684,6 +2815,29 @@ class FakeOsModuleTest(FakeOsModuleTestBase):
         self.os.unlink(file1_path)
         self.assertEqual(self.os.stat(file2_path).st_nlink, 1)
 
+    @unittest.skipIf(IS_PYPY, "follow_symlinks not supported in PyPi")
+    def test_link_no_follow_symlink(self):
+        self.skip_if_symlink_not_supported()
+        target_path = self.make_path("target_path")
+        self.create_file(target_path, contents="foo")
+        symlink_path = self.make_path("symlink_to_file")
+        self.create_symlink(symlink_path, target_path)
+        link_path = self.make_path("link_to_symlink")
+        self.os.link(symlink_path, link_path, follow_symlinks=False)
+        self.assertTrue(self.os.path.islink(link_path))
+
+    @unittest.skipIf(not IS_PYPY, "follow_symlinks only not supported in PyPi")
+    def test_link_follow_symlink_not_supported_inPypy(self):
+        self.skip_if_symlink_not_supported()
+        target_path = self.make_path("target_path")
+        self.create_file(target_path, contents="foo")
+        symlink_path = self.make_path("symlink_to_file")
+        self.create_symlink(symlink_path, target_path)
+        link_path = self.make_path("link_to_symlink")
+        with self.assertRaises(OSError) as cm:
+            self.os.link(symlink_path, link_path, follow_symlinks=False)
+        self.assertEqual(errno.EINVAL, cm.exception.errno)
+
     def test_nlink_for_directories(self):
         self.skip_real_fs()
         self.create_dir(self.make_path("foo", "bar"))
@@ -2698,9 +2852,9 @@ class FakeOsModuleTest(FakeOsModuleTestBase):
 
     def test_umask(self):
         self.check_posix_only()
-        umask = os.umask(0o22)
-        os.umask(umask)
-        self.assertEqual(umask, self.os.umask(0o22))
+        umask = self.os.umask(0o22)
+        self.assertEqual(umask, self.os.umask(0o12))
+        self.os.umask(umask)
 
     def test_mkdir_umask_applied(self):
         """mkdir creates a directory with umask applied."""
@@ -2717,7 +2871,7 @@ class FakeOsModuleTest(FakeOsModuleTestBase):
     def test_makedirs_umask_applied(self):
         """makedirs creates a directories with umask applied."""
         self.check_posix_only()
-        self.os.umask(0o22)
+        umask = self.os.umask(0o22)
         self.os.makedirs(self.make_path("p1", "dir1"))
         self.assert_mode_equal(0o755, self.os.stat(self.make_path("p1")).st_mode)
         self.assert_mode_equal(
@@ -2729,6 +2883,7 @@ class FakeOsModuleTest(FakeOsModuleTestBase):
         self.assert_mode_equal(
             0o710, self.os.stat(self.make_path("p2", "dir2")).st_mode
         )
+        self.os.umask(umask)
 
     def test_mknod_umask_applied(self):
         """mkdir creates a device with umask applied."""
@@ -2748,11 +2903,11 @@ class FakeOsModuleTest(FakeOsModuleTestBase):
         self.check_posix_only()
         self.os.umask(0o22)
         file1 = self.make_path("file1")
-        self.open(file1, "w").close()
+        self.open(file1, "w", encoding="utf8").close()
         self.assert_mode_equal(0o644, self.os.stat(file1).st_mode)
         self.os.umask(0o27)
         file2 = self.make_path("file2")
-        self.open(file2, "w").close()
+        self.open(file2, "w", encoding="utf8").close()
         self.assert_mode_equal(0o640, self.os.stat(file2).st_mode)
 
     def test_open_pipe(self):
@@ -2794,7 +2949,7 @@ class FakeOsModuleTest(FakeOsModuleTestBase):
             fds.append(self.os.open(path, os.O_CREAT))
         file_path = self.make_path("file.txt")
         self.create_file(file_path)
-        with self.open(file_path):
+        with self.open(file_path, encoding="utf8"):
             read_fd, write_fd = self.os.pipe()
             with self.open(write_fd, "wb") as f:
                 self.assertEqual(4, f.write(b"test"))
@@ -2824,7 +2979,7 @@ class FakeOsModuleTest(FakeOsModuleTestBase):
         file_path = self.make_path("foo", "bar")
         self.create_file(file_path, contents="012345678901234567")
         self.os.truncate(file_path, 10)
-        with self.open(file_path) as f:
+        with self.open(file_path, encoding="utf8") as f:
             self.assertEqual("0123456789", f.read())
 
     def test_truncate_non_existing(self):
@@ -2836,7 +2991,7 @@ class FakeOsModuleTest(FakeOsModuleTestBase):
         fd = self.os.open(file_path, os.O_RDWR)
         self.os.truncate(fd, 20)
         self.assertEqual(20, self.os.stat(file_path).st_size)
-        with self.open(file_path) as f:
+        with self.open(file_path, encoding="utf8") as f:
             self.assertEqual("0123456789" + "\0" * 10, f.read())
 
     def test_truncate_with_fd(self):
@@ -2849,7 +3004,7 @@ class FakeOsModuleTest(FakeOsModuleTestBase):
         fd = self.os.open(file_path, os.O_RDWR)
         self.os.truncate(fd, 10)
         self.assertEqual(10, self.os.stat(file_path).st_size)
-        with self.open(file_path) as f:
+        with self.open(file_path, encoding="utf8") as f:
             self.assertEqual("0123456789", f.read())
 
     def test_ftruncate(self):
@@ -2863,7 +3018,7 @@ class FakeOsModuleTest(FakeOsModuleTestBase):
         fd = self.os.open(file_path, os.O_RDWR)
         self.os.truncate(fd, 10)
         self.assertEqual(10, self.os.stat(file_path).st_size)
-        with self.open(file_path) as f:
+        with self.open(file_path, encoding="utf8") as f:
             self.assertEqual("0123456789", f.read())
 
     def test_capabilities(self):
@@ -2881,6 +3036,65 @@ class FakeOsModuleTest(FakeOsModuleTestBase):
             os.stat in os.supports_effective_ids,
         )
 
+    def test_dup(self):
+        with self.assertRaises(OSError) as cm:
+            self.os.dup(500)
+        self.assertEqual(errno.EBADF, cm.exception.errno)
+        file_path = self.make_path("test.txt")
+        self.create_file(file_path, contents="heythere")
+        fd1 = self.os.open(file_path, os.O_RDONLY)
+        fd2 = self.os.dup(fd1)
+        self.assertEqual(b"hey", self.os.read(fd1, 3))
+        self.assertEqual(b"there", self.os.read(fd1, 10))
+        self.os.close(fd2)
+        self.os.close(fd1)
+
+    def test_dup_uses_freed_fd(self):
+        file_path1 = self.make_path("foo.txt")
+        file_path2 = self.make_path("bar.txt")
+        self.create_file(file_path1, contents="foo here")
+        self.create_file(file_path2, contents="bar here")
+        fd1 = self.os.open(file_path1, os.O_RDONLY)
+        fd2 = self.os.open(file_path2, os.O_RDONLY)
+        self.os.close(fd1)
+        fd3 = self.os.dup(fd2)
+        self.assertEqual(fd1, fd3)
+        self.os.close(fd2)
+
+    def test_dup2_uses_existing_fd(self):
+        with self.assertRaises(OSError) as cm:
+            self.os.dup2(500, 501)
+        self.assertEqual(errno.EBADF, cm.exception.errno)
+
+        file_path1 = self.make_path("foo.txt")
+        file_path2 = self.make_path("bar.txt")
+        self.create_file(file_path1, contents="foo here")
+        self.create_file(file_path2, contents="bar here")
+        fd1 = self.os.open(file_path1, os.O_RDONLY)
+        fd2 = self.os.open(file_path2, os.O_RDONLY)
+        self.assertEqual(b"bar", self.os.read(fd2, 3))
+        fd2 = self.os.dup2(fd1, fd2)
+        self.assertEqual(b"foo", self.os.read(fd2, 3))
+        self.os.lseek(fd2, 0, 0)
+        self.assertEqual(b"foo", self.os.read(fd1, 3))
+        self.os.close(fd2)
+
+    def test_dup2_with_new_fd(self):
+        file_path1 = self.make_path("foo.txt")
+        file_path2 = self.make_path("bar.txt")
+        self.create_file(file_path1)
+        self.create_file(file_path2)
+        fd1 = self.os.open(file_path1, os.O_RDONLY)
+        fd2 = fd1 + 2
+        self.assertEqual(fd2, self.os.dup2(fd1, fd2))
+        fd3 = self.os.open(file_path2, os.O_RDONLY)
+        fd4 = self.os.dup(fd3)
+        self.os.close(fd4)
+        self.os.close(fd2)
+        # we have a free position before fd2 that is now filled
+        self.assertEqual(fd1 + 1, fd3)
+        self.assertEqual(fd1 + 3, fd4)
+
 
 class RealOsModuleTest(FakeOsModuleTest):
     def use_real_fs(self):
@@ -2889,7 +3103,7 @@ class RealOsModuleTest(FakeOsModuleTest):
 
 class FakeOsModuleTestCaseInsensitiveFS(FakeOsModuleTestBase):
     def setUp(self):
-        super(FakeOsModuleTestCaseInsensitiveFS, self).setUp()
+        super().setUp()
         self.check_case_insensitive_fs()
         self.rwx = self.os.R_OK | self.os.W_OK | self.os.X_OK
         self.rw = self.os.R_OK | self.os.W_OK
@@ -2920,22 +3134,52 @@ class FakeOsModuleTestCaseInsensitiveFS(FakeOsModuleTestBase):
         files.sort()
         self.assertEqual(files, sorted(self.os.listdir(self.make_path("SymLink"))))
 
-    def test_fdopen_mode(self):
-        self.skip_real_fs()
-        file_path1 = self.make_path("some_file1")
-        file_path2 = self.make_path("Some_File1")
-        file_path3 = self.make_path("SOME_file1")
-        self.create_file(file_path1, contents="contents here1")
-        self.os.chmod(file_path2, (stat.S_IFREG | 0o666) ^ stat.S_IWRITE)
+    def test_listdir_possible_without_exe_permission(self):
+        # regression test for #960
+        self.check_posix_only()
+        self.skip_root()
+        directory = self.make_path("testdir")
+        file_path = self.os.path.join(directory, "file.txt")
+        self.create_file(file_path, contents="hey", perm=0o777)
+        self.os.chmod(directory, 0o655)  # rw-r-xr-x
+        # We cannot create any files in the directory, because that requires
+        # searching it
+        another_file = self.make_path("file.txt")
+        self.create_file(another_file, contents="hey")
+        with self.assertRaises(PermissionError):
+            self.os.link(another_file, self.os.path.join(directory, "link.txt"))
+        # We can enumerate the directory using listdir and scandir:
+        assert self.os.listdir(directory) == ["file.txt"]
+        assert len(list(self.os.scandir(directory))) == 1
+
+        # We cannot read files inside of the directory,
+        # even if we have read access to the file
+        with self.assertRaises(PermissionError):
+            self.os.stat(file_path)
+        with self.assertRaises(PermissionError):
+            with self.open(file_path, encoding="utf8") as f:
+                f.read()
 
-        fake_file1 = self.open(file_path3, "r")
-        fileno1 = fake_file1.fileno()
-        self.os.fdopen(fileno1)
-        self.os.fdopen(fileno1, "r")
-        if not is_root():
-            self.assertRaises(OSError, self.os.fdopen, fileno1, "w")
-        else:
-            self.os.fdopen(fileno1, "w")
+    def test_listdir_impossible_without_read_permission(self):
+        # regression test for #960
+        self.check_posix_only()
+        self.skip_root()
+        directory = self.make_path("testdir")
+        file_path = self.os.path.join(directory, "file.txt")
+        self.create_file(file_path, contents="hey", perm=0o777)
+        self.os.chmod(directory, 0o355)  # -wxr-xr-x
+        another_file = self.make_path("file.txt")
+        self.create_file(another_file, contents="hey")
+        self.os.link(another_file, self.os.path.join(directory, "link.txt"))
+        # We cannot enumerate the directory using listdir or scandir:
+        with self.assertRaises(PermissionError):
+            self.os.listdir(directory)
+        with self.assertRaises(PermissionError):
+            self.os.scandir(directory)
+        # we can access the file if we know the file name
+        assert self.os.stat(file_path).st_mode & 0o777 == 0o755
+        with self.open(file_path, encoding="utf8") as f:
+            assert f.read() == "hey"
 
     def test_stat(self):
         directory = self.make_path("xyzzy")
@@ -3093,7 +3337,7 @@ class FakeOsModuleTestCaseInsensitiveFS(FakeOsModuleTestBase):
         self.check_windows_only()
         path = self.make_path("foo", "bar")
         self.create_file(path)
-        with self.open(path, "r"):
+        with self.open(path, "r", encoding="utf8"):
             self.assert_raises_os_error(errno.EACCES, self.os.remove, path.upper())
         self.assertTrue(self.os.path.exists(path))
 
@@ -3101,7 +3345,7 @@ class FakeOsModuleTestCaseInsensitiveFS(FakeOsModuleTestBase):
         self.check_posix_only()
         path = self.make_path("foo", "bar")
         self.create_file(path)
-        self.open(path, "r")
+        self.open(path, "r", encoding="utf8")
         self.os.remove(path.upper())
         self.assertFalse(self.os.path.exists(path))
 
@@ -3747,7 +3991,7 @@ class FakeOsModuleTestCaseInsensitiveFS(FakeOsModuleTestBase):
     def test_fsync_pass(self):
         test_file_path = self.make_path("test_file")
         self.create_file(test_file_path, contents="dummy file contents")
-        test_file = self.open(test_file_path.upper(), "r+")
+        test_file = self.open(test_file_path.upper(), "r+", encoding="utf8")
         test_fd = test_file.fileno()
         # Test that this doesn't raise anything
         self.os.fsync(test_fd)
@@ -3794,7 +4038,7 @@ class FakeOsModuleTestCaseInsensitiveFS(FakeOsModuleTestBase):
         self.os.unlink(file1_path)
         # assert that second file exists, and its contents are the same
         self.assertTrue(self.os.path.exists(file2_path))
-        with self.open(file2_path.upper()) as f:
+        with self.open(file2_path.upper(), encoding="utf8") as f:
             self.assertEqual(f.read(), contents1)
 
     def test_link_is_existing_file(self):
@@ -3944,7 +4188,7 @@ class FakeOsModuleTimeTest(FakeOsModuleTestBase):
         path = self.make_path("some_file")
         self.createTestFile(path)
 
-        with FakeFileOpen(self.filesystem)(path) as f:
+        with FakeFileOpen(self.filesystem)(path, encoding="utf8") as f:
             self.os.utime(f.filedes, times=(1, 2))
             st = self.os.stat(path)
             self.assertEqual(1, st.st_atime)
@@ -3954,10 +4198,6 @@ class FakeOsModuleTimeTest(FakeOsModuleTestBase):
 class FakeOsModuleLowLevelFileOpTest(FakeOsModuleTestBase):
     """Test low level functions `os.open()`, `os.read()` and `os.write()`."""
 
-    def setUp(self):
-        os.umask(0o022)
-        super(FakeOsModuleLowLevelFileOpTest, self).setUp()
-
     def test_open_read_only(self):
         file_path = self.make_path("file1")
         self.create_file(file_path, contents=b"contents")
@@ -4397,7 +4637,7 @@ class FakeOsModuleLowLevelFileOpTest(FakeOsModuleTestBase):
         self.os.sendfile(fd2, fd1, 0, 3)
         self.os.close(fd2)
         self.os.close(fd1)
-        with self.open(dst_file_path) as f:
+        with self.open(dst_file_path, encoding="utf8") as f:
             self.assertEqual("tes", f.read())
 
     def test_sendfile_with_offset(self):
@@ -4411,7 +4651,7 @@ class FakeOsModuleLowLevelFileOpTest(FakeOsModuleTestBase):
         self.os.sendfile(fd2, fd1, 4, 4)
         self.os.close(fd2)
         self.os.close(fd1)
-        with self.open(dst_file_path) as f:
+        with self.open(dst_file_path, encoding="utf8") as f:
             self.assertEqual("cont", f.read())
 
     def test_sendfile_twice(self):
@@ -4426,7 +4666,7 @@ class FakeOsModuleLowLevelFileOpTest(FakeOsModuleTestBase):
         self.os.sendfile(fd2, fd1, 4, 4)
         self.os.close(fd2)
         self.os.close(fd1)
-        with self.open(dst_file_path) as f:
+        with self.open(dst_file_path, encoding="utf8") as f:
             self.assertEqual("contcont", f.read())
 
     def test_sendfile_offset_none(self):
@@ -4441,7 +4681,7 @@ class FakeOsModuleLowLevelFileOpTest(FakeOsModuleTestBase):
         self.os.sendfile(fd2, fd1, None, 3)
         self.os.close(fd2)
         self.os.close(fd1)
-        with self.open(dst_file_path) as f:
+        with self.open(dst_file_path, encoding="utf8") as f:
             self.assertEqual("testcon", f.read())
 
     @unittest.skipIf(not TestCase.is_macos, "Testing MacOs only behavior")
@@ -4552,7 +4792,7 @@ class FakeOsModuleWalkTest(FakeOsModuleTestBase):
     def test_walk_calls_on_error_if_not_directory(self):
         """Calls onerror with correct errno when walking non-directory."""
         self.ResetErrno()
-        filename = self.make_path("foo" "bar")
+        filename = self.make_path("foobar")
         self.create_file(filename)
         self.assertEqual(True, self.os.path.exists(filename))
         # Calling `os.walk` on a file should trigger a call to the
@@ -4675,229 +4915,255 @@ class RealOsModuleWalkTest(FakeOsModuleWalkTest):
 
 class FakeOsModuleDirFdTest(FakeOsModuleTestBase):
     def setUp(self):
-        super(FakeOsModuleDirFdTest, self).setUp()
-        self.os.supports_dir_fd.clear()
-        self.filesystem.is_windows_fs = False
-        self.filesystem.create_dir("/foo/bar")
-        self.dir_fd = self.os.open("/foo", os.O_RDONLY)
-        self.filesystem.create_file("/foo/baz")
+        super().setUp()
+        self.check_posix_only()
+        if not self.use_real_fs():
+            # in the real OS, we test the option as is, in the fake OS
+            # we test both the supported and unsupported option
+            self.os.supports_dir_fd.clear()
+        self.dir_fd_path = self.make_path("foo")
+        self.create_dir(self.dir_fd_path)
+        self.dir_fd = self.os.open(self.dir_fd_path, os.O_RDONLY)
+        self.fname = "baz"
+        self.fpath = self.os.path.join(self.dir_fd_path, self.fname)
+        self.create_file(self.fpath)
+
+    def add_supported_function(self, fct):
+        if not self.use_real_fs():
+            self.os.supports_dir_fd.add(fct)
 
     def test_access(self):
-        self.assertRaises(
-            NotImplementedError,
-            self.os.access,
-            "baz",
-            self.os.F_OK,
-            dir_fd=self.dir_fd,
-        )
-        self.os.supports_dir_fd.add(self.os.access)
-        self.assertTrue(self.os.access("baz", self.os.F_OK, dir_fd=self.dir_fd))
+        def os_access():
+            return self.os.access(self.fname, self.os.F_OK, dir_fd=self.dir_fd)
+
+        if self.os.access not in self.os.supports_dir_fd:
+            with self.assertRaises(NotImplementedError):
+                os_access()
+        self.add_supported_function(self.os.access)
+        if self.os.access in self.os.supports_dir_fd:
+            self.assertTrue(os_access())
 
     def test_chmod(self):
-        self.assertRaises(
-            NotImplementedError,
-            self.os.chmod,
-            "baz",
-            0o6543,
-            dir_fd=self.dir_fd,
-        )
-        self.os.supports_dir_fd.add(self.os.chmod)
-        self.os.chmod("baz", 0o6543, dir_fd=self.dir_fd)
-        st = self.os.stat("/foo/baz")
-        self.assert_mode_equal(0o6543, st.st_mode)
+        def os_chmod():
+            self.os.chmod(self.fname, 0o6543, dir_fd=self.dir_fd)
+
+        if self.os.chmod not in self.os.supports_dir_fd:
+            with self.assertRaises(NotImplementedError):
+                os_chmod()
+        self.add_supported_function(self.os.chmod)
+        if self.os.chmod in self.os.supports_dir_fd:
+            os_chmod()
+            st = self.os.stat(self.fpath)
+            self.assert_mode_equal(0o6543, st.st_mode)
 
     @unittest.skipIf(not hasattr(os, "chown"), "chown not on all platforms available")
     def test_chown(self):
-        self.assertRaises(
-            NotImplementedError,
-            self.os.chown,
-            "baz",
-            100,
-            101,
-            dir_fd=self.dir_fd,
-        )
-        self.os.supports_dir_fd.add(self.os.chown)
-        self.os.chown("baz", 100, 101, dir_fd=self.dir_fd)
-        st = self.os.stat("/foo/baz")
-        self.assertEqual(st[stat.ST_UID], 100)
-        self.assertEqual(st[stat.ST_GID], 101)
+        def os_chown():
+            self.os.chown(self.fname, 100, 101, dir_fd=self.dir_fd)
+
+        self.skip_real_fs()
+        if self.os.chown not in self.os.supports_dir_fd:
+            with self.assertRaises(NotImplementedError):
+                os_chown()
+        self.add_supported_function(self.os.chown)
+        os_chown()
+        st = self.os.stat(self.fpath)
+        self.assertEqual(100, st[stat.ST_UID])
+        self.assertEqual(101, st[stat.ST_GID])
 
     def test_link_src_fd(self):
-        self.assertRaises(
-            NotImplementedError,
-            self.os.link,
-            "baz",
-            "/bat",
-            src_dir_fd=self.dir_fd,
-        )
-        self.os.supports_dir_fd.add(self.os.link)
-        self.os.link("baz", "/bat", src_dir_fd=self.dir_fd)
-        self.assertTrue(self.os.path.exists("/bat"))
+        def os_link():
+            self.os.link(self.fname, link_dest, src_dir_fd=self.dir_fd)
+
+        link_dest = self.make_path("bat")
+        if self.os.link not in self.os.supports_dir_fd:
+            with self.assertRaises(NotImplementedError):
+                os_link()
+        self.add_supported_function(self.os.link)
+        if self.os.link in self.os.supports_dir_fd:
+            os_link()
+            self.assertTrue(self.os.path.exists(link_dest))
 
     def test_link_dst_fd(self):
-        self.assertRaises(
-            NotImplementedError,
-            self.os.link,
-            "baz",
-            "/bat",
-            dst_dir_fd=self.dir_fd,
-        )
-        self.os.supports_dir_fd.add(self.os.link)
-        self.os.link("/foo/baz", "bat", dst_dir_fd=self.dir_fd)
-        self.assertTrue(self.os.path.exists("/foo/bat"))
+        def os_link():
+            self.os.link(self.fpath, "bat", dst_dir_fd=self.dir_fd)
+
+        if self.os.link not in self.os.supports_dir_fd:
+            with self.assertRaises(NotImplementedError):
+                os_link()
+        self.add_supported_function(self.os.link)
+        if self.os.link in self.os.supports_dir_fd:
+            os_link()
+            link_path = self.os.path.join(self.dir_fd_path, "bat")
+            self.assertTrue(self.os.path.exists(link_path))
 
     def test_symlink(self):
-        self.assertRaises(
-            NotImplementedError,
-            self.os.symlink,
-            "baz",
-            "/bat",
-            dir_fd=self.dir_fd,
-        )
-        self.os.supports_dir_fd.add(self.os.symlink)
-        self.os.symlink("baz", "/bat", dir_fd=self.dir_fd)
-        self.assertTrue(self.os.path.exists("/bat"))
+        def os_symlink():
+            self.os.symlink(self.fpath, "bat", dir_fd=self.dir_fd)
+
+        if self.os.symlink not in self.os.supports_dir_fd:
+            with self.assertRaises(NotImplementedError):
+                os_symlink()
+        self.add_supported_function(self.os.symlink)
+        if self.os.symlink in self.os.supports_dir_fd:
+            os_symlink()
+            link_path = self.os.path.join(self.dir_fd_path, "bat")
+            self.assertTrue(self.os.path.exists(link_path))
 
     def test_readlink(self):
-        self.skip_if_symlink_not_supported()
-        self.filesystem.create_symlink("/meyer/lemon/pie", "/foo/baz")
-        self.filesystem.create_symlink("/geo/metro", "/meyer")
-        self.assertRaises(
-            NotImplementedError,
-            self.os.readlink,
-            "/geo/metro/lemon/pie",
-            dir_fd=self.dir_fd,
-        )
-        self.os.supports_dir_fd.add(self.os.readlink)
-        self.assertEqual(
-            "/foo/baz",
-            self.os.readlink("/geo/metro/lemon/pie", dir_fd=self.dir_fd),
-        )
+        def os_readlink():
+            return self.os.readlink("lemon/tree", dir_fd=self.dir_fd)
+
+        link_dir = self.os.path.join(self.dir_fd_path, "lemon")
+        self.create_dir(link_dir)
+        self.create_symlink(self.os.path.join(link_dir, "tree"), self.fpath)
+        if self.os.readlink not in self.os.supports_dir_fd:
+            with self.assertRaises(NotImplementedError):
+                os_readlink()
+        self.add_supported_function(self.os.readlink)
+        if self.os.readlink in self.os.supports_dir_fd:
+            self.assertEqual(self.fpath, os_readlink())
 
     def test_stat(self):
-        self.assertRaises(NotImplementedError, self.os.stat, "baz", dir_fd=self.dir_fd)
-        self.os.supports_dir_fd.add(self.os.stat)
-        st = self.os.stat("baz", dir_fd=self.dir_fd)
-        self.assertEqual(st.st_mode, 0o100666)
+        def os_stat():
+            return self.os.stat(self.fname, dir_fd=self.dir_fd)
+
+        if self.os.stat not in self.os.supports_dir_fd:
+            with self.assertRaises(NotImplementedError):
+                os_stat()
+        self.add_supported_function(self.os.stat)
+        if self.os.stat in self.os.supports_dir_fd:
+            self.assertEqual(os_stat().st_mode, 0o100644)
 
     def test_lstat(self):
-        self.assertRaises(NotImplementedError, self.os.lstat, "baz", dir_fd=self.dir_fd)
-        self.os.supports_dir_fd.add(self.os.lstat)
-        st = self.os.lstat("baz", dir_fd=self.dir_fd)
-        self.assertEqual(st.st_mode, 0o100666)
+        st = self.os.lstat(self.fname, dir_fd=self.dir_fd)
+        self.assertEqual(st.st_mode, 0o100644)
 
     def test_mkdir(self):
-        self.assertRaises(
-            NotImplementedError, self.os.mkdir, "newdir", dir_fd=self.dir_fd
-        )
-        self.os.supports_dir_fd.add(self.os.mkdir)
-        self.os.mkdir("newdir", dir_fd=self.dir_fd)
-        self.assertTrue(self.os.path.exists("/foo/newdir"))
+        def os_mkdir():
+            self.os.mkdir("newdir", dir_fd=self.dir_fd)
+
+        newdir_path = self.os.path.join(self.dir_fd_path, "newdir")
+        if self.os.mkdir not in self.os.supports_dir_fd:
+            with self.assertRaises(NotImplementedError):
+                os_mkdir()
+        self.add_supported_function(self.os.mkdir)
+        if self.os.mkdir in self.os.supports_dir_fd:
+            os_mkdir()
+            self.assertTrue(self.os.path.exists(newdir_path))
 
     def test_rmdir(self):
-        self.assertRaises(NotImplementedError, self.os.rmdir, "bar", dir_fd=self.dir_fd)
-        self.os.supports_dir_fd.add(self.os.rmdir)
-        self.os.rmdir("bar", dir_fd=self.dir_fd)
-        self.assertFalse(self.os.path.exists("/foo/bar"))
+        def os_rmdir():
+            self.os.rmdir("dir", dir_fd=self.dir_fd)
+
+        dir_path = self.os.path.join(self.dir_fd_path, "dir")
+        self.create_dir(dir_path)
+        self.assertTrue(self.os.path.exists(dir_path))
+        if self.os.rmdir not in self.os.supports_dir_fd:
+            with self.assertRaises(NotImplementedError):
+                os_rmdir()
+        self.add_supported_function(self.os.rmdir)
+        if self.os.rmdir in self.os.supports_dir_fd:
+            os_rmdir()
+            self.assertFalse(self.os.path.exists(dir_path))
 
     @unittest.skipIf(not hasattr(os, "mknod"), "mknod not on all platforms available")
     def test_mknod(self):
-        self.assertRaises(
-            NotImplementedError, self.os.mknod, "newdir", dir_fd=self.dir_fd
-        )
-        self.os.supports_dir_fd.add(self.os.mknod)
-        self.os.mknod("newdir", dir_fd=self.dir_fd)
-        self.assertTrue(self.os.path.exists("/foo/newdir"))
+        def os_mknod():
+            self.os.mknod("newdir", dir_fd=self.dir_fd)
+
+        if self.os.mknod not in self.os.supports_dir_fd:
+            with self.assertRaises(NotImplementedError):
+                os_mknod()
+        self.add_supported_function(self.os.mknod)
+        if self.os.mknod in self.os.supports_dir_fd:
+            if self.is_macos and sys.version_info >= (3, 13) and not is_root():
+                self.skipTest("Needs root rights under macos")
+            os_mknod()
+            newdir_path = self.os.path.join(self.dir_fd_path, "newdir")
+            self.assertTrue(self.os.path.exists(newdir_path))
 
     def test_rename_src_fd(self):
-        self.assertRaises(
-            NotImplementedError,
-            self.os.rename,
-            "baz",
-            "/foo/batz",
-            src_dir_fd=self.dir_fd,
-        )
-        self.os.supports_dir_fd.add(self.os.rename)
-        self.os.rename("bar", "/foo/batz", src_dir_fd=self.dir_fd)
-        self.assertTrue(self.os.path.exists("/foo/batz"))
+        def os_rename():
+            self.os.rename(self.fname, new_name, src_dir_fd=self.dir_fd)
+
+        new_name = self.os.path.join(self.dir_fd_path, "batz")
+        if self.os.rename not in self.os.supports_dir_fd:
+            with self.assertRaises(NotImplementedError):
+                os_rename()
+        self.add_supported_function(self.os.rename)
+        if self.os.rename in self.os.supports_dir_fd:
+            os_rename()
+            self.assertTrue(self.os.path.exists(new_name))
 
     def test_rename_dst_fd(self):
-        self.assertRaises(
-            NotImplementedError,
-            self.os.rename,
-            "baz",
-            "/foo/batz",
-            dst_dir_fd=self.dir_fd,
-        )
-        self.os.supports_dir_fd.add(self.os.rename)
-        self.os.rename("/foo/bar", "batz", dst_dir_fd=self.dir_fd)
-        self.assertTrue(self.os.path.exists("/foo/batz"))
+        def os_rename():
+            self.os.rename(self.fpath, "batz", dst_dir_fd=self.dir_fd)
+
+        if self.os.rename not in self.os.supports_dir_fd:
+            with self.assertRaises(NotImplementedError):
+                os_rename()
+        self.add_supported_function(self.os.rename)
+        if self.os.rename in self.os.supports_dir_fd:
+            os_rename()
+            new_path = self.os.path.join(self.dir_fd_path, "batz")
+            self.assertTrue(self.os.path.exists(new_path))
 
     def test_replace_src_fd(self):
-        self.assertRaises(
-            NotImplementedError,
-            self.os.rename,
-            "baz",
-            "/foo/batz",
-            src_dir_fd=self.dir_fd,
-        )
-        self.os.supports_dir_fd.add(self.os.rename)
-        self.os.replace("bar", "/foo/batz", src_dir_fd=self.dir_fd)
-        self.assertTrue(self.os.path.exists("/foo/batz"))
+        new_name = self.os.path.join(self.dir_fd_path, "batz")
+        self.os.replace(self.fname, new_name, src_dir_fd=self.dir_fd)
+        self.assertTrue(self.os.path.exists(new_name))
 
     def test_replace_dst_fd(self):
-        self.assertRaises(
-            NotImplementedError,
-            self.os.rename,
-            "baz",
-            "/foo/batz",
-            dst_dir_fd=self.dir_fd,
-        )
-        self.os.supports_dir_fd.add(self.os.rename)
-        self.os.replace("/foo/bar", "batz", dst_dir_fd=self.dir_fd)
-        self.assertTrue(self.os.path.exists("/foo/batz"))
+        self.os.replace(self.fpath, "batz", dst_dir_fd=self.dir_fd)
+        new_path = self.os.path.join(self.dir_fd_path, "batz")
+        self.assertTrue(self.os.path.exists(new_path))
 
     def test_remove(self):
-        self.assertRaises(
-            NotImplementedError, self.os.remove, "baz", dir_fd=self.dir_fd
-        )
-        self.os.supports_dir_fd.add(self.os.remove)
-        self.os.remove("baz", dir_fd=self.dir_fd)
-        self.assertFalse(self.os.path.exists("/foo/baz"))
+        self.os.remove(self.fname, dir_fd=self.dir_fd)
+        self.assertFalse(self.os.path.exists(self.fpath))
 
     def test_unlink(self):
-        self.assertRaises(
-            NotImplementedError, self.os.unlink, "baz", dir_fd=self.dir_fd
-        )
-        self.os.supports_dir_fd.add(self.os.unlink)
-        self.os.unlink("baz", dir_fd=self.dir_fd)
-        self.assertFalse(self.os.path.exists("/foo/baz"))
+        def os_unlink():
+            self.os.unlink(self.fname, dir_fd=self.dir_fd)
+
+        if self.os.unlink not in self.os.supports_dir_fd:
+            with self.assertRaises(NotImplementedError):
+                os_unlink()
+        self.add_supported_function(self.os.unlink)
+        if self.os.unlink in self.os.supports_dir_fd:
+            os_unlink()
+            self.assertFalse(self.os.path.exists(self.fpath))
 
     def test_utime(self):
-        self.assertRaises(
-            NotImplementedError,
-            self.os.utime,
-            "baz",
-            (1, 2),
-            dir_fd=self.dir_fd,
-        )
-        self.os.supports_dir_fd.add(self.os.utime)
-        self.os.utime("baz", times=(1, 2), dir_fd=self.dir_fd)
-        st = self.os.stat("/foo/baz")
-        self.assertEqual(1, st.st_atime)
-        self.assertEqual(2, st.st_mtime)
+        def os_utime():
+            self.os.utime(self.fname, times=(1, 2), dir_fd=self.dir_fd)
+
+        if self.os.utime not in self.os.supports_dir_fd:
+            with self.assertRaises(NotImplementedError):
+                os_utime()
+        self.add_supported_function(self.os.utime)
+        if self.os.utime in self.os.supports_dir_fd:
+            os_utime()
+            st = self.os.stat(self.fpath)
+            self.assertEqual(1, st.st_atime)
+            self.assertEqual(2, st.st_mtime)
 
     def test_open(self):
-        self.assertRaises(
-            NotImplementedError,
-            self.os.open,
-            "baz",
-            os.O_RDONLY,
-            dir_fd=self.dir_fd,
-        )
-        self.os.supports_dir_fd.add(self.os.open)
-        fd = self.os.open("baz", os.O_RDONLY, dir_fd=self.dir_fd)
-        self.assertLess(0, fd)
+        def os_open():
+            return self.os.open(self.fname, os.O_RDONLY, dir_fd=self.dir_fd)
+
+        if self.os.open not in self.os.supports_dir_fd:
+            with self.assertRaises(NotImplementedError):
+                os_open()
+        self.add_supported_function(self.os.open)
+        if self.os.open in self.os.supports_dir_fd:
+            self.assertLess(0, os_open())
+
+
+class RealOsModuleDirFdTest(FakeOsModuleDirFdTest):
+    def use_real_fs(self):
+        return True
 
 
 class StatPropagationTest(TestCase):
@@ -4912,7 +5178,7 @@ class StatPropagationTest(TestCase):
         file_path = "xyzzy/close"
         content = "This is a test."
         self.os.mkdir(file_dir)
-        fh = self.open(file_path, "w")
+        fh = self.open(file_path, "w", encoding="utf8")
         self.assertEqual(0, self.os.stat(file_path)[stat.ST_SIZE])
         self.assertEqual("", self.filesystem.get_object(file_path).contents)
         fh.write(content)
@@ -4930,9 +5196,9 @@ class StatPropagationTest(TestCase):
         # The file has size, but no content. When the file is opened for
         # reading, its size should be preserved.
         self.filesystem.create_file(file_path, st_size=size)
-        fh = self.open(file_path, "r")
+        fh = self.open(file_path, "r", encoding="utf8")
         fh.close()
-        self.assertEqual(size, self.open(file_path, "r").size())
+        self.assertEqual(size, self.open(file_path, "r", encoding="utf8").size())
 
     def test_file_size_after_write(self):
         file_path = "test_file"
@@ -4941,11 +5207,13 @@ class StatPropagationTest(TestCase):
         self.filesystem.create_file(file_path, contents=original_content)
         added_content = "foo bar"
         expected_size = original_size + len(added_content)
-        fh = self.open(file_path, "a")
+        fh = self.open(file_path, "a", encoding="utf8")
         fh.write(added_content)
         self.assertEqual(original_size, fh.size())
         fh.close()
-        self.assertEqual(expected_size, self.open(file_path, "r").size())
+        self.assertEqual(
+            expected_size, self.open(file_path, "r", encoding="utf8").size()
+        )
 
     def test_large_file_size_after_write(self):
         file_path = "test_file"
@@ -4953,7 +5221,7 @@ class StatPropagationTest(TestCase):
         original_size = len(original_content)
         self.filesystem.create_file(file_path, st_size=original_size)
         added_content = "foo bar"
-        fh = self.open(file_path, "a")
+        fh = self.open(file_path, "a", encoding="utf8")
         self.assertRaises(
             fake_file.FakeLargeFileIoException,
             lambda: fh.write(added_content),
@@ -4966,7 +5234,7 @@ class StatPropagationTest(TestCase):
         file_path = self.os.path.join(file_dir, file_name)
         content = "This might be a test."
         self.os.mkdir(file_dir)
-        fh = self.open(file_path, "w")
+        fh = self.open(file_path, "w", encoding="utf8")
         self.assertEqual(0, self.os.stat(file_path)[stat.ST_SIZE])
         self.assertEqual("", self.filesystem.get_object(file_path).contents)
         fh.write(content)
@@ -4987,41 +5255,30 @@ class StatPropagationTest(TestCase):
 
         # pre-create file with content
         self.os.mkdir(file_dir)
-        fh = self.open(file_path, "w")
+        fh = self.open(file_path, "w", encoding="utf8")
         fh.write(content)
         fh.close()
         self.assertEqual(len(content), self.os.stat(file_path)[stat.ST_SIZE])
         self.assertEqual(content, self.filesystem.get_object(file_path).contents)
 
         # test file truncation
-        fh = self.open(file_path, "w")
+        fh = self.open(file_path, "w", encoding="utf8")
         self.assertEqual(0, self.os.stat(file_path)[stat.ST_SIZE])
         self.assertEqual("", self.filesystem.get_object(file_path).contents)
         fh.close()
 
 
-@unittest.skipIf(not use_scandir, "only run if scandir is available")
 class FakeScandirTest(FakeOsModuleTestBase):
     FILE_SIZE = 50
     LINKED_FILE_SIZE = 10
 
+    def used_scandir(self):
+        return self.os.scandir
+
     def setUp(self):
-        super(FakeScandirTest, self).setUp()
+        super().setUp()
         self.supports_symlinks = not self.is_windows or not self.use_real_fs()
-
-        if use_scandir_package:
-            if self.use_real_fs():
-                from scandir import scandir
-            else:
-                import pyfakefs.fake_scandir
-
-                def fake_scan_dir(p):
-                    return pyfakefs.fake_scandir.scandir(self.filesystem, p)
-
-                scandir = fake_scan_dir
-        else:
-            scandir = self.os.scandir
-        self.scandir = scandir
+        self.scandir = self.used_scandir()
 
         self.directory = self.make_path("xyzzy", "plugh")
         link_dir = self.make_path("linked", "plugh")
@@ -5046,7 +5303,7 @@ class FakeScandirTest(FakeOsModuleTestBase):
             self.create_dir(self.linked_dir_path)
             self.create_file(
                 self.linked_file_path, contents=b"a" * self.LINKED_FILE_SIZE
-            ),
+            )
             self.create_symlink(self.dir_link_path, self.linked_dir_path)
             self.create_symlink(self.file_link_path, self.linked_file_path)
             self.create_symlink(self.dir_rel_link_path, self.rel_linked_dir_path)
@@ -5139,7 +5396,7 @@ class FakeScandirTest(FakeOsModuleTestBase):
         )
 
     def test_inode(self):
-        if use_scandir and self.use_real_fs():
+        if self.use_real_fs():
             if self.is_windows:
                 self.skipTest("inode seems not to work in scandir module under Windows")
             if IN_DOCKER:
@@ -5183,7 +5440,6 @@ class FakeScandirTest(FakeOsModuleTestBase):
                 self.assertEqual(1, self.os.stat(self.file_path).st_nlink)
 
     @unittest.skipIf(not hasattr(os, "O_DIRECTORY"), "opening directory not supported")
-    @unittest.skipIf(sys.version_info < (3, 7), "fd not supported for scandir")
     def test_scandir_with_fd(self):
         # regression test for #723
         temp_dir = self.make_path("tmp", "dir")
@@ -5196,6 +5452,20 @@ class FakeScandirTest(FakeOsModuleTestBase):
         children = [dir_entry.name for dir_entry in self.os.scandir(fd)]
         assert sorted(children) == ["file1", "file2", "subdir"]
 
+    def test_file_removed_during_scandir(self):
+        # regression test for #1051
+        dir_path = self.make_path("wls")
+        file1_path = self.os.path.join(dir_path, "1.log")
+        self.create_file(file1_path)
+        file2_path = self.os.path.join(dir_path, "2.log")
+        self.create_file(file2_path)
+        with self.os.scandir(dir_path) as it:
+            for entry in it:
+                if entry.is_file():
+                    self.os.remove(entry.path)
+        assert not self.os.path.exists(file1_path)
+        assert not self.os.path.exists(file2_path)
+
     def check_stat(
         self, absolute_symlink_expected_size, relative_symlink_expected_size
     ):
@@ -5260,10 +5530,6 @@ class FakeScandirTest(FakeOsModuleTestBase):
             self.assertEqual(file_stat.st_ino, self.dir_entries[5].stat().st_ino)
             self.assertEqual(file_stat.st_dev, self.dir_entries[5].stat().st_dev)
 
-    @unittest.skipIf(
-        sys.version_info < (3, 6) or not use_builtin_scandir,
-        "Path-like objects have been introduced in Python 3.6",
-    )
     def test_path_like(self):
         self.assertTrue(isinstance(self.dir_entries[0], os.PathLike))
         self.assertEqual(
@@ -5302,11 +5568,10 @@ class RealScandirRelTest(FakeScandirRelTest):
 
 
 @unittest.skipIf(TestCase.is_windows, "dir_fd not supported for os.scandir in Windows")
-@unittest.skipIf(use_scandir_package, "no dir_fd support for scandir package")
 class FakeScandirFdTest(FakeScandirTest):
     def tearDown(self):
         self.os.close(self.dir_fd)
-        super(FakeScandirFdTest, self).tearDown()
+        super().tearDown()
 
     def scandir_path(self):
         # When scandir is called with a filedescriptor, only the name of the
@@ -5336,7 +5601,7 @@ class RealScandirFdRelTest(FakeScandirFdRelTest):
 
 class FakeExtendedAttributeTest(FakeOsModuleTestBase):
     def setUp(self):
-        super(FakeExtendedAttributeTest, self).setUp()
+        super().setUp()
         self.check_linux_only()
         self.dir_path = self.make_path("foo")
         self.file_path = self.os.path.join(self.dir_path, "bar")
@@ -5346,26 +5611,25 @@ class FakeExtendedAttributeTest(FakeOsModuleTestBase):
         self.assertEqual([], self.os.listxattr(self.dir_path))
         self.assertEqual([], self.os.listxattr(self.file_path))
 
+    def test_getxattr_raises_for_non_existing_file(self):
+        with self.assertRaises(FileNotFoundError):
+            self.os.getxattr("bogus_path", "test")
+
+    def test_getxattr_raises_for_non_existing_attribute(self):
+        with self.assertRaises(OSError) as cm:
+            self.os.getxattr(self.file_path, "bogus")
+        self.assertEqual(errno.ENODATA, cm.exception.errno)
+
     def test_setxattr(self):
-        self.assertRaises(TypeError, self.os.setxattr, self.file_path, "test", "value")
-        self.assert_raises_os_error(
-            errno.EEXIST,
-            self.os.setxattr,
-            self.file_path,
-            "test",
-            b"value",
-            self.os.XATTR_REPLACE,
-        )
+        with self.assertRaises(TypeError):
+            self.os.setxattr(self.file_path, "test", "value")
+        with self.assertRaises(FileExistsError):
+            self.os.setxattr(self.file_path, "test", b"value", self.os.XATTR_REPLACE)
         self.os.setxattr(self.file_path, "test", b"value")
         self.assertEqual(b"value", self.os.getxattr(self.file_path, "test"))
-        self.assert_raises_os_error(
-            errno.ENODATA,
-            self.os.setxattr,
-            self.file_path,
-            "test",
-            b"value",
-            self.os.XATTR_CREATE,
-        )
+        with self.assertRaises(OSError) as cm:
+            self.os.setxattr(self.file_path, "test", b"value", self.os.XATTR_CREATE)
+        self.assertEqual(errno.ENODATA, cm.exception.errno)
 
     def test_removeattr(self):
         self.os.removexattr(self.file_path, "test")
@@ -5375,7 +5639,9 @@ class FakeExtendedAttributeTest(FakeOsModuleTestBase):
         self.assertEqual(b"value", self.os.getxattr(self.file_path, "test"))
         self.os.removexattr(self.file_path, "test")
         self.assertEqual([], self.os.listxattr(self.file_path))
-        self.assertIsNone(self.os.getxattr(self.file_path, "test"))
+        with self.assertRaises(OSError) as cm:
+            self.os.getxattr(self.file_path, "test")
+        self.assertEqual(errno.ENODATA, cm.exception.errno)
 
     def test_default_path(self):
         self.os.chdir(self.dir_path)
@@ -5391,7 +5657,7 @@ class FakeOsUnreadableDirTest(FakeOsModuleTestBase):
             # and cannot be created in the real OS using file system
             # functions only
             self.check_posix_only()
-        super(FakeOsUnreadableDirTest, self).setUp()
+        super().setUp()
         self.dir_path = self.make_path("some_dir")
         self.file_path = self.os.path.join(self.dir_path, "some_file")
         self.create_file(self.file_path)
@@ -5410,7 +5676,7 @@ class FakeOsUnreadableDirTest(FakeOsModuleTestBase):
         set_uid(uid + 10)
         self.assertEqual(uid + 10, self.os.getuid())
         self.assertEqual(uid + 10, get_uid())
-        set_uid(uid)
+        reset_ids()
         self.assertEqual(uid, self.os.getuid())
 
     def test_getgid(self):
@@ -5420,7 +5686,7 @@ class FakeOsUnreadableDirTest(FakeOsModuleTestBase):
         set_gid(gid + 10)
         self.assertEqual(gid + 10, self.os.getgid())
         self.assertEqual(gid + 10, get_gid())
-        set_gid(gid)
+        reset_ids()
         self.assertEqual(gid, self.os.getgid())
 
     def test_listdir_unreadable_dir(self):
@@ -5439,24 +5705,24 @@ class FakeOsUnreadableDirTest(FakeOsModuleTestBase):
         self.check_posix_only()
         user_id = get_uid()
         set_uid(user_id + 1)
-        dir_path = self.make_path("dir1")
+        dir_path = "/dir1"
         self.create_dir(dir_path, perm=0o600)
         self.assertTrue(self.os.path.exists(dir_path))
-        set_uid(user_id)
+        reset_ids()
         if not is_root():
             with self.assertRaises(PermissionError):
                 self.os.listdir(dir_path)
         else:
-            self.assertEqual(["some_file"], self.os.listdir(self.dir_path))
+            self.assertEqual([], self.os.listdir(dir_path))
 
     def test_listdir_group_readable_dir_from_other_user(self):
         self.skip_real_fs()  # won't change user in real fs
-        user_id = get_uid()
-        set_uid(user_id + 1)
-        dir_path = self.make_path("dir1")
+        self.check_posix_only()
+        set_uid(get_uid() + 1)
+        dir_path = "/dir1"
         self.create_dir(dir_path, perm=0o660)
         self.assertTrue(self.os.path.exists(dir_path))
-        set_uid(user_id)
+        reset_ids()
         self.assertEqual([], self.os.listdir(dir_path))
 
     def test_listdir_group_readable_dir_from_other_group(self):
@@ -5464,7 +5730,7 @@ class FakeOsUnreadableDirTest(FakeOsModuleTestBase):
         self.check_posix_only()
         group_id = self.os.getgid()
         set_gid(group_id + 1)
-        dir_path = self.make_path("dir1")
+        dir_path = "/dir1"
         self.create_dir(dir_path, perm=0o060)
         self.assertTrue(self.os.path.exists(dir_path))
         set_gid(group_id)
@@ -5475,14 +5741,15 @@ class FakeOsUnreadableDirTest(FakeOsModuleTestBase):
             self.assertEqual([], self.os.listdir(dir_path))
 
     def test_listdir_other_readable_dir_from_other_group(self):
+        self.check_posix_only()
         self.skip_real_fs()  # won't change user in real fs
-        group_id = get_gid()
-        set_gid(group_id + 1)
         dir_path = self.make_path("dir1")
-        self.create_dir(dir_path, perm=0o004)
+        self.create_dir(dir_path, 0o004)
+        set_uid(get_uid() + 1)
+        set_gid(get_gid() + 1)
         self.assertTrue(self.os.path.exists(dir_path))
-        set_gid(group_id)
         self.assertEqual([], self.os.listdir(dir_path))
+        reset_ids()
 
     def test_stat_unreadable_dir(self):
         self.assertEqual(0, self.os.stat(self.dir_path).st_mode & 0o666)
@@ -5508,13 +5775,13 @@ class FakeOsUnreadableDirTest(FakeOsModuleTestBase):
         self.assertFalse(self.os.path.exists(dir_path))
 
     def test_remove_unreadable_dir_from_other_user(self):
+        self.check_posix_only()
         self.skip_real_fs()  # won't change user in real fs
-        user_id = get_uid()
-        set_uid(user_id + 1)
-        dir_path = self.make_path("dir1")
+        set_uid(get_uid() + 1)
+        dir_path = "/dir1"
         self.create_dir(dir_path, perm=0o000)
         self.assertTrue(self.os.path.exists(dir_path))
-        set_uid(user_id)
+        reset_ids()
         if not is_root():
             with self.assertRaises(PermissionError):
                 self.os.rmdir(dir_path)
diff --git a/pyfakefs/tests/fake_pathlib_test.py b/pyfakefs/tests/fake_pathlib_test.py
index 12820ba..fa8fedf 100644
--- a/pyfakefs/tests/fake_pathlib_test.py
+++ b/pyfakefs/tests/fake_pathlib_test.py
@@ -19,6 +19,7 @@ Note that many of the tests are directly taken from examples in the
 python docs.
 """
 
+import contextlib
 import errno
 import os
 import pathlib
@@ -32,6 +33,12 @@ from unittest.mock import patch
 from pyfakefs import fake_pathlib, fake_filesystem, fake_filesystem_unittest, fake_os
 from pyfakefs.fake_filesystem import OSType
 from pyfakefs.helpers import IS_PYPY, is_root
+from pyfakefs.tests.skipped_pathlib import (
+    check_exists_pathlib,
+    read_bytes_pathlib,
+    read_pathlib,
+    read_text_pathlib,
+)
 from pyfakefs.tests.test_utils import RealFsTestMixin
 
 is_windows = sys.platform == "win32"
@@ -44,6 +51,9 @@ class RealPathlibTestCase(fake_filesystem_unittest.TestCase, RealFsTestMixin):
         fake_filesystem_unittest.TestCase.__init__(self, methodName)
         RealFsTestMixin.__init__(self)
 
+    def used_pathlib(self):
+        return pathlib
+
     def setUp(self):
         RealFsTestMixin.setUp(self)
         self.filesystem = None
@@ -52,8 +62,8 @@ class RealPathlibTestCase(fake_filesystem_unittest.TestCase, RealFsTestMixin):
             self.setUpPyfakefs()
             self.filesystem = self.fs
             self.create_basepath()
-        self.pathlib = pathlib
-        self.path = pathlib.Path
+        self.pathlib = self.used_pathlib()
+        self.path = self.pathlib.Path
         self.os = os
         self.open = open
 
@@ -188,7 +198,7 @@ class FakePathlibInitializationWithDriveTest(RealPathlibTestCase):
         )
         self.assertEqual(path.parents[1], self.path("d:"))
 
-    @unittest.skipIf(not is_windows, "Windows-specifc behavior")
+    @unittest.skipIf(not is_windows, "Windows-specific behavior")
     def test_is_absolute(self):
         self.assertTrue(self.path("c:/a/b").is_absolute())
         self.assertFalse(self.path("/a/b").is_absolute())
@@ -206,18 +216,28 @@ class FakePathlibPurePathTest(RealPathlibTestCase):
 
     def test_is_reserved_posix(self):
         self.check_posix_only()
-        self.assertFalse(self.path("/dev").is_reserved())
-        self.assertFalse(self.path("/").is_reserved())
-        self.assertFalse(self.path("COM1").is_reserved())
-        self.assertFalse(self.path("nul.txt").is_reserved())
+        with (
+            contextlib.nullcontext()
+            if sys.version_info < (3, 13)
+            else self.assertWarns(DeprecationWarning)
+        ):
+            self.assertFalse(self.path("/dev").is_reserved())
+            self.assertFalse(self.path("/").is_reserved())
+            self.assertFalse(self.path("COM1").is_reserved())
+            self.assertFalse(self.path("nul.txt").is_reserved())
 
     @unittest.skipIf(not is_windows, "Windows specific behavior")
     def test_is_reserved_windows(self):
         self.check_windows_only()
-        self.assertFalse(self.path("/dev").is_reserved())
-        self.assertFalse(self.path("/").is_reserved())
-        self.assertTrue(self.path("COM1").is_reserved())
-        self.assertTrue(self.path("nul.txt").is_reserved())
+        with (
+            contextlib.nullcontext()
+            if sys.version_info < (3, 13)
+            else self.assertWarns(DeprecationWarning)
+        ):
+            self.assertFalse(self.path("/dev").is_reserved())
+            self.assertFalse(self.path("/").is_reserved())
+            self.assertTrue(self.path("COM1").is_reserved())
+            self.assertTrue(self.path("nul.txt").is_reserved())
 
     def test_joinpath(self):
         self.assertEqual(self.path("/etc").joinpath("passwd"), self.path("/etc/passwd"))
@@ -283,9 +303,177 @@ class RealPathlibPurePathTest(FakePathlibPurePathTest):
         return True
 
 
+class FakePathlibPurePosixPathTest(RealPathlibTestCase):
+    def setUp(self):
+        super().setUp()
+        self.path = self.pathlib.PurePosixPath
+
+    def test_is_reserved(self):
+        with (
+            contextlib.nullcontext()
+            if sys.version_info < (3, 13)
+            else self.assertWarns(DeprecationWarning)
+        ):
+            self.assertFalse(self.path("/dev").is_reserved())
+            self.assertFalse(self.path("/").is_reserved())
+            self.assertFalse(self.path("COM1").is_reserved())
+            self.assertFalse(self.path("nul.txt").is_reserved())
+
+    def test_joinpath(self):
+        self.assertEqual(self.path("/etc").joinpath("passwd"), self.path("/etc/passwd"))
+        self.assertEqual(
+            self.path("/etc").joinpath(self.path("passwd")),
+            self.path("/etc/passwd"),
+        )
+        self.assertEqual(
+            self.path("/foo").joinpath("bar", "baz"), self.path("/foo/bar/baz")
+        )
+        self.assertEqual(
+            self.path("c:").joinpath("/Program Files"),
+            self.path("/Program Files"),
+        )
+
+    def test_match(self):
+        self.assertTrue(self.path("a/b.py").match("*.py"))
+        self.assertTrue(self.path("/a/b/c.py").match("b/*.py"))
+        self.assertFalse(self.path("/a/b/c.py").match("a/*.py"))
+        self.assertTrue(self.path("/a.py").match("/*.py"))
+        self.assertFalse(self.path("a/b.py").match("/*.py"))
+
+    def test_relative_to(self):
+        self.assertEqual(
+            self.path("/etc/passwd").relative_to("/"), self.path("etc/passwd")
+        )
+        self.assertEqual(
+            self.path("/etc/passwd").relative_to("/"), self.path("etc/passwd")
+        )
+        with self.assertRaises(ValueError):
+            self.path("passwd").relative_to("/usr")
+
+    @unittest.skipIf(sys.version_info < (3, 9), "is_relative_to new in Python 3.9")
+    def test_is_relative_to(self):
+        path = self.path("/etc/passwd")
+        self.assertTrue(path.is_relative_to("/etc"))
+        self.assertFalse(path.is_relative_to("/src"))
+
+    def test_with_name(self):
+        self.assertEqual(
+            self.path("c:/Downloads/pathlib.tar.gz").with_name("setup.py"),
+            self.path("c:/Downloads/setup.py"),
+        )
+        self.assertEqual(self.path("c:/").with_name("setup.py"), self.path("setup.py"))
+
+    def test_with_suffix(self):
+        self.assertEqual(
+            self.path("c:/Downloads/pathlib.tar.gz").with_suffix(".bz2"),
+            self.path("c:/Downloads/pathlib.tar.bz2"),
+        )
+        self.assertEqual(
+            self.path("README").with_suffix(".txt"), self.path("README.txt")
+        )
+
+    def test_to_string(self):
+        self.assertEqual(str(self.path("/usr/bin/ls")), "/usr/bin/ls")
+        self.assertEqual(str(self.path("usr") / "bin" / "ls"), "usr/bin/ls")
+
+
+class RealPathlibPurePosixPathTest(FakePathlibPurePosixPathTest):
+    def use_real_fs(self):
+        return True
+
+
+class FakePathlibPureWindowsPathTest(RealPathlibTestCase):
+    def setUp(self):
+        super().setUp()
+        self.path = self.pathlib.PureWindowsPath
+
+    def test_is_reserved(self):
+        with (
+            contextlib.nullcontext()
+            if sys.version_info < (3, 13)
+            else self.assertWarns(DeprecationWarning)
+        ):
+            self.assertFalse(self.path("/dev").is_reserved())
+            self.assertFalse(self.path("/").is_reserved())
+            self.assertTrue(self.path("COM1").is_reserved())
+            self.assertTrue(self.path("nul.txt").is_reserved())
+
+    def test_joinpath(self):
+        self.assertEqual(self.path("/etc").joinpath("passwd"), self.path("/etc/passwd"))
+        self.assertEqual(
+            self.path("/etc").joinpath(self.path("passwd")),
+            self.path("/etc/passwd"),
+        )
+        self.assertEqual(
+            self.path("/foo").joinpath("bar", "baz"), self.path("/foo/bar/baz")
+        )
+        self.assertEqual(
+            self.path("c:").joinpath("/Program Files"),
+            self.path("c:/Program Files"),
+        )
+
+    def test_match(self):
+        self.assertTrue(self.path("a/b.py").match("*.py"))
+        self.assertTrue(self.path("/a/b/c.py").match("b/*.py"))
+        self.assertFalse(self.path("/a/b/c.py").match("a/*.py"))
+        self.assertTrue(self.path("/a.py").match("/*.py"))
+        self.assertFalse(self.path("a/b.py").match("/*.py"))
+
+    def test_relative_to(self):
+        self.assertEqual(
+            self.path("/etc/passwd").relative_to("/"), self.path("etc/passwd")
+        )
+        self.assertEqual(
+            self.path("/etc/passwd").relative_to("/"), self.path("etc/passwd")
+        )
+        with self.assertRaises(ValueError):
+            self.path("passwd").relative_to("/usr")
+
+    @unittest.skipIf(sys.version_info < (3, 9), "is_relative_to new in Python 3.9")
+    def test_is_relative_to(self):
+        path = self.path("/etc/passwd")
+        self.assertTrue(path.is_relative_to("/etc"))
+        self.assertFalse(path.is_relative_to("/src"))
+
+    def test_with_name(self):
+        self.assertEqual(
+            self.path("c:/Downloads/pathlib.tar.gz").with_name("setup.py"),
+            self.path("c:/Downloads/setup.py"),
+        )
+        with self.assertRaises(ValueError):
+            self.path("c:/").with_name("setup.py")
+
+    def test_with_suffix(self):
+        self.assertEqual(
+            self.path("c:/Downloads/pathlib.tar.gz").with_suffix(".bz2"),
+            self.path("c:/Downloads/pathlib.tar.bz2"),
+        )
+        self.assertEqual(
+            self.path("README").with_suffix(".txt"), self.path("README.txt")
+        )
+
+    def test_to_string(self):
+        self.assertEqual(str(self.path("/usr/bin/ls")), "\\usr\\bin\\ls")
+        self.assertEqual(
+            str(self.path("c:/Windows/System32/ntoskrnl.exe")),
+            "c:\\Windows\\System32\\ntoskrnl.exe",
+        )
+        self.assertEqual(str(self.path("usr") / "bin" / "ls"), "usr\\bin\\ls")
+        self.assertEqual(
+            str(self.path("C:/") / "Windows" / "System32" / "ntoskrnl.exe"),
+            "C:\\Windows\\System32\\ntoskrnl.exe",
+        )
+
+
+class RealPathlibPureWindowsPathTest(FakePathlibPureWindowsPathTest):
+    def use_real_fs(self):
+        return True
+
+
 class FakePathlibFileObjectPropertyTest(RealPathlibTestCase):
     def setUp(self):
-        super(FakePathlibFileObjectPropertyTest, self).setUp()
+        super().setUp()
+        self.umask = self.os.umask(0o022)
         self.file_path = self.make_path("home", "jane", "test.py")
         self.create_file(self.file_path, contents=b"a" * 100)
         self.create_dir(self.make_path("home", "john"))
@@ -304,6 +492,9 @@ class FakePathlibFileObjectPropertyTest(RealPathlibTestCase):
             self.make_path("home", "none", "test.py"),
         )
 
+    def tearDown(self):
+        self.os.umask(self.umask)
+
     def test_exists(self):
         self.skip_if_symlink_not_supported()
         self.assertTrue(self.path(self.file_path).exists())
@@ -373,14 +564,15 @@ class FakePathlibFileObjectPropertyTest(RealPathlibTestCase):
         self.skip_if_symlink_not_supported()
         self.check_lstat(0)
 
-    @unittest.skipIf(is_windows, "Linux specific behavior")
+    @unittest.skipIf(is_windows, "POSIX specific behavior")
     def test_chmod(self):
-        self.check_linux_only()
+        self.check_posix_only()
         file_stat = self.os.stat(self.file_path)
-        self.assertEqual(file_stat.st_mode, stat.S_IFREG | 0o666)
+        self.assertEqual(file_stat.st_mode, stat.S_IFREG | 0o644)
         link_stat = self.os.lstat(self.file_link_path)
         # we get stat.S_IFLNK | 0o755 under MacOs
-        self.assertEqual(link_stat.st_mode, stat.S_IFLNK | 0o777)
+        mode = 0o755 if self.is_macos else 0o777
+        self.assertEqual(link_stat.st_mode, stat.S_IFLNK | mode)
 
     def test_lchmod(self):
         self.skip_if_symlink_not_supported()
@@ -391,9 +583,11 @@ class FakePathlibFileObjectPropertyTest(RealPathlibTestCase):
                 self.path(self.file_link_path).lchmod(0o444)
         else:
             self.path(self.file_link_path).lchmod(0o444)
-            self.assertEqual(file_stat.st_mode, stat.S_IFREG | 0o666)
+            mode = 0o666 if is_windows else 0o644
+            self.assertEqual(file_stat.st_mode, stat.S_IFREG | mode)
             # the exact mode depends on OS and Python version
-            self.assertEqual(link_stat.st_mode & 0o777700, stat.S_IFLNK | 0o700)
+            mode_mask = 0o600 if self.is_windows_fs else 0o700
+            self.assertEqual(link_stat.st_mode & 0o777700, stat.S_IFLNK | mode_mask)
 
     @unittest.skipIf(
         sys.version_info < (3, 10),
@@ -408,15 +602,17 @@ class FakePathlibFileObjectPropertyTest(RealPathlibTestCase):
                 self.path(self.file_link_path).chmod(0o444, follow_symlinks=False)
         else:
             self.path(self.file_link_path).chmod(0o444, follow_symlinks=False)
-            self.assertEqual(file_stat.st_mode, stat.S_IFREG | 0o666)
+            mode = 0o666 if is_windows else 0o644
+            self.assertEqual(file_stat.st_mode, stat.S_IFREG | mode)
             # the exact mode depends on OS and Python version
-            self.assertEqual(link_stat.st_mode & 0o777700, stat.S_IFLNK | 0o700)
+            mode_mask = 0o600 if self.is_windows_fs else 0o700
+            self.assertEqual(link_stat.st_mode & 0o777700, stat.S_IFLNK | mode_mask)
 
     def test_resolve(self):
         self.create_dir(self.make_path("antoine", "docs"))
         self.create_file(self.make_path("antoine", "setup.py"))
         self.os.chdir(self.make_path("antoine"))
-        # use real path to handle symlink /var to /private/var in MacOs
+        # use real path to handle symlink /var to /private/var in macOS
         self.assert_equal_paths(
             self.path().resolve(),
             self.path(self.os.path.realpath(self.make_path("antoine"))),
@@ -443,13 +639,62 @@ class FakePathlibFileObjectPropertyTest(RealPathlibTestCase):
         file_path = self.os.path.join(dir_path, "some_file")
         self.create_file(file_path)
         self.os.chmod(dir_path, 0o000)
-        it = self.path(dir_path).iterdir()
         if not is_root():
-            self.assert_raises_os_error(errno.EACCES, list, it)
+            if sys.version_info >= (3, 13):
+                self.assert_raises_os_error(errno.EACCES, self.path(dir_path).iterdir)
+            else:
+                it = self.path(dir_path).iterdir()
+                self.assert_raises_os_error(errno.EACCES, list, it)
         else:
+            it = self.path(dir_path).iterdir()
             path = str(list(it)[0])
             self.assertTrue(path.endswith("some_file"))
 
+    def test_iterdir_and_glob_without_exe_permission(self):
+        # regression test for #960
+        self.check_posix_only()
+        self.skip_root()
+        directory = self.path(self.make_path("testdir"))
+        file_path = directory / "file.txt"
+        self.create_file(file_path, contents="hey", perm=0o777)
+        directory.chmod(0o655)  # rw-r-xr-x
+        # We cannot create any files in the directory, because that requires
+        # searching it
+        another_file = self.path(self.make_path("file.txt"))
+        self.create_file(another_file, contents="hey")
+        with self.assertRaises(PermissionError):
+            self.os.link(another_file, directory / "link.txt")
+        # We can enumerate the directory using iterdir and glob:
+        assert len(list(directory.iterdir())) == 1
+        assert list(directory.iterdir())[0] == file_path
+        assert len(list(directory.glob("*.txt"))) == 1
+        assert list(directory.glob("*.txt"))[0] == file_path
+
+        # We cannot read files inside the directory,
+        # even if we have read access to the file
+        with self.assertRaises(PermissionError):
+            file_path.stat()
+        with self.assertRaises(PermissionError):
+            file_path.read_text(encoding="utf8")
+
+    def test_iterdir_impossible_without_read_permission(self):
+        # regression test for #960
+        self.check_posix_only()
+        self.skip_root()
+        directory = self.path(self.make_path("testdir"))
+        file_path = directory / "file.txt"
+        self.create_file(file_path, contents="hey", perm=0o777)
+        directory.chmod(0o355)  # -wxr-xr-x
+
+        # We cannot enumerate the directory using iterdir:
+        with self.assertRaises(PermissionError):
+            list(directory.iterdir())
+        # glob does not find the file
+        assert len(list(directory.glob("*.txt"))) == 0
+        # we can access the file if we know the file name
+        assert file_path.stat().st_mode & 0o777 == 0o755
+        assert file_path.read_text(encoding="utf8") == "hey"
+
     def test_resolve_nonexisting_file(self):
         path = self.path(self.make_path("/path", "to", "file", "this can not exist"))
         self.assertEqual(path, path.resolve())
@@ -462,7 +707,9 @@ class FakePathlibFileObjectPropertyTest(RealPathlibTestCase):
             self.path.cwd(), self.path(self.os.path.realpath(dir_path))
         )
 
-    @unittest.skipIf(sys.platform != "win32", "Windows specific test")
+    @unittest.skipIf(
+        sys.platform != "win32" or sys.version_info < (3, 8), "Windows specific test"
+    )
     @patch.dict(os.environ, {"USERPROFILE": r"C:\Users\John"})
     def test_expanduser_windows(self):
         self.assertEqual(
@@ -475,7 +722,9 @@ class FakePathlibFileObjectPropertyTest(RealPathlibTestCase):
     def test_expanduser_posix(self):
         self.assertEqual(self.path("~").expanduser(), self.path("/home/john"))
 
-    @unittest.skipIf(sys.platform != "win32", "Windows specific test")
+    @unittest.skipIf(
+        sys.platform != "win32" or sys.version_info < (3, 8), "Windows specific test"
+    )
     @patch.dict(os.environ, {"USERPROFILE": r"C:\Users\John"})
     def test_home_windows(self):
         self.assertEqual(
@@ -513,14 +762,14 @@ class FakePathlibPathFileOperationTest(RealPathlibTestCase):
     def test_open(self):
         self.create_dir(self.make_path("foo"))
         with self.assertRaises(OSError):
-            self.path(self.make_path("foo", "bar.txt")).open()
-        self.path(self.make_path("foo", "bar.txt")).open("w").close()
+            self.path(self.make_path("foo", "bar.txt")).open(encoding="utf8")
+        self.path(self.make_path("foo", "bar.txt")).open("w", encoding="utf8").close()
         self.assertTrue(self.os.path.exists(self.make_path("foo", "bar.txt")))
 
     def test_read_text(self):
         self.create_file(self.make_path("text_file"), contents="foo")
         file_path = self.path(self.make_path("text_file"))
-        self.assertEqual(file_path.read_text(), "foo")
+        self.assertEqual(file_path.read_text(encoding="utf8"), "foo")
 
     @unittest.skipIf(
         sys.version_info < (3, 12),
@@ -541,7 +790,7 @@ class FakePathlibPathFileOperationTest(RealPathlibTestCase):
     def test_write_text(self):
         path_name = self.make_path("text_file")
         file_path = self.path(path_name)
-        file_path.write_text(str("foo"))
+        file_path.write_text("foo", encoding="utf8")
         self.assertTrue(self.os.path.exists(path_name))
         self.check_contents(path_name, "foo")
 
@@ -555,13 +804,13 @@ class FakePathlibPathFileOperationTest(RealPathlibTestCase):
     @unittest.skipIf(sys.version_info < (3, 10), "newline argument new in Python 3.10")
     def test_write_with_newline_arg(self):
         path = self.path(self.make_path("some_file"))
-        path.write_text("1\r\n2\n3\r4", newline="")
+        path.write_text("1\r\n2\n3\r4", newline="", encoding="utf8")
         self.check_contents(path, b"1\r\n2\n3\r4")
-        path.write_text("1\r\n2\n3\r4", newline="\n")
+        path.write_text("1\r\n2\n3\r4", newline="\n", encoding="utf8")
         self.check_contents(path, b"1\r\n2\n3\r4")
-        path.write_text("1\r\n2\n3\r4", newline="\r\n")
+        path.write_text("1\r\n2\n3\r4", newline="\r\n", encoding="utf8")
         self.check_contents(path, b"1\r\r\n2\r\n3\r4")
-        path.write_text("1\r\n2\n3\r4", newline="\r")
+        path.write_text("1\r\n2\n3\r4", newline="\r", encoding="utf8")
         self.check_contents(path, b"1\r\r2\r3\r4")
 
     def test_read_bytes(self):
@@ -665,7 +914,6 @@ class FakePathlibPathFileOperationTest(RealPathlibTestCase):
 
     @unittest.skipIf(sys.version_info < (3, 10), "hardlink_to new in Python 3.10")
     def test_hardlink_to(self):
-        self.skip_if_symlink_not_supported()
         file_name = self.make_path("foo", "bar.txt")
         self.create_file(file_name)
         self.assertEqual(1, self.os.stat(file_name).st_nlink)
@@ -702,6 +950,18 @@ class FakePathlibPathFileOperationTest(RealPathlibTestCase):
             errno.EEXIST, self.path(file_name).mkdir, exist_ok=True
         )
 
+    @unittest.skipIf(not is_windows, "Windows specific behavior")
+    def test_mkdir_with_automount_unc_path(self):
+        self.skip_real_fs()
+        self.path(r"\\test\unc\foo").mkdir(parents=True)
+        self.assertTrue(self.path(r"\\test\unc\foo").exists())
+
+    @unittest.skipIf(not is_windows, "Windows specific behavior")
+    def test_mkdir_with_automount_drive(self):
+        self.skip_real_fs()
+        self.path(r"d:\foo\bar").mkdir(parents=True)
+        self.assertTrue(self.path(r"d:\foo\bar").exists())
+
     def test_rmdir(self):
         dir_name = self.make_path("foo", "bar")
         self.create_dir(dir_name)
@@ -729,32 +989,33 @@ class FakePathlibPathFileOperationTest(RealPathlibTestCase):
         self.create_file(self.make_path("foo", "setup.pyc"))
         path = self.path(self.make_path("foo"))
         self.assertEqual(
-            sorted(path.glob("*.py")),
             [
                 self.path(self.make_path("foo", "all_tests.py")),
                 self.path(self.make_path("foo", "setup.py")),
             ],
+            sorted(path.glob("*.py")),
         )
 
-    @unittest.skipIf(not is_windows, "Windows specific test")
     def test_glob_case_windows(self):
+        self.check_windows_only()
         self.create_file(self.make_path("foo", "setup.py"))
         self.create_file(self.make_path("foo", "all_tests.PY"))
         self.create_file(self.make_path("foo", "README.md"))
         self.create_file(self.make_path("foo", "example.Py"))
         path = self.path(self.make_path("foo"))
         self.assertEqual(
-            sorted(path.glob("*.py")),
             [
                 self.path(self.make_path("foo", "all_tests.PY")),
                 self.path(self.make_path("foo", "example.Py")),
                 self.path(self.make_path("foo", "setup.py")),
             ],
+            sorted(path.glob("*.py")),
         )
 
-    @unittest.skipIf(is_windows, "Posix specific test")
     def test_glob_case_posix(self):
         self.check_posix_only()
+        if sys.platform == "win32" and sys.version_info < (3, 12):
+            self.skipTest(reason="Ignoring inconsistent path delimiters")
         self.create_file(self.make_path("foo", "setup.py"))
         self.create_file(self.make_path("foo", "all_tests.PY"))
         self.create_file(self.make_path("foo", "README.md"))
@@ -772,8 +1033,8 @@ class RealPathlibPathFileOperationTest(FakePathlibPathFileOperationTest):
 
 
 class FakePathlibUsageInOsFunctionsTest(RealPathlibTestCase):
-    """Test that many os / os.path functions accept a path-like object
-    since Python 3.6. The functionality of these functions is tested
+    """Test that many `os` / `os.path` functions accept a path-like object.
+    The functionality of these functions is tested
     elsewhere, we just check that they accept a fake path object as an
     argument.
     """
@@ -781,10 +1042,10 @@ class FakePathlibUsageInOsFunctionsTest(RealPathlibTestCase):
     def test_join(self):
         dir1 = "foo"
         dir2 = "bar"
-        dir = self.os.path.join(dir1, dir2)
-        self.assertEqual(dir, self.os.path.join(self.path(dir1), dir2))
-        self.assertEqual(dir, self.os.path.join(dir1, self.path(dir2)))
-        self.assertEqual(dir, self.os.path.join(self.path(dir1), self.path(dir2)))
+        dir3 = self.os.path.join(dir1, dir2)
+        self.assertEqual(dir3, self.os.path.join(self.path(dir1), dir2))
+        self.assertEqual(dir3, self.os.path.join(dir1, self.path(dir2)))
+        self.assertEqual(dir3, self.os.path.join(self.path(dir1), self.path(dir2)))
 
     def test_normcase(self):
         dir1 = self.make_path("Foo", "Bar", "Baz")
@@ -1123,6 +1384,18 @@ class FakePathlibUsageInOsFunctionsTest(RealPathlibTestCase):
         with self.assertRaises(NotImplementedError):
             self.path(path).group()
 
+    def test_walk(self):
+        """Regression test for #915 - walk results shall be strings."""
+        base_dir = self.make_path("foo")
+        base_path = self.path(base_dir)
+        self.create_dir(base_path)
+        self.create_file(base_path / "1.txt")
+        self.create_file(base_path / "bar" / "2.txt")
+        result = list(step for step in self.os.walk(base_path))
+        assert len(result) == 2
+        assert result[0] == (base_dir, ["bar"], ["1.txt"])
+        assert result[1] == (self.os.path.join(base_dir, "bar"), [], ["2.txt"])
+
 
 class RealPathlibUsageInOsFunctionsTest(FakePathlibUsageInOsFunctionsTest):
     def use_real_fs(self):
@@ -1131,7 +1404,7 @@ class RealPathlibUsageInOsFunctionsTest(FakePathlibUsageInOsFunctionsTest):
 
 class FakeFilesystemPathLikeObjectTest(unittest.TestCase):
     def setUp(self):
-        self.filesystem = fake_filesystem.FakeFilesystem(path_separator="/")
+        self.filesystem = fake_filesystem.FakeFilesystem()
         self.pathlib = fake_pathlib.FakePathlibModule(self.filesystem)
         self.os = fake_os.FakeOsModule(self.filesystem)
 
@@ -1194,6 +1467,8 @@ class FakeFilesystemChmodTest(fake_filesystem_unittest.TestCase):
     @unittest.skipIf(sys.platform != "win32", "Windows specific test")
     def test_is_file_for_unreadable_dir_windows(self):
         self.fs.os = OSType.WINDOWS
+        if is_root():
+            self.skipTest("Test only valid for non-root user")
         path = pathlib.Path("/foo/bar")
         self.fs.create_file(path)
         # normal chmod does not really set the mode to 0
@@ -1205,5 +1480,171 @@ class FakeFilesystemChmodTest(fake_filesystem_unittest.TestCase):
             path.is_file()
 
 
+class FakePathlibModulePurePathTest(fake_filesystem_unittest.TestCase):
+    def test_windows_pure_path_parsing_backslash(self):
+        path = r"C:\Windows\cmd.exe"
+        pure_result = pathlib.PureWindowsPath(path).stem
+        self.assertEqual("cmd", pure_result)
+
+        self.setUpPyfakefs()
+        self.assertEqual(
+            pure_result, fake_pathlib.FakePathlibModule.PureWindowsPath(path).stem
+        )
+        self.assertEqual(pure_result, pathlib.PureWindowsPath(path).stem)
+
+    def test_windows_pure_path_parsing_forward_slash(self):
+        path = r"C:/Windows/cmd.exe"
+        pure_result = pathlib.PureWindowsPath(path).stem
+        self.assertEqual("cmd", pure_result)
+
+        self.setUpPyfakefs()
+        self.assertEqual(
+            pure_result, fake_pathlib.FakePathlibModule.PureWindowsPath(path).stem
+        )
+        self.assertEqual(pure_result, pathlib.PureWindowsPath(path).stem)
+
+    def test_posix_pure_path_parsing(self):
+        path = r"/bin/bash"
+        pure_result = pathlib.PurePosixPath(path).stem
+        self.assertEqual("bash", pure_result)
+
+        self.setUpPyfakefs()
+        self.assertEqual(
+            pure_result, fake_pathlib.FakePathlibModule.PurePosixPath(path).stem
+        )
+        self.assertEqual(pathlib.PurePosixPath(path).stem, pure_result)
+
+    def test_windows_pure_path_str_backslash(self):
+        path = r"C:\Windows\cmd.exe"
+        pure_result = str(pathlib.PureWindowsPath(path))
+        self.assertEqual(r"C:\Windows\cmd.exe", pure_result)
+
+        self.setUpPyfakefs()
+        self.assertEqual(
+            pure_result, str(fake_pathlib.FakePathlibModule.PureWindowsPath(path))
+        )
+        self.assertEqual(str(pathlib.PureWindowsPath(path)), pure_result)
+
+    def test_windows_pure_path_str_forward_slash(self):
+        path = "C:/Windows/cmd.exe"
+        pure_result_win = str(pathlib.PureWindowsPath(path))
+        self.assertEqual(r"C:\Windows\cmd.exe", pure_result_win)
+        pure_result_posix_stem = str(pathlib.PurePosixPath(path).stem)
+        self.assertEqual("cmd", pure_result_posix_stem)
+
+        self.setUpPyfakefs()
+        self.assertEqual(
+            pure_result_win, str(fake_pathlib.FakePathlibModule.PureWindowsPath(path))
+        )
+        self.assertEqual(pure_result_win, str(pathlib.PureWindowsPath(path)))
+        self.assertEqual(pure_result_posix_stem, pathlib.PurePosixPath(path).stem)
+
+    def test_posix_pure_path_str_backslash(self):
+        path = r"\bin\bash"
+        pure_result = str(pathlib.PurePosixPath(path))
+        self.assertEqual(r"\bin\bash", pure_result)
+
+        self.setUpPyfakefs()
+        self.assertEqual(
+            pure_result, str(fake_pathlib.FakePathlibModule.PurePosixPath(path))
+        )
+        self.assertEqual(pure_result, str(pathlib.PurePosixPath(path)))
+
+    def test_posix_pure_path_str_forward_slash(self):
+        path = "/bin/bash"
+        pure_result = str(pathlib.PurePosixPath(path))
+        self.assertEqual(r"/bin/bash", pure_result)
+
+        self.setUpPyfakefs()
+        self.assertEqual(
+            pure_result, str(fake_pathlib.FakePathlibModule.PurePosixPath(path))
+        )
+        self.assertEqual(pure_result, str(pathlib.PurePosixPath(path)))
+
+    def check_posix_pure_path_is_absolute(self, path, expected_result):
+        pure_result = pathlib.PurePosixPath(path).is_absolute()
+        self.assertEqual(expected_result, pure_result)
+
+        self.setUpPyfakefs()
+        self.assertEqual(
+            pure_result,
+            fake_pathlib.FakePathlibModule.PurePosixPath(path).is_absolute(),
+        )
+        self.assertEqual(pure_result, pathlib.PurePosixPath(path).is_absolute())
+
+    def test_posix_pure_path_is_absolute_for_absolute_path(self):
+        self.check_posix_pure_path_is_absolute("/bin/bash", expected_result=True)
+
+    def test_posix_pure_path_is_absolute_for_local_path(self):
+        self.check_posix_pure_path_is_absolute("bin/bash", expected_result=False)
+
+    def test_posix_pure_path_is_absolute_for_relative_path(self):
+        self.check_posix_pure_path_is_absolute("../bin/bash", expected_result=False)
+
+    def check_windows_pure_path_is_absolute(self, path, expected_result):
+        pure_result = pathlib.PureWindowsPath(path).is_absolute()
+        self.assertEqual(expected_result, pure_result)
+
+        self.setUpPyfakefs()
+        self.assertEqual(
+            pure_result,
+            fake_pathlib.FakePathlibModule.PureWindowsPath(path).is_absolute(),
+        )
+        self.assertEqual(pure_result, pathlib.PureWindowsPath(path).is_absolute())
+
+    def test_windows_pure_path_is_absolute_for_absolute_path(self):
+        self.check_windows_pure_path_is_absolute("C:/Windows/cmd.exe", True)
+
+    def test_windows_pure_path_is_absolute_for_local_path(self):
+        self.check_windows_pure_path_is_absolute("./cmd.exe", expected_result=False)
+
+    def test_windows_pure_path_is_absolute_for_relative_path(self):
+        self.check_windows_pure_path_is_absolute("../cmd.exe", expected_result=False)
+
+
+class FakePathlibModulePurePathTestWindows(FakePathlibModulePurePathTest):
+    def setUpPyfakefs(self, **kwargs):
+        super().setUpPyfakefs(**kwargs)
+        self.fs.os = OSType.WINDOWS
+
+
+class FakePathlibModulePurePathTestMacos(FakePathlibModulePurePathTest):
+    def setUpPyfakefs(self, **kwargs):
+        super().setUpPyfakefs(**kwargs)
+        self.fs.os = OSType.MACOS
+
+
+class FakePathlibModulePurePathTestLinux(FakePathlibModulePurePathTest):
+    def setUpPyfakefs(self, **kwargs):
+        super().setUpPyfakefs(**kwargs)
+        self.fs.os = OSType.LINUX
+
+
+class SkipPathlibTest(fake_filesystem_unittest.TestCase):
+    def setUp(self):
+        self.setUpPyfakefs(additional_skip_names=["skipped_pathlib"])
+
+    def test_open_in_skipped_module(self):
+        # regression test for #1012
+        contents = read_pathlib("skipped_pathlib.py")
+        self.assertTrue(contents.startswith("# Licensed under the Apache License"))
+
+    def test_read_text_in_skipped_module(self):
+        # regression test for #1012
+        contents = read_text_pathlib("skipped_pathlib.py")
+        self.assertTrue(contents.startswith("# Licensed under the Apache License"))
+
+    def test_read_bytes_in_skipped_module(self):
+        # regression test for #1012
+        contents = read_bytes_pathlib("skipped_pathlib.py")
+        self.assertTrue(contents.startswith(b"# Licensed under the Apache License"))
+
+    @unittest.skipIf(
+        IS_PYPY and sys.version_info < (3, 8), "Ignoring error in outdated version"
+    )
+    def test_exists(self):
+        self.assertTrue(check_exists_pathlib())
+
+
 if __name__ == "__main__":
     unittest.main(verbosity=2)
diff --git a/pyfakefs/tests/fake_stat_time_test.py b/pyfakefs/tests/fake_stat_time_test.py
index 5833ebd..2602d1a 100644
--- a/pyfakefs/tests/fake_stat_time_test.py
+++ b/pyfakefs/tests/fake_stat_time_test.py
@@ -11,6 +11,7 @@
 # limitations under the License.
 
 """Unit tests for file timestamp updates."""
+
 import time
 import unittest
 from collections import namedtuple
@@ -60,14 +61,14 @@ class FakeStatTestBase(RealFsTestCase):
 
     def open_close_new_file(self):
         with self.mock_time():
-            with self.open(self.file_path, self.mode):
+            with self.open(self.file_path, self.mode, encoding="utf8"):
                 created = self.stat_time(self.file_path)
             closed = self.stat_time(self.file_path)
             return created, closed
 
     def open_write_close_new_file(self):
         with self.mock_time():
-            with self.open(self.file_path, self.mode) as f:
+            with self.open(self.file_path, self.mode, encoding="utf8") as f:
                 created = self.stat_time(self.file_path)
                 f.write("foo")
                 written = self.stat_time(self.file_path)
@@ -80,7 +81,7 @@ class FakeStatTestBase(RealFsTestCase):
             self.create_file(self.file_path)
 
             before = self.stat_time(self.file_path)
-            with self.open(self.file_path, self.mode):
+            with self.open(self.file_path, self.mode, encoding="utf8"):
                 opened = self.stat_time(self.file_path)
             closed = self.stat_time(self.file_path)
 
@@ -91,7 +92,7 @@ class FakeStatTestBase(RealFsTestCase):
             self.create_file(self.file_path)
 
             before = self.stat_time(self.file_path)
-            with self.open(self.file_path, self.mode) as f:
+            with self.open(self.file_path, self.mode, encoding="utf8") as f:
                 opened = self.stat_time(self.file_path)
                 f.write("foo")
                 written = self.stat_time(self.file_path)
@@ -104,7 +105,7 @@ class FakeStatTestBase(RealFsTestCase):
             self.create_file(self.file_path)
 
             before = self.stat_time(self.file_path)
-            with self.open(self.file_path, self.mode) as f:
+            with self.open(self.file_path, self.mode, encoding="utf8") as f:
                 opened = self.stat_time(self.file_path)
                 f.flush()
                 flushed = self.stat_time(self.file_path)
@@ -117,7 +118,7 @@ class FakeStatTestBase(RealFsTestCase):
             self.create_file(self.file_path)
 
             before = self.stat_time(self.file_path)
-            with self.open(self.file_path, self.mode) as f:
+            with self.open(self.file_path, self.mode, encoding="utf8") as f:
                 opened = self.stat_time(self.file_path)
                 f.write("foo")
                 written = self.stat_time(self.file_path)
@@ -132,7 +133,7 @@ class FakeStatTestBase(RealFsTestCase):
             self.create_file(self.file_path)
 
             before = self.stat_time(self.file_path)
-            with self.open(self.file_path, "r") as f:
+            with self.open(self.file_path, "r", encoding="utf8") as f:
                 opened = self.stat_time(self.file_path)
                 f.read()
                 read = self.stat_time(self.file_path)
@@ -144,7 +145,7 @@ class FakeStatTestBase(RealFsTestCase):
 
     def open_read_close_new_file(self):
         with self.mock_time():
-            with self.open(self.file_path, self.mode) as f:
+            with self.open(self.file_path, self.mode, encoding="utf8") as f:
                 created = self.stat_time(self.file_path)
                 f.read()
                 read = self.stat_time(self.file_path)
@@ -157,7 +158,7 @@ class FakeStatTestBase(RealFsTestCase):
             self.create_file(self.file_path)
 
             before = self.stat_time(self.file_path)
-            with self.open(self.file_path, self.mode) as f:
+            with self.open(self.file_path, self.mode, encoding="utf8") as f:
                 opened = self.stat_time(self.file_path)
                 f.read()
                 read = self.stat_time(self.file_path)
@@ -388,7 +389,7 @@ class FakeStatTestBase(RealFsTestCase):
 
 class TestFakeModeW(FakeStatTestBase):
     def setUp(self):
-        super(TestFakeModeW, self).setUp()
+        super().setUp()
         self.mode = "w"
 
     def test_open_close_new_file(self):
@@ -410,7 +411,7 @@ class TestFakeModeW(FakeStatTestBase):
         self.check_open_write_flush_close_w_mode()
 
     def test_read_raises(self):
-        with self.open(self.file_path, "w") as f:
+        with self.open(self.file_path, "w", encoding="utf8") as f:
             with self.assertRaises(OSError):
                 f.read()
 
@@ -422,7 +423,7 @@ class TestRealModeW(TestFakeModeW):
 
 class TestFakeModeWPlus(FakeStatTestBase):
     def setUp(self):
-        super(TestFakeModeWPlus, self).setUp()
+        super().setUp()
         self.mode = "w+"
 
     def test_open_close_new_file(self):
@@ -475,7 +476,7 @@ class TestRealModeWPlus(TestFakeModeWPlus):
 
 class TestFakeModeA(FakeStatTestBase):
     def setUp(self):
-        super(TestFakeModeA, self).setUp()
+        super().setUp()
         self.mode = "a"
 
     def test_open_close_new_file(self):
@@ -497,7 +498,7 @@ class TestFakeModeA(FakeStatTestBase):
         self.check_open_write_flush_close_non_w_mode()
 
     def test_read_raises(self):
-        with self.open(self.file_path, "a") as f:
+        with self.open(self.file_path, "a", encoding="utf8") as f:
             with self.assertRaises(OSError):
                 f.read()
 
@@ -509,7 +510,7 @@ class TestRealModeA(TestFakeModeA):
 
 class TestFakeModeAPlus(FakeStatTestBase):
     def setUp(self):
-        super(TestFakeModeAPlus, self).setUp()
+        super().setUp()
         self.mode = "a+"
 
     def test_open_close_new_file(self):
@@ -544,7 +545,7 @@ class TestRealModeAPlus(TestFakeModeAPlus):
 
 class TestFakeModeR(FakeStatTestBase):
     def setUp(self):
-        super(TestFakeModeR, self).setUp()
+        super().setUp()
         self.mode = "r"
 
     def test_open_close(self):
@@ -591,7 +592,7 @@ class TestRealModeR(TestFakeModeR):
 
 class TestFakeModeRPlus(FakeStatTestBase):
     def setUp(self):
-        super(TestFakeModeRPlus, self).setUp()
+        super().setUp()
         self.mode = "r+"
 
     def test_open_close(self):
diff --git a/pyfakefs/tests/fake_tempfile_test.py b/pyfakefs/tests/fake_tempfile_test.py
index f208b56..09d6a4f 100644
--- a/pyfakefs/tests/fake_tempfile_test.py
+++ b/pyfakefs/tests/fake_tempfile_test.py
@@ -44,7 +44,7 @@ class FakeTempfileModuleTest(fake_filesystem_unittest.TestCase):
         file_obj = self.fs.get_object(obj.name)
         contents = file_obj.contents
         self.assertEqual("foo", contents)
-        obj = tempfile.NamedTemporaryFile(mode="w", delete=False)
+        obj = tempfile.NamedTemporaryFile(mode="w", encoding="utf8", delete=False)
         obj.write("foo")
         obj.close()
         file_obj = self.fs.get_object(obj.name)
diff --git a/pyfakefs/tests/fixtures/deprecated_property.py b/pyfakefs/tests/fixtures/deprecated_property.py
index 9bdb590..c99fab5 100644
--- a/pyfakefs/tests/fixtures/deprecated_property.py
+++ b/pyfakefs/tests/fixtures/deprecated_property.py
@@ -14,6 +14,7 @@
 over modules. The code is modeled after code in xmlbuilder.py in Python 3.6.
 See issue #542.
 """
+
 import warnings
 
 
diff --git a/pyfakefs/tests/import_as_example.py b/pyfakefs/tests/import_as_example.py
index 74f9505..835a2c4 100644
--- a/pyfakefs/tests/import_as_example.py
+++ b/pyfakefs/tests/import_as_example.py
@@ -14,6 +14,7 @@
 Example module that is used for testing modules that import file system modules
 to be patched under another name.
 """
+
 import os as my_os
 import pathlib
 import sys
@@ -95,12 +96,12 @@ def system_stat(filepath):
 
 
 def file_contents1(filepath):
-    with bltn_open(filepath) as f:
+    with bltn_open(filepath, encoding="utf8") as f:
         return f.read()
 
 
 def file_contents2(filepath):
-    with io_open(filepath) as f:
+    with io_open(filepath, encoding="utf8") as f:
         return f.read()
 
 
@@ -111,7 +112,7 @@ def exists_this_file():
 
 def open_this_file():
     """Works only in real fs"""
-    with open(__file__):
+    with open(__file__, encoding="utf8"):
         pass
 
 
diff --git a/pyfakefs/tests/mox3_stubout_example.py b/pyfakefs/tests/mox3_stubout_example.py
index 44dfee9..15aac94 100644
--- a/pyfakefs/tests/mox3_stubout_example.py
+++ b/pyfakefs/tests/mox3_stubout_example.py
@@ -14,6 +14,7 @@
 Example module that is used for testing the functionality of
 :py:class`pyfakefs.mox_stubout.StubOutForTesting`.
 """
+
 import datetime
 import math
 import os
diff --git a/pyfakefs/tests/mox3_stubout_test.py b/pyfakefs/tests/mox3_stubout_test.py
index 3382001..2f9ba81 100644
--- a/pyfakefs/tests/mox3_stubout_test.py
+++ b/pyfakefs/tests/mox3_stubout_test.py
@@ -54,7 +54,7 @@ class GroundhogDate(datetime.date):
 
 class StubOutForTestingTest(unittest.TestCase):
     def setUp(self):
-        super(StubOutForTestingTest, self).setUp()
+        super().setUp()
         self.stubber = mox3_stubout.StubOutForTesting()
 
     def test_stubout_method_with_set(self):
diff --git a/pyfakefs/tests/patched_packages_test.py b/pyfakefs/tests/patched_packages_test.py
index 1c76091..16bbc92 100644
--- a/pyfakefs/tests/patched_packages_test.py
+++ b/pyfakefs/tests/patched_packages_test.py
@@ -14,6 +14,7 @@
 Provides patches for some commonly used modules that enable them to work
 with pyfakefs.
 """
+
 import os
 import sys
 import unittest
diff --git a/pyfakefs/tests/performance_test.py b/pyfakefs/tests/performance_test.py
index 5e44f22..56ad78b 100644
--- a/pyfakefs/tests/performance_test.py
+++ b/pyfakefs/tests/performance_test.py
@@ -10,6 +10,7 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 """Shall provide tests to check performance overhead of pyfakefs."""
+
 import os
 import time
 import unittest
@@ -60,10 +61,10 @@ if os.environ.get("TEST_PERFORMANCE"):
         """
 
         def test_cached_time(self):
-            self.assertLess(SetupPerformanceTest.elapsed_time, 0.4)
+            self.assertLess(SetupPerformanceTest.elapsed_time, 0.18)
 
         def test_uncached_time(self):
-            self.assertLess(SetupNoCachePerformanceTest.elapsed_time, 6)
+            self.assertLess(SetupNoCachePerformanceTest.elapsed_time, 4)
 
     def test_setup(self):
         pass
diff --git a/pyfakefs/tests/skipped_pathlib.py b/pyfakefs/tests/skipped_pathlib.py
new file mode 100644
index 0000000..5659a71
--- /dev/null
+++ b/pyfakefs/tests/skipped_pathlib.py
@@ -0,0 +1,38 @@
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
+"""
+Provides functions for testing additional_skip_names functionality.
+"""
+
+import os
+from pathlib import Path
+
+
+def read_pathlib(file_name):
+    return (Path(__file__).parent / file_name).open("r").read()
+
+
+def read_text_pathlib(file_name):
+    return (Path(__file__).parent / file_name).read_text()
+
+
+def read_bytes_pathlib(file_name):
+    return (Path(__file__).parent / file_name).read_bytes()
+
+
+def check_exists_pathlib():
+    return os.path.exists(__file__) and Path(__file__).exists()
+
+
+def read_open(file_name):
+    with open(os.path.join(os.path.dirname(__file__), file_name)) as f:
+        return f.read()
diff --git a/pyfakefs/tests/test_utils.py b/pyfakefs/tests/test_utils.py
index 9555efb..a5b35c6 100644
--- a/pyfakefs/tests/test_utils.py
+++ b/pyfakefs/tests/test_utils.py
@@ -15,6 +15,7 @@
 # Disable attribute errors - attributes not be found in mixin (shall be cleaned up...)
 # pytype: disable=attribute-error
 """Common helper classes used in tests, or as test class base."""
+
 import os
 import platform
 import shutil
@@ -26,7 +27,7 @@ from contextlib import contextmanager
 from unittest import mock
 
 from pyfakefs import fake_filesystem, fake_open, fake_os
-from pyfakefs.helpers import is_byte_string, to_string
+from pyfakefs.helpers import is_byte_string, to_string, is_root
 
 
 class DummyTime:
@@ -227,6 +228,12 @@ class RealFsTestMixin:
         else:
             self.set_windows_fs(False)
 
+    @staticmethod
+    def skip_root():
+        """Skips the test if run as root."""
+        if is_root():
+            raise unittest.SkipTest("Test only valid for non-root user")
+
     def skip_real_fs(self):
         """If called at test start, no real FS test is executed."""
         if self.use_real_fs():
@@ -262,32 +269,18 @@ class RealFsTestMixin:
                     "Skipping because FakeFS does not match real FS"
                 )
 
-    def symlink_can_be_tested(self, force_real_fs=False):
+    def symlink_can_be_tested(self):
         """Used to check if symlinks and hard links can be tested under
         Windows. All tests are skipped under Windows for Python versions
         not supporting links, and real tests are skipped if running without
         administrator rights.
         """
-        if not TestCase.is_windows or (not force_real_fs and not self.use_real_fs()):
-            return True
-        if TestCase.symlinks_can_be_tested is None:
-            if force_real_fs:
-                self.base_path = tempfile.mkdtemp()
-            link_path = self.make_path("link")
-            try:
-                self.os.symlink(self.base_path, link_path)
-                TestCase.symlinks_can_be_tested = True
-                self.os.remove(link_path)
-            except (OSError, NotImplementedError):
-                TestCase.symlinks_can_be_tested = False
-            if force_real_fs:
-                self.base_path = None
-        return TestCase.symlinks_can_be_tested
-
-    def skip_if_symlink_not_supported(self, force_real_fs=False):
+        return not TestCase.is_windows or is_root()
+
+    def skip_if_symlink_not_supported(self):
         """If called at test start, tests are skipped if symlinks are not
         supported."""
-        if not self.symlink_can_be_tested(force_real_fs):
+        if not self.symlink_can_be_tested():
             raise unittest.SkipTest("Symlinks under Windows need admin privileges")
 
     def make_path(self, *args):
@@ -305,7 +298,7 @@ class RealFsTestMixin:
         args = [to_string(arg) for arg in args]
         return self.os.path.join(self.base_path, *args)
 
-    def create_dir(self, dir_path, perm=0o777):
+    def create_dir(self, dir_path, perm=0o777, apply_umask=True):
         """Create the directory at `dir_path`, including subdirectories.
         `dir_path` shall be composed using `make_path()`.
         """
@@ -325,21 +318,34 @@ class RealFsTestMixin:
             existing_path = self.os.path.join(existing_path, component)
             self.os.mkdir(existing_path)
             self.os.chmod(existing_path, 0o777)
+        if apply_umask:
+            umask = self.os.umask(0o022)
+            perm &= ~umask
+            self.os.umask(umask)
         self.os.chmod(dir_path, perm)
 
-    def create_file(self, file_path, contents=None, encoding=None, perm=0o666):
+    def create_file(
+        self, file_path, contents=None, encoding=None, perm=0o666, apply_umask=True
+    ):
         """Create the given file at `file_path` with optional contents,
         including subdirectories. `file_path` shall be composed using
         `make_path()`.
         """
         self.create_dir(self.os.path.dirname(file_path))
         mode = "wb" if encoding is not None or is_byte_string(contents) else "w"
+        kwargs = {"mode": mode}
 
         if encoding is not None and contents is not None:
             contents = contents.encode(encoding)
-        with self.open(file_path, mode) as f:
+        if mode == "w":
+            kwargs["encoding"] = "utf8"
+        with self.open(file_path, **kwargs) as f:
             if contents is not None:
                 f.write(contents)
+        if apply_umask:
+            umask = self.os.umask(0o022)
+            perm &= ~umask
+            self.os.umask(umask)
         self.os.chmod(file_path, perm)
 
     def create_symlink(self, link_path, target_path):
@@ -354,7 +360,10 @@ class RealFsTestMixin:
         Asserts equality.
         """
         mode = "rb" if is_byte_string(contents) else "r"
-        with self.open(file_path, mode) as f:
+        kwargs = {"mode": mode}
+        if mode == "r":
+            kwargs["encoding"] = "utf8"
+        with self.open(file_path, **kwargs) as f:
             self.assertEqual(contents, f.read())
 
     def create_basepath(self):
diff --git a/requirements.txt b/requirements.txt
index b949482..c63164e 100644
--- a/requirements.txt
+++ b/requirements.txt
@@ -1 +1 @@
-pytest>=3.0.0
+pytest>=6.2.5
diff --git a/requirements_dev.txt b/requirements_dev.txt
index eb37ab8..e88d271 100644
--- a/requirements_dev.txt
+++ b/requirements_dev.txt
@@ -1 +1 @@
-pre-commit==3.3.3
+pre-commit==4.0.1
diff --git a/setup.cfg b/setup.cfg
index a45a048..e010b7f 100644
--- a/setup.cfg
+++ b/setup.cfg
@@ -28,10 +28,13 @@ classifiers =
     Intended Audience :: Developers
     License :: OSI Approved :: Apache Software License
     Programming Language :: Python :: 3
+    Programming Language :: Python :: 3.7
     Programming Language :: Python :: 3.8
     Programming Language :: Python :: 3.9
     Programming Language :: Python :: 3.10
     Programming Language :: Python :: 3.11
+    Programming Language :: Python :: 3.12
+    Programming Language :: Python :: 3.13
     Programming Language :: Python :: Implementation :: CPython
     Programming Language :: Python :: Implementation :: PyPy
     Operating System :: POSIX
@@ -49,7 +52,7 @@ universal = 0
 [options]
 packages = find:
 install_requires =
-python_requires = >=3.8
+python_requires = >=3.7
 test_suite = pyfakefs.tests
 include_package_data = True
 
diff --git a/tox.ini b/tox.ini
index ccc165e..b80f53c 100644
--- a/tox.ini
+++ b/tox.ini
@@ -1,5 +1,7 @@
 [tox]
-envlist = py37,py38,py39,py310,py311,pypy3
+envlist =
+    py{37,38,39,310,311,312,313}
+    pypy{37,39,310}
 
 [testenv]
 deps =
```

