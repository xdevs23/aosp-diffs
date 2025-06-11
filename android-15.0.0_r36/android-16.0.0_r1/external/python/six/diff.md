```diff
diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
new file mode 100644
index 0000000..3d5990a
--- /dev/null
+++ b/.github/workflows/ci.yml
@@ -0,0 +1,82 @@
+name: CI
+
+on:
+  push:
+    branches:
+      - main
+  pull_request:
+    branches:
+      - main
+
+jobs:
+  test:
+    strategy:
+      matrix:
+        python-version: [
+          "2.7",
+          "3.5",
+          "3.6",
+          "3.7",
+          "3.8",
+          "3.9",
+          "3.10",
+          "3.11",
+          "3.12",
+          "3.13",
+          "pypy-2.7",
+          "pypy-3.8",
+        ]
+        os: [ubuntu-latest, windows-latest, macos-latest]
+        exclude:
+          - python-version: "2.7"
+            os: "ubuntu-latest"
+          - python-version: "2.7"
+            os: "windows-latest"
+          - python-version: "2.7"
+            os: "macos-latest"
+          - python-version: "3.5"
+            os: "macos-latest"
+          - python-version: "3.6"
+            os: "macos-latest"
+          - python-version: "3.7"
+            os: "macos-latest"
+          - python-version: "3.5"
+            os: "ubuntu-latest"
+          - python-version: "3.6"
+            os: "ubuntu-latest"
+        include:
+          - python-version: "3.5"
+            os: "macos-12"
+          - python-version: "3.6"
+            os: "macos-12"
+          - python-version: "3.7"
+            os: "macos-12"
+          - python-version: "2.7"
+            os: "ubuntu-20.04"
+          - python-version: "3.5"
+            os: "ubuntu-20.04"
+          - python-version: "3.6"
+            os: "ubuntu-20.04"
+    runs-on: ${{ matrix.os }}
+    env:
+      TOXENV: py
+    steps:
+      - uses: actions/checkout@v3
+      - if: ${{ matrix.python-version == '2.7' }}
+        run: |
+          sudo apt-get install python-is-python2
+          curl -sSL https://bootstrap.pypa.io/pip/2.7/get-pip.py -o get-pip.py
+          python get-pip.py
+        name: Set up Python ${{ matrix.python-version }} on ${{ matrix.os }}
+      - if: ${{ matrix.python-version != '2.7' }}
+        name: Set up Python ${{ matrix.python-version }} on ${{ matrix.os }}
+        uses: actions/setup-python@v5
+        with:
+          python-version: ${{ matrix.python-version }}
+          allow-prereleases: true
+        env:
+          PIP_TRUSTED_HOST: ${{ contains(fromJson('["3.5"]'), matrix.python-version) && 'pypi.python.org pypi.org files.pythonhosted.org' || '' }}
+      - name: Install dependencies
+        run: python -m pip install -U tox
+      - name: Run tox
+        run: python -m tox
diff --git a/.github/workflows/publish.yml b/.github/workflows/publish.yml
new file mode 100644
index 0000000..10ab03f
--- /dev/null
+++ b/.github/workflows/publish.yml
@@ -0,0 +1,39 @@
+name: Upload package
+
+on:
+  push:
+    tags:
+      - '*'
+  workflow_dispatch:
+
+jobs:
+  deploy:
+    runs-on: ubuntu-latest
+    steps:
+    - uses: actions/checkout@v3
+    - name: Set up Python
+      uses: actions/setup-python@v5
+      with:
+        python-version: '3.13'
+    - name: Install dependencies
+      run: |
+        python -m pip install --upgrade pip
+        pip install -U build twine
+    - name: Build package
+      run: |
+        python -m build
+    - name: Publish package
+      env:
+        TWINE_USERNAME: "__token__"
+      run: |
+        if [[ "$GITHUB_EVENT_NAME" == "workflow_dispatch" ]]; then
+          export TWINE_REPOSITORY="testpypi"
+          export TWINE_PASSWORD="${{ secrets.TEST_PYPI_UPLOAD_TOKEN }}"
+        elif [[ "$GITHUB_EVENT_NAME" == "push" ]]; then
+          export TWINE_REPOSITORY="pypi"
+          export TWINE_PASSWORD="${{ secrets.PYPI_UPLOAD_TOKEN }}"
+        else
+          echo "Unknown event name: ${GITHUB_EVENT_NAME}"
+          exit 1
+        fi
+        python -m twine upload dist/*
diff --git a/.travis.yml b/.travis.yml
deleted file mode 100644
index 24a969a..0000000
--- a/.travis.yml
+++ /dev/null
@@ -1,50 +0,0 @@
-os: linux
-dist: xenial
-language: python
-python:
-- 2.7
-- 3.4
-- 3.5
-- 3.6
-- 3.7
-- &mainstream_python 3.8
-- nightly
-- pypy
-- pypy3
-install:
-- pip install --upgrade --force-reinstall "setuptools; python_version != '3.3'" "setuptools < 40; python_version == '3.3'"
-- pip uninstall --yes six || true
-- pip install --upgrade --force-reinstall --ignore-installed -e .
-- pip install "pytest==4.6.9; python_version != '3.3'" "pytest==2.9.2; python_version == '3.3'" "typing; python_version < '3'"
-- &py_pkg_list pip list --format=columns || pip list
-script:
-- py.test
-- echo Checking whether installation flow is not broken...
-- pip uninstall --yes six || true
-- pip install --ignore-installed .
-- *py_pkg_list
-jobs:
-  fast_finish: true
-  include:
-  - python: 3.3
-    dist: trusty
-  - stage: upload new version of python package to PYPI (only for tagged commits)
-    python: *mainstream_python
-    install: skip
-    script: skip
-    deploy:
-      provider: pypi
-      on:
-        tags: true
-        all_branches: true
-        python: *mainstream_python
-      user: __token__
-      distributions: "sdist bdist_wheel"
-      password:
-        secure: "F83KFmQnpBcR/BD7tBjJcmchvvoxYjIB0EDmDKEM+Rq1SJUH0qtYZlMJ0H4S8sTeY4+h26Ssfg5+oe9SqS5AkEMLFVM2lDcFtIXNR9bIvsXjkKsdxIWZJJ+Vl7EmW+ND/oj9IWnHOvaPr6F1YQqOuP2LfrDsoZ+4wo4X+UCC8xCGCaAIliPIt6y7U3ENeCQJTwUc93eDMZrEROmWAwsxF54a13CIkbTWe+S3iEp949MaNBWx2f9XNi7Gidk2gKUKordK0MXiO7+DcrQdiCAtPryqqNKR/JjZ66P9eK1A2VWyk65/5E8+OJeexuSlHGg52HKoXU2BPIkzgcaSjt79WQKVKJzYi2iD0Bd/9/RKrnq8+GVd0yT5IJV5OhwcpT0ScPs/9pAZ1mSEufx1FtXN61ujs2VEuleSQAWBiNGXsRQNCzVxgfatkUTNMjB0jxUzNay5CFrMlo5AVWBcdByhUto3szV/lxLj7arM48GHXaf+5MXhaELU8L2pTpJoQ8Rdj+Tx5HbhJ+wWF6EyT919prB2/6fM4d/MHIuHfJkCasYZSvhamGnTBzxxH9Fv7l18FyrBXF+Rz65mXVkUlxFMICSMWRJWEb4I2KWK1bsxCFy+o38TMeije+1nbvKVRKbLMn6mbXfBb/wfLTNogHFXrlR5VcugcP079dqR9O3iV4M="
-
-cache:
-  pip: true
-after_failure:
-- echo "Here's a list of installed Python packages:"
-- *py_pkg_list
diff --git a/CHANGES b/CHANGES
index f3bf6a4..48e0a85 100644
--- a/CHANGES
+++ b/CHANGES
@@ -3,6 +3,15 @@ Changelog for six
 
 This file lists the changes in each six version.
 
+1.17.0
+------
+
+- Pull request #388: Remove `URLopener` and `FancyURLopener` classes from
+  `urllib.request` when running on Python 3.14 or greater.
+
+- Pull request #365, issue #283: `six.moves.UserDict` now points to
+  `UserDict.IterableUserDict` instead of `UserDict.UserDict` on Python 2.
+
 1.16.0
 ------
 
diff --git a/CONTRIBUTORS b/CONTRIBUTORS
index a76dffd..be72290 100644
--- a/CONTRIBUTORS
+++ b/CONTRIBUTORS
@@ -35,6 +35,7 @@ Mirko Rossini
 Peter Ruibal
 Miroslav Shubernetskiy
 Eli Schwartz
+Bart Skowron
 Anthony Sottile
 Victor Stinner
 Jonathan Vanasco
diff --git a/LICENSE b/LICENSE
index de66331..1cc22a5 100644
--- a/LICENSE
+++ b/LICENSE
@@ -1,4 +1,4 @@
-Copyright (c) 2010-2020 Benjamin Peterson
+Copyright (c) 2010-2024 Benjamin Peterson
 
 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
diff --git a/METADATA b/METADATA
index 2473a70..7daf6b0 100644
--- a/METADATA
+++ b/METADATA
@@ -1,20 +1,20 @@
 # This project was upgraded with external_updater.
 # Usage: tools/external_updater/updater.sh update external/python/six
-# For more info, check https://cs.android.com/android/platform/superproject/+/main:tools/external_updater/README.md
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
 name: "six"
 description: "Python PyPI six package"
 third_party {
   license_type: NOTICE
   last_upgrade_date {
-    year: 2024
-    month: 7
-    day: 9
+    year: 2025
+    month: 1
+    day: 21
   }
   homepage: "https://pypi.python.org/pypi/six"
   identifier {
     type: "Git"
     value: "https://github.com/benjaminp/six"
-    version: "1.16.0"
+    version: "1.17.0"
   }
 }
diff --git a/OWNERS b/OWNERS
index 9a6f87a..0da7b78 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,2 +1,3 @@
 colefaust@google.com
 krzysio@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/README.rst b/README.rst
index 6339ba5..3674bc9 100644
--- a/README.rst
+++ b/README.rst
@@ -2,10 +2,6 @@
    :target: https://pypi.org/project/six/
    :alt: six on PyPI
 
-.. image:: https://travis-ci.org/benjaminp/six.svg?branch=master
-   :target: https://travis-ci.org/benjaminp/six
-   :alt: six on TravisCI
-
 .. image:: https://readthedocs.org/projects/six/badge/?version=latest
    :target: https://six.readthedocs.io/
    :alt: six's documentation on Read the Docs
diff --git a/documentation/conf.py b/documentation/conf.py
index 2f0f323..b6e3b12 100644
--- a/documentation/conf.py
+++ b/documentation/conf.py
@@ -33,7 +33,7 @@ master_doc = "index"
 
 # General information about the project.
 project = u"six"
-copyright = u"2010-2020, Benjamin Peterson"
+copyright = u"2010-2024, Benjamin Peterson"
 
 sys.path.append(os.path.abspath(os.path.join(".", "..")))
 from six import __version__ as six_version
diff --git a/documentation/index.rst b/documentation/index.rst
index 45390b8..643ced9 100644
--- a/documentation/index.rst
+++ b/documentation/index.rst
@@ -577,148 +577,148 @@ functionality; its structure mimics the structure of the Python 3
 
 Supported renames:
 
-+------------------------------+-------------------------------------+---------------------------------------+
-| Name                         | Python 2 name                       | Python 3 name                         |
-+==============================+=====================================+=======================================+
-| ``builtins``                 | :mod:`py2:__builtin__`              | :mod:`py3:builtins`                   |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``configparser``             | :mod:`py2:ConfigParser`             | :mod:`py3:configparser`               |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``copyreg``                  | :mod:`py2:copy_reg`                 | :mod:`py3:copyreg`                    |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``cPickle``                  | :mod:`py2:cPickle`                  | :mod:`py3:pickle`                     |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``cStringIO``                | :func:`py2:cStringIO.StringIO`      | :class:`py3:io.StringIO`              |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``collections_abc``          | :mod:`py2:collections`              | :mod:`py3:collections.abc` (3.3+)     |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``dbm_gnu``                  | :mod:`py2:gdbm`                     | :mod:`py3:dbm.gnu`                    |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``dbm_ndbm``                 | :mod:`py2:dbm`                      | :mod:`py3:dbm.ndbm`                   |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``_dummy_thread``            | :mod:`py2:dummy_thread`             | :mod:`py3:_dummy_thread` (< 3.9)      |
-|                              |                                     | :mod:`py3:_thread` (3.9+)             |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``email_mime_base``          | :mod:`py2:email.MIMEBase`           | :mod:`py3:email.mime.base`            |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``email_mime_image``         | :mod:`py2:email.MIMEImage`          | :mod:`py3:email.mime.image`           |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``email_mime_multipart``     | :mod:`py2:email.MIMEMultipart`      | :mod:`py3:email.mime.multipart`       |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``email_mime_nonmultipart``  | :mod:`py2:email.MIMENonMultipart`   | :mod:`py3:email.mime.nonmultipart`    |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``email_mime_text``          | :mod:`py2:email.MIMEText`           | :mod:`py3:email.mime.text`            |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``filter``                   | :func:`py2:itertools.ifilter`       | :func:`py3:filter`                    |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``filterfalse``              | :func:`py2:itertools.ifilterfalse`  | :func:`py3:itertools.filterfalse`     |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``getcwd``                   | :func:`py2:os.getcwdu`              | :func:`py3:os.getcwd`                 |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``getcwdb``                  | :func:`py2:os.getcwd`               | :func:`py3:os.getcwdb`                |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``getoutput``                | :func:`py2:commands.getoutput`      | :func:`py3:subprocess.getoutput`      |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``http_cookiejar``           | :mod:`py2:cookielib`                | :mod:`py3:http.cookiejar`             |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``http_cookies``             | :mod:`py2:Cookie`                   | :mod:`py3:http.cookies`               |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``html_entities``            | :mod:`py2:htmlentitydefs`           | :mod:`py3:html.entities`              |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``html_parser``              | :mod:`py2:HTMLParser`               | :mod:`py3:html.parser`                |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``http_client``              | :mod:`py2:httplib`                  | :mod:`py3:http.client`                |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``BaseHTTPServer``           | :mod:`py2:BaseHTTPServer`           | :mod:`py3:http.server`                |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``CGIHTTPServer``            | :mod:`py2:CGIHTTPServer`            | :mod:`py3:http.server`                |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``SimpleHTTPServer``         | :mod:`py2:SimpleHTTPServer`         | :mod:`py3:http.server`                |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``input``                    | :func:`py2:raw_input`               | :func:`py3:input`                     |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``intern``                   | :func:`py2:intern`                  | :func:`py3:sys.intern`                |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``map``                      | :func:`py2:itertools.imap`          | :func:`py3:map`                       |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``queue``                    | :mod:`py2:Queue`                    | :mod:`py3:queue`                      |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``range``                    | :func:`py2:xrange`                  | :func:`py3:range`                     |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``reduce``                   | :func:`py2:reduce`                  | :func:`py3:functools.reduce`          |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``reload_module``            | :func:`py2:reload`                  | :func:`py3:imp.reload`,               |
-|                              |                                     | :func:`py3:importlib.reload`          |
-|                              |                                     | on Python 3.4+                        |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``reprlib``                  | :mod:`py2:repr`                     | :mod:`py3:reprlib`                    |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``shlex_quote``              | :mod:`py2:pipes.quote`              | :mod:`py3:shlex.quote`                |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``socketserver``             | :mod:`py2:SocketServer`             | :mod:`py3:socketserver`               |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``_thread``                  | :mod:`py2:thread`                   | :mod:`py3:_thread`                    |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``tkinter``                  | :mod:`py2:Tkinter`                  | :mod:`py3:tkinter`                    |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``tkinter_dialog``           | :mod:`py2:Dialog`                   | :mod:`py3:tkinter.dialog`             |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``tkinter_filedialog``       | :mod:`py2:FileDialog`               | :mod:`py3:tkinter.FileDialog`         |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``tkinter_scrolledtext``     | :mod:`py2:ScrolledText`             | :mod:`py3:tkinter.scrolledtext`       |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``tkinter_simpledialog``     | :mod:`py2:SimpleDialog`             | :mod:`py3:tkinter.simpledialog`       |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``tkinter_ttk``              | :mod:`py2:ttk`                      | :mod:`py3:tkinter.ttk`                |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``tkinter_tix``              | :mod:`py2:Tix`                      | :mod:`py3:tkinter.tix`                |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``tkinter_constants``        | :mod:`py2:Tkconstants`              | :mod:`py3:tkinter.constants`          |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``tkinter_dnd``              | :mod:`py2:Tkdnd`                    | :mod:`py3:tkinter.dnd`                |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``tkinter_colorchooser``     | :mod:`py2:tkColorChooser`           | :mod:`py3:tkinter.colorchooser`       |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``tkinter_commondialog``     | :mod:`py2:tkCommonDialog`           | :mod:`py3:tkinter.commondialog`       |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``tkinter_tkfiledialog``     | :mod:`py2:tkFileDialog`             | :mod:`py3:tkinter.filedialog`         |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``tkinter_font``             | :mod:`py2:tkFont`                   | :mod:`py3:tkinter.font`               |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``tkinter_messagebox``       | :mod:`py2:tkMessageBox`             | :mod:`py3:tkinter.messagebox`         |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``tkinter_tksimpledialog``   | :mod:`py2:tkSimpleDialog`           | :mod:`py3:tkinter.simpledialog`       |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``urllib.parse``             | See :mod:`six.moves.urllib.parse`   | :mod:`py3:urllib.parse`               |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``urllib.error``             | See :mod:`six.moves.urllib.error`   | :mod:`py3:urllib.error`               |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``urllib.request``           | See :mod:`six.moves.urllib.request` | :mod:`py3:urllib.request`             |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``urllib.response``          | See :mod:`six.moves.urllib.response`| :mod:`py3:urllib.response`            |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``urllib.robotparser``       | :mod:`py2:robotparser`              | :mod:`py3:urllib.robotparser`         |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``urllib_robotparser``       | :mod:`py2:robotparser`              | :mod:`py3:urllib.robotparser`         |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``UserDict``                 | :class:`py2:UserDict.UserDict`      | :class:`py3:collections.UserDict`     |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``UserList``                 | :class:`py2:UserList.UserList`      | :class:`py3:collections.UserList`     |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``UserString``               | :class:`py2:UserString.UserString`  | :class:`py3:collections.UserString`   |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``winreg``                   | :mod:`py2:_winreg`                  | :mod:`py3:winreg`                     |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``xmlrpc_client``            | :mod:`py2:xmlrpclib`                | :mod:`py3:xmlrpc.client`              |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``xmlrpc_server``            | :mod:`py2:SimpleXMLRPCServer`       | :mod:`py3:xmlrpc.server`              |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``xrange``                   | :func:`py2:xrange`                  | :func:`py3:range`                     |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``zip``                      | :func:`py2:itertools.izip`          | :func:`py3:zip`                       |
-+------------------------------+-------------------------------------+---------------------------------------+
-| ``zip_longest``              | :func:`py2:itertools.izip_longest`  | :func:`py3:itertools.zip_longest`     |
-+------------------------------+-------------------------------------+---------------------------------------+
++------------------------------+---------------------------------------+---------------------------------------+
+| Name                         | Python 2 name                         | Python 3 name                         |
++==============================+=======================================+=======================================+
+| ``builtins``                 | :mod:`py2:__builtin__`                | :mod:`py3:builtins`                   |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``configparser``             | :mod:`py2:ConfigParser`               | :mod:`py3:configparser`               |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``copyreg``                  | :mod:`py2:copy_reg`                   | :mod:`py3:copyreg`                    |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``cPickle``                  | :mod:`py2:cPickle`                    | :mod:`py3:pickle`                     |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``cStringIO``                | :func:`py2:cStringIO.StringIO`        | :class:`py3:io.StringIO`              |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``collections_abc``          | :mod:`py2:collections`                | :mod:`py3:collections.abc` (3.3+)     |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``dbm_gnu``                  | :mod:`py2:gdbm`                       | :mod:`py3:dbm.gnu`                    |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``dbm_ndbm``                 | :mod:`py2:dbm`                        | :mod:`py3:dbm.ndbm`                   |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``_dummy_thread``            | :mod:`py2:dummy_thread`               | :mod:`py3:_dummy_thread` (< 3.9)      |
+|                              |                                       | :mod:`py3:_thread` (3.9+)             |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``email_mime_base``          | :mod:`py2:email.MIMEBase`             | :mod:`py3:email.mime.base`            |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``email_mime_image``         | :mod:`py2:email.MIMEImage`            | :mod:`py3:email.mime.image`           |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``email_mime_multipart``     | :mod:`py2:email.MIMEMultipart`        | :mod:`py3:email.mime.multipart`       |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``email_mime_nonmultipart``  | :mod:`py2:email.MIMENonMultipart`     | :mod:`py3:email.mime.nonmultipart`    |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``email_mime_text``          | :mod:`py2:email.MIMEText`             | :mod:`py3:email.mime.text`            |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``filter``                   | :func:`py2:itertools.ifilter`         | :func:`py3:filter`                    |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``filterfalse``              | :func:`py2:itertools.ifilterfalse`    | :func:`py3:itertools.filterfalse`     |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``getcwd``                   | :func:`py2:os.getcwdu`                | :func:`py3:os.getcwd`                 |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``getcwdb``                  | :func:`py2:os.getcwd`                 | :func:`py3:os.getcwdb`                |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``getoutput``                | :func:`py2:commands.getoutput`        | :func:`py3:subprocess.getoutput`      |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``http_cookiejar``           | :mod:`py2:cookielib`                  | :mod:`py3:http.cookiejar`             |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``http_cookies``             | :mod:`py2:Cookie`                     | :mod:`py3:http.cookies`               |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``html_entities``            | :mod:`py2:htmlentitydefs`             | :mod:`py3:html.entities`              |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``html_parser``              | :mod:`py2:HTMLParser`                 | :mod:`py3:html.parser`                |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``http_client``              | :mod:`py2:httplib`                    | :mod:`py3:http.client`                |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``BaseHTTPServer``           | :mod:`py2:BaseHTTPServer`             | :mod:`py3:http.server`                |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``CGIHTTPServer``            | :mod:`py2:CGIHTTPServer`              | :mod:`py3:http.server`                |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``SimpleHTTPServer``         | :mod:`py2:SimpleHTTPServer`           | :mod:`py3:http.server`                |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``input``                    | :func:`py2:raw_input`                 | :func:`py3:input`                     |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``intern``                   | :func:`py2:intern`                    | :func:`py3:sys.intern`                |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``map``                      | :func:`py2:itertools.imap`            | :func:`py3:map`                       |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``queue``                    | :mod:`py2:Queue`                      | :mod:`py3:queue`                      |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``range``                    | :func:`py2:xrange`                    | :func:`py3:range`                     |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``reduce``                   | :func:`py2:reduce`                    | :func:`py3:functools.reduce`          |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``reload_module``            | :func:`py2:reload`                    | :func:`py3:imp.reload`,               |
+|                              |                                       | :func:`py3:importlib.reload`          |
+|                              |                                       | on Python 3.4+                        |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``reprlib``                  | :mod:`py2:repr`                       | :mod:`py3:reprlib`                    |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``shlex_quote``              | :mod:`py2:pipes.quote`                | :mod:`py3:shlex.quote`                |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``socketserver``             | :mod:`py2:SocketServer`               | :mod:`py3:socketserver`               |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``_thread``                  | :mod:`py2:thread`                     | :mod:`py3:_thread`                    |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``tkinter``                  | :mod:`py2:Tkinter`                    | :mod:`py3:tkinter`                    |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``tkinter_dialog``           | :mod:`py2:Dialog`                     | :mod:`py3:tkinter.dialog`             |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``tkinter_filedialog``       | :mod:`py2:FileDialog`                 | :mod:`py3:tkinter.FileDialog`         |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``tkinter_scrolledtext``     | :mod:`py2:ScrolledText`               | :mod:`py3:tkinter.scrolledtext`       |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``tkinter_simpledialog``     | :mod:`py2:SimpleDialog`               | :mod:`py3:tkinter.simpledialog`       |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``tkinter_ttk``              | :mod:`py2:ttk`                        | :mod:`py3:tkinter.ttk`                |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``tkinter_tix``              | :mod:`py2:Tix`                        | :mod:`py3:tkinter.tix`                |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``tkinter_constants``        | :mod:`py2:Tkconstants`                | :mod:`py3:tkinter.constants`          |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``tkinter_dnd``              | :mod:`py2:Tkdnd`                      | :mod:`py3:tkinter.dnd`                |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``tkinter_colorchooser``     | :mod:`py2:tkColorChooser`             | :mod:`py3:tkinter.colorchooser`       |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``tkinter_commondialog``     | :mod:`py2:tkCommonDialog`             | :mod:`py3:tkinter.commondialog`       |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``tkinter_tkfiledialog``     | :mod:`py2:tkFileDialog`               | :mod:`py3:tkinter.filedialog`         |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``tkinter_font``             | :mod:`py2:tkFont`                     | :mod:`py3:tkinter.font`               |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``tkinter_messagebox``       | :mod:`py2:tkMessageBox`               | :mod:`py3:tkinter.messagebox`         |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``tkinter_tksimpledialog``   | :mod:`py2:tkSimpleDialog`             | :mod:`py3:tkinter.simpledialog`       |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``urllib.parse``             | See :mod:`six.moves.urllib.parse`     | :mod:`py3:urllib.parse`               |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``urllib.error``             | See :mod:`six.moves.urllib.error`     | :mod:`py3:urllib.error`               |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``urllib.request``           | See :mod:`six.moves.urllib.request`   | :mod:`py3:urllib.request`             |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``urllib.response``          | See :mod:`six.moves.urllib.response`  | :mod:`py3:urllib.response`            |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``urllib.robotparser``       | :mod:`py2:robotparser`                | :mod:`py3:urllib.robotparser`         |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``urllib_robotparser``       | :mod:`py2:robotparser`                | :mod:`py3:urllib.robotparser`         |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``UserDict``                 | :class:`py2:UserDict.IterableUserDict`| :class:`py3:collections.UserDict`     |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``UserList``                 | :class:`py2:UserList.UserList`        | :class:`py3:collections.UserList`     |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``UserString``               | :class:`py2:UserString.UserString`    | :class:`py3:collections.UserString`   |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``winreg``                   | :mod:`py2:_winreg`                    | :mod:`py3:winreg`                     |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``xmlrpc_client``            | :mod:`py2:xmlrpclib`                  | :mod:`py3:xmlrpc.client`              |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``xmlrpc_server``            | :mod:`py2:SimpleXMLRPCServer`         | :mod:`py3:xmlrpc.server`              |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``xrange``                   | :func:`py2:xrange`                    | :func:`py3:range`                     |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``zip``                      | :func:`py2:itertools.izip`            | :func:`py3:zip`                       |
++------------------------------+---------------------------------------+---------------------------------------+
+| ``zip_longest``              | :func:`py2:itertools.izip_longest`    | :func:`py3:itertools.zip_longest`     |
++------------------------------+---------------------------------------+---------------------------------------+
 
 urllib parse
 <<<<<<<<<<<<
diff --git a/setup.cfg b/setup.cfg
index 317e016..299040f 100644
--- a/setup.cfg
+++ b/setup.cfg
@@ -6,15 +6,7 @@ max-line-length = 100
 ignore = F821
 
 [metadata]
-license_file = LICENSE
+license_files = LICENSE
 
 [tool:pytest]
 minversion=2.2.0
-pep8ignore =
-    documentation/*.py ALL
-    test_six.py ALL
-
-flakes-ignore =
-    documentation/*.py ALL
-    test_six.py ALL
-    six.py UndefinedName
diff --git a/setup.py b/setup.py
index d90958b..660cf39 100644
--- a/setup.py
+++ b/setup.py
@@ -1,4 +1,4 @@
-# Copyright (c) 2010-2020 Benjamin Peterson
+# Copyright (c) 2010-2024 Benjamin Peterson
 #
 # Permission is hereby granted, free of charge, to any person obtaining a copy
 # of this software and associated documentation files (the "Software"), to deal
diff --git a/six.py b/six.py
index 4e15675..3de5969 100644
--- a/six.py
+++ b/six.py
@@ -1,4 +1,4 @@
-# Copyright (c) 2010-2020 Benjamin Peterson
+# Copyright (c) 2010-2024 Benjamin Peterson
 #
 # Permission is hereby granted, free of charge, to any person obtaining a copy
 # of this software and associated documentation files (the "Software"), to deal
@@ -29,7 +29,7 @@ import sys
 import types
 
 __author__ = "Benjamin Peterson <benjamin@python.org>"
-__version__ = "1.16.0"
+__version__ = "1.17.0"
 
 
 # Useful for very coarse version differentiation.
@@ -263,7 +263,7 @@ _moved_attributes = [
     MovedAttribute("reduce", "__builtin__", "functools"),
     MovedAttribute("shlex_quote", "pipes", "shlex", "quote"),
     MovedAttribute("StringIO", "StringIO", "io"),
-    MovedAttribute("UserDict", "UserDict", "collections"),
+    MovedAttribute("UserDict", "UserDict", "collections", "IterableUserDict", "UserDict"),
     MovedAttribute("UserList", "UserList", "collections"),
     MovedAttribute("UserString", "UserString", "collections"),
     MovedAttribute("xrange", "__builtin__", "builtins", "xrange", "range"),
@@ -435,12 +435,17 @@ _urllib_request_moved_attributes = [
     MovedAttribute("HTTPErrorProcessor", "urllib2", "urllib.request"),
     MovedAttribute("urlretrieve", "urllib", "urllib.request"),
     MovedAttribute("urlcleanup", "urllib", "urllib.request"),
-    MovedAttribute("URLopener", "urllib", "urllib.request"),
-    MovedAttribute("FancyURLopener", "urllib", "urllib.request"),
     MovedAttribute("proxy_bypass", "urllib", "urllib.request"),
     MovedAttribute("parse_http_list", "urllib2", "urllib.request"),
     MovedAttribute("parse_keqv_list", "urllib2", "urllib.request"),
 ]
+if sys.version_info[:2] < (3, 14):
+    _urllib_request_moved_attributes.extend(
+        [
+            MovedAttribute("URLopener", "urllib", "urllib.request"),
+            MovedAttribute("FancyURLopener", "urllib", "urllib.request"),
+        ]
+    )
 for attr in _urllib_request_moved_attributes:
     setattr(Module_six_moves_urllib_request, attr.name, attr)
 del attr
diff --git a/test_six.py b/test_six.py
index 7b8b03b..8890c0e 100644
--- a/test_six.py
+++ b/test_six.py
@@ -1,4 +1,4 @@
-# Copyright (c) 2010-2020 Benjamin Peterson
+# Copyright (c) 2010-2024 Benjamin Peterson
 #
 # Permission is hereby granted, free of charge, to any person obtaining a copy
 # of this software and associated documentation files (the "Software"), to deal
@@ -113,6 +113,15 @@ except ImportError:
     except ImportError:
         have_gdbm = False
 
+have_ndbm = True
+try:
+    import dbm
+except ImportError:
+    try:
+        import dbm.ndbm
+    except ImportError:
+        have_ndbm = False
+
 @pytest.mark.parametrize("item_name",
                           [item.name for item in six._moved_attributes])
 def test_move_items(item_name):
@@ -127,8 +136,12 @@ def test_move_items(item_name):
         if item_name.startswith("tkinter"):
             if not have_tkinter:
                 pytest.skip("requires tkinter")
-        if item_name.startswith("dbm_gnu") and not have_gdbm:
+            if item_name == "tkinter_tix" and sys.version_info >= (3, 13):
+                pytest.skip("tkinter.tix removed from Python 3.13")
+        if item_name == "dbm_gnu" and not have_gdbm:
             pytest.skip("requires gdbm")
+        if item_name == "dbm_ndbm":
+            pytest.skip("requires ndbm")
         raise
     assert item_name in dir(six.moves)
 
@@ -220,8 +233,8 @@ def test_map():
 
 def test_getoutput():
     from six.moves import getoutput
-    output = getoutput('echo "foo"')
-    assert output == 'foo'
+    output = getoutput('dir' if sys.platform.startswith('win') else 'echo foo')
+    assert output != ''
 
 
 def test_zip():
```

