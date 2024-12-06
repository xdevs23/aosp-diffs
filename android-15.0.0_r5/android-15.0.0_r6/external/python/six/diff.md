```diff
diff --git a/.gitignore b/.gitignore
new file mode 100644
index 0000000..d4b534b
--- /dev/null
+++ b/.gitignore
@@ -0,0 +1,7 @@
+*.pyc
+build
+dist
+MANIFEST
+documentation/_build
+.tox
+six.egg-info
diff --git a/.travis.yml b/.travis.yml
new file mode 100644
index 0000000..24a969a
--- /dev/null
+++ b/.travis.yml
@@ -0,0 +1,50 @@
+os: linux
+dist: xenial
+language: python
+python:
+- 2.7
+- 3.4
+- 3.5
+- 3.6
+- 3.7
+- &mainstream_python 3.8
+- nightly
+- pypy
+- pypy3
+install:
+- pip install --upgrade --force-reinstall "setuptools; python_version != '3.3'" "setuptools < 40; python_version == '3.3'"
+- pip uninstall --yes six || true
+- pip install --upgrade --force-reinstall --ignore-installed -e .
+- pip install "pytest==4.6.9; python_version != '3.3'" "pytest==2.9.2; python_version == '3.3'" "typing; python_version < '3'"
+- &py_pkg_list pip list --format=columns || pip list
+script:
+- py.test
+- echo Checking whether installation flow is not broken...
+- pip uninstall --yes six || true
+- pip install --ignore-installed .
+- *py_pkg_list
+jobs:
+  fast_finish: true
+  include:
+  - python: 3.3
+    dist: trusty
+  - stage: upload new version of python package to PYPI (only for tagged commits)
+    python: *mainstream_python
+    install: skip
+    script: skip
+    deploy:
+      provider: pypi
+      on:
+        tags: true
+        all_branches: true
+        python: *mainstream_python
+      user: __token__
+      distributions: "sdist bdist_wheel"
+      password:
+        secure: "F83KFmQnpBcR/BD7tBjJcmchvvoxYjIB0EDmDKEM+Rq1SJUH0qtYZlMJ0H4S8sTeY4+h26Ssfg5+oe9SqS5AkEMLFVM2lDcFtIXNR9bIvsXjkKsdxIWZJJ+Vl7EmW+ND/oj9IWnHOvaPr6F1YQqOuP2LfrDsoZ+4wo4X+UCC8xCGCaAIliPIt6y7U3ENeCQJTwUc93eDMZrEROmWAwsxF54a13CIkbTWe+S3iEp949MaNBWx2f9XNi7Gidk2gKUKordK0MXiO7+DcrQdiCAtPryqqNKR/JjZ66P9eK1A2VWyk65/5E8+OJeexuSlHGg52HKoXU2BPIkzgcaSjt79WQKVKJzYi2iD0Bd/9/RKrnq8+GVd0yT5IJV5OhwcpT0ScPs/9pAZ1mSEufx1FtXN61ujs2VEuleSQAWBiNGXsRQNCzVxgfatkUTNMjB0jxUzNay5CFrMlo5AVWBcdByhUto3szV/lxLj7arM48GHXaf+5MXhaELU8L2pTpJoQ8Rdj+Tx5HbhJ+wWF6EyT919prB2/6fM4d/MHIuHfJkCasYZSvhamGnTBzxxH9Fv7l18FyrBXF+Rz65mXVkUlxFMICSMWRJWEb4I2KWK1bsxCFy+o38TMeije+1nbvKVRKbLMn6mbXfBb/wfLTNogHFXrlR5VcugcP079dqR9O3iV4M="
+
+cache:
+  pip: true
+after_failure:
+- echo "Here's a list of installed Python packages:"
+- *py_pkg_list
diff --git a/Android.bp b/Android.bp
index fff8b04..fd63546 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1,17 +1,3 @@
-// Copyright 2017 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
 package {
     default_applicable_licenses: ["external_python_six_license"],
 }
diff --git a/CHANGES b/CHANGES
index b399882..f3bf6a4 100644
--- a/CHANGES
+++ b/CHANGES
@@ -3,6 +3,53 @@ Changelog for six
 
 This file lists the changes in each six version.
 
+1.16.0
+------
+
+- Pull request #343, issue #341, pull request #349: Port _SixMetaPathImporter to
+  Python 3.10.
+
+1.15.0
+------
+
+- Pull request #331: Optimize `six.ensure_str` and `six.ensure_binary`.
+
+1.14.0
+------
+
+- Issue #288, pull request #289: Add `six.assertNotRegex`.
+
+- Issue #317: `six.moves._dummy_thread` now points to the `_thread` module on
+  Python 3.9+. Python 3.7 and later requires threading and deprecated the
+  `_dummy_thread` module.
+
+- Issue #308, pull request #314: Remove support for Python 2.6 and Python 3.2.
+
+- Issue #250, issue #165, pull request #251: `six.wraps` now ignores missing
+  attributes. This follows the Python 3.2+ standard library behavior.
+
+1.13.0
+------
+
+- Issue #298, pull request #299: Add `six.moves.dbm_ndbm`.
+
+- Issue #155: Add `six.moves.collections_abc`, which aliases the `collections`
+  module on Python 2-3.2 and the `collections.abc` on Python 3.3 and greater.
+
+- Pull request #304: Re-add distutils fallback in `setup.py`.
+
+- Pull request #305: On Python 3.7, `with_metaclass` supports classes using PEP
+  560 features.
+
+1.12.0
+------
+
+- Issue #259, pull request #260: `six.add_metaclass` now preserves
+  `__qualname__` from the original class.
+
+- Pull request #204: Add `six.ensure_binary`, `six.ensure_text`, and
+  `six.ensure_str`.
+
 1.11.0
 ------
 
@@ -59,7 +106,7 @@ This file lists the changes in each six version.
 
 - Issue #98: Fix `six.moves` race condition in multi-threaded code.
 
-- Pull request #51: Add `six.view(keys|values|itmes)`, which provide dictionary
+- Pull request #51: Add `six.view(keys|values|items)`, which provide dictionary
   views on Python 2.7+.
 
 - Issue #112: `six.moves.reload_module` now uses the importlib module on
@@ -186,7 +233,7 @@ This file lists the changes in each six version.
 - Issue #40: Add import mapping for the Python 2 gdbm module.
 
 - Issue #35: On Python versions less than 2.7, print_ now encodes unicode
-  strings when outputing to standard streams. (Python 2.7 handles this
+  strings when outputting to standard streams. (Python 2.7 handles this
   automatically.)
 
 1.4.1
diff --git a/CONTRIBUTORS b/CONTRIBUTORS
new file mode 100644
index 0000000..a76dffd
--- /dev/null
+++ b/CONTRIBUTORS
@@ -0,0 +1,44 @@
+The primary author and maintainer of six is Benjamin Peterson. He would like to
+acknowledge the following people who submitted bug reports, pull requests, and
+otherwise worked to improve six:
+
+Marc Abramowitz
+immerrr again
+Alexander Artemenko
+Aymeric Augustin
+Lee Ball
+Ben Bariteau
+Ned Batchelder
+Wouter Bolsterlee
+Brett Cannon
+Jason R. Coombs
+Julien Danjou
+Ben Darnell
+Ben Davis
+Jon Dufresne
+Tim Graham
+Thomas Grainger
+Max Grender-Jones
+Pierre Grimaud
+Joshua Harlow
+Toshiki Kataoka
+Hugo van Kemenade
+Anselm Kruis
+Ivan Levkivskyi
+Alexander Lukanin
+James Mills
+Jordan Moldow
+Berker Peksag
+Sridhar Ratnakumar
+Erik Rose
+Mirko Rossini
+Peter Ruibal
+Miroslav Shubernetskiy
+Eli Schwartz
+Anthony Sottile
+Victor Stinner
+Jonathan Vanasco
+Lucas Wiman
+Jingxin Zhu
+
+If you think you belong on this list, please let me know! --Benjamin
diff --git a/LICENSE b/LICENSE
index f3068bf..de66331 100644
--- a/LICENSE
+++ b/LICENSE
@@ -1,4 +1,4 @@
-Copyright (c) 2010-2017 Benjamin Peterson
+Copyright (c) 2010-2020 Benjamin Peterson
 
 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
diff --git a/METADATA b/METADATA
index 2b372ac..2473a70 100644
--- a/METADATA
+++ b/METADATA
@@ -1,17 +1,20 @@
-name: "six"
-description:
-    "Python PyPI six package"
+# This project was upgraded with external_updater.
+# Usage: tools/external_updater/updater.sh update external/python/six
+# For more info, check https://cs.android.com/android/platform/superproject/+/main:tools/external_updater/README.md
 
+name: "six"
+description: "Python PyPI six package"
 third_party {
-  url {
-    type: HOMEPAGE
-    value: "https://pypi.python.org/pypi/six"
+  license_type: NOTICE
+  last_upgrade_date {
+    year: 2024
+    month: 7
+    day: 9
   }
-  url {
-    type: GIT
+  homepage: "https://pypi.python.org/pypi/six"
+  identifier {
+    type: "Git"
     value: "https://github.com/benjaminp/six"
+    version: "1.16.0"
   }
-  version: "1.11.0"
-  license_type: NOTICE
-  last_upgrade_date { year: 2018 month: 1 day: 4 }
 }
diff --git a/PKG-INFO b/PKG-INFO
deleted file mode 100644
index cd5ff4b..0000000
--- a/PKG-INFO
+++ /dev/null
@@ -1,41 +0,0 @@
-Metadata-Version: 1.1
-Name: six
-Version: 1.11.0
-Summary: Python 2 and 3 compatibility utilities
-Home-page: http://pypi.python.org/pypi/six/
-Author: Benjamin Peterson
-Author-email: benjamin@python.org
-License: MIT
-Description: .. image:: http://img.shields.io/pypi/v/six.svg
-           :target: https://pypi.python.org/pypi/six
-        
-        .. image:: https://travis-ci.org/benjaminp/six.svg?branch=master
-            :target: https://travis-ci.org/benjaminp/six
-        
-        .. image:: http://img.shields.io/badge/license-MIT-green.svg
-           :target: https://github.com/benjaminp/six/blob/master/LICENSE
-        
-        Six is a Python 2 and 3 compatibility library.  It provides utility functions
-        for smoothing over the differences between the Python versions with the goal of
-        writing Python code that is compatible on both Python versions.  See the
-        documentation for more information on what is provided.
-        
-        Six supports every Python version since 2.6.  It is contained in only one Python
-        file, so it can be easily copied into your project. (The copyright and license
-        notice must be retained.)
-        
-        Online documentation is at http://six.rtfd.org.
-        
-        Bugs can be reported to https://github.com/benjaminp/six.  The code can also
-        be found there.
-        
-        For questions about six or porting in general, email the python-porting mailing
-        list: https://mail.python.org/mailman/listinfo/python-porting
-        
-Platform: UNKNOWN
-Classifier: Programming Language :: Python :: 2
-Classifier: Programming Language :: Python :: 3
-Classifier: Intended Audience :: Developers
-Classifier: License :: OSI Approved :: MIT License
-Classifier: Topic :: Software Development :: Libraries
-Classifier: Topic :: Utilities
diff --git a/README.rst b/README.rst
index c17d8d7..6339ba5 100644
--- a/README.rst
+++ b/README.rst
@@ -1,25 +1,29 @@
-.. image:: http://img.shields.io/pypi/v/six.svg
-   :target: https://pypi.python.org/pypi/six
+.. image:: https://img.shields.io/pypi/v/six.svg
+   :target: https://pypi.org/project/six/
+   :alt: six on PyPI
 
 .. image:: https://travis-ci.org/benjaminp/six.svg?branch=master
-    :target: https://travis-ci.org/benjaminp/six
+   :target: https://travis-ci.org/benjaminp/six
+   :alt: six on TravisCI
 
-.. image:: http://img.shields.io/badge/license-MIT-green.svg
+.. image:: https://readthedocs.org/projects/six/badge/?version=latest
+   :target: https://six.readthedocs.io/
+   :alt: six's documentation on Read the Docs
+
+.. image:: https://img.shields.io/badge/license-MIT-green.svg
    :target: https://github.com/benjaminp/six/blob/master/LICENSE
+   :alt: MIT License badge
 
 Six is a Python 2 and 3 compatibility library.  It provides utility functions
 for smoothing over the differences between the Python versions with the goal of
 writing Python code that is compatible on both Python versions.  See the
 documentation for more information on what is provided.
 
-Six supports every Python version since 2.6.  It is contained in only one Python
+Six supports Python 2.7 and 3.3+.  It is contained in only one Python
 file, so it can be easily copied into your project. (The copyright and license
 notice must be retained.)
 
-Online documentation is at http://six.rtfd.org.
+Online documentation is at https://six.readthedocs.io/.
 
 Bugs can be reported to https://github.com/benjaminp/six.  The code can also
 be found there.
-
-For questions about six or porting in general, email the python-porting mailing
-list: https://mail.python.org/mailman/listinfo/python-porting
diff --git a/documentation/conf.py b/documentation/conf.py
index ad925c1..2f0f323 100644
--- a/documentation/conf.py
+++ b/documentation/conf.py
@@ -33,7 +33,7 @@ master_doc = "index"
 
 # General information about the project.
 project = u"six"
-copyright = u"2010-2017, Benjamin Peterson"
+copyright = u"2010-2020, Benjamin Peterson"
 
 sys.path.append(os.path.abspath(os.path.join(".", "..")))
 from six import __version__ as six_version
diff --git a/documentation/index.rst b/documentation/index.rst
index dd0dc6e..45390b8 100644
--- a/documentation/index.rst
+++ b/documentation/index.rst
@@ -13,7 +13,7 @@ Python 3.  It is intended to support codebases that work on both Python 2 and 3
 without modification.  six consists of only one Python file, so it is painless
 to copy into a project.
 
-Six can be downloaded on `PyPi <https://pypi.python.org/pypi/six/>`_.  Its bug
+Six can be downloaded on `PyPI <https://pypi.org/project/six/>`_.  Its bug
 tracker and code hosting is on `GitHub <https://github.com/benjaminp/six>`_.
 
 The name, "six", comes from the fact that 2*3 equals 6.  Why not addition?
@@ -50,8 +50,9 @@ Six provides constants that may differ between Python versions.  Ones ending
 
 .. data:: class_types
 
-   Possible class types.  In Python 2, this encompasses old-style and new-style
-   classes.  In Python 3, this is just new-styles.
+   Possible class types.  In Python 2, this encompasses old-style
+   :data:`py2:types.ClassType` and new-style ``type`` classes.  In Python 3,
+   this is just ``type``.
 
 
 .. data:: integer_types
@@ -75,7 +76,9 @@ Six provides constants that may differ between Python versions.  Ones ending
 .. data:: binary_type
 
    Type for representing binary data.  This is :func:`py2:str` in Python 2 and
-   :func:`py3:bytes` in Python 3.
+   :func:`py3:bytes` in Python 3.  Python 2.6 and 2.7 include ``bytes`` as a
+   builtin alias of ``str``, so six’s version is only necessary for Python 2.5
+   compatibility.
 
 
 .. data:: MAXSIZE
@@ -254,9 +257,10 @@ functions and methods is the stdlib :mod:`py3:inspect` module.
 
 .. decorator:: wraps(wrapped, assigned=functools.WRAPPER_ASSIGNMENTS, updated=functools.WRAPPER_UPDATES)
 
-   This is exactly the :func:`py3:functools.wraps` decorator, but it sets the
-   ``__wrapped__`` attribute on what it decorates as :func:`py3:functools.wraps`
-   does on Python versions after 3.2.
+   This is Python 3.2's :func:`py3:functools.wraps` decorator.  It sets the
+   ``__wrapped__`` attribute on what it decorates.  It doesn't raise an error if
+   any of the attributes mentioned in ``assigned`` and ``updated`` are missing
+   on ``wrapped`` object.
 
 
 Syntax compatibility
@@ -371,7 +375,7 @@ string data in all Python versions.
 .. function:: b(data)
 
    A "fake" bytes literal.  *data* should always be a normal string literal.  In
-   Python 2, :func:`b` returns a 8-bit string.  In Python 3, *data* is encoded
+   Python 2, :func:`b` returns an 8-bit string.  In Python 3, *data* is encoded
    with the latin-1 encoding to bytes.
 
 
@@ -433,6 +437,24 @@ string data in all Python versions.
    a bytes object iterator in Python 3.
 
 
+.. function:: ensure_binary(s, encoding='utf-8', errors='strict')
+
+   Coerce *s* to :data:`binary_type`. *encoding*, *errors* are the same as
+   :meth:`py3:str.encode`
+
+
+.. function:: ensure_str(s, encoding='utf-8', errors='strict')
+
+   Coerce *s* to ``str``. *encoding*, *errors* are the same as
+   :meth:`py3:str.encode`
+
+
+.. function:: ensure_text(s, encoding='utf-8', errors='strict')
+
+   Coerce *s* to :data:`text_type`. *encoding*, *errors* are the same as
+   :meth:`py3:bytes.decode`
+
+
 .. data:: StringIO
 
    This is a fake file object for textual data.  It's an alias for
@@ -488,6 +510,11 @@ Note these functions are only available on Python 2.7 or later.
    Alias for :meth:`~py3:unittest.TestCase.assertRegex` on Python 3 and
    :meth:`~py2:unittest.TestCase.assertRegexpMatches` on Python 2.
 
+.. function:: assertNotRegex()
+
+   Alias for :meth:`~py3:unittest.TestCase.assertNotRegex` on Python 3 and
+   :meth:`~py2:unittest.TestCase.assertNotRegexpMatches` on Python 2.
+
 
 Renamed modules and attributes compatibility
 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
@@ -503,7 +530,7 @@ Python 2 or 3, write::
    from six.moves import html_parser
 
 Similarly, to get the function to reload modules, which was moved from the
-builtin module to the ``imp`` module, use::
+builtin module to the ``importlib`` module, use::
 
    from six.moves import reload_module
 
@@ -563,9 +590,14 @@ Supported renames:
 +------------------------------+-------------------------------------+---------------------------------------+
 | ``cStringIO``                | :func:`py2:cStringIO.StringIO`      | :class:`py3:io.StringIO`              |
 +------------------------------+-------------------------------------+---------------------------------------+
-| ``dbm_gnu``                  | :func:`py2:gdbm`                    | :class:`py3:dbm.gnu`                  |
+| ``collections_abc``          | :mod:`py2:collections`              | :mod:`py3:collections.abc` (3.3+)     |
++------------------------------+-------------------------------------+---------------------------------------+
+| ``dbm_gnu``                  | :mod:`py2:gdbm`                     | :mod:`py3:dbm.gnu`                    |
++------------------------------+-------------------------------------+---------------------------------------+
+| ``dbm_ndbm``                 | :mod:`py2:dbm`                      | :mod:`py3:dbm.ndbm`                   |
 +------------------------------+-------------------------------------+---------------------------------------+
-| ``_dummy_thread``            | :mod:`py2:dummy_thread`             | :mod:`py3:_dummy_thread`              |
+| ``_dummy_thread``            | :mod:`py2:dummy_thread`             | :mod:`py3:_dummy_thread` (< 3.9)      |
+|                              |                                     | :mod:`py3:_thread` (3.9+)             |
 +------------------------------+-------------------------------------+---------------------------------------+
 | ``email_mime_base``          | :mod:`py2:email.MIMEBase`           | :mod:`py3:email.mime.base`            |
 +------------------------------+-------------------------------------+---------------------------------------+
diff --git a/setup.cfg b/setup.cfg
index e12068c..317e016 100644
--- a/setup.cfg
+++ b/setup.cfg
@@ -5,17 +5,16 @@ universal = 1
 max-line-length = 100
 ignore = F821
 
-[tool:pytest]
-minversion = 2.2.0
-pep8ignore = 
-	documentation/*.py ALL
-	test_six.py ALL
-flakes-ignore = 
-	documentation/*.py ALL
-	test_six.py ALL
-	six.py UndefinedName
+[metadata]
+license_file = LICENSE
 
-[egg_info]
-tag_build = 
-tag_date = 0
+[tool:pytest]
+minversion=2.2.0
+pep8ignore =
+    documentation/*.py ALL
+    test_six.py ALL
 
+flakes-ignore =
+    documentation/*.py ALL
+    test_six.py ALL
+    six.py UndefinedName
diff --git a/setup.py b/setup.py
index ca44e10..d90958b 100644
--- a/setup.py
+++ b/setup.py
@@ -1,4 +1,4 @@
-# Copyright (c) 2010-2017 Benjamin Peterson
+# Copyright (c) 2010-2020 Benjamin Peterson
 #
 # Permission is hereby granted, free of charge, to any person obtaining a copy
 # of this software and associated documentation files (the "Software"), to deal
@@ -31,6 +31,7 @@ except ImportError:
 import six
 
 six_classifiers = [
+    "Development Status :: 5 - Production/Stable",
     "Programming Language :: Python :: 2",
     "Programming Language :: Python :: 3",
     "Intended Audience :: Developers",
@@ -46,11 +47,12 @@ setup(name="six",
       version=six.__version__,
       author="Benjamin Peterson",
       author_email="benjamin@python.org",
-      url="http://pypi.python.org/pypi/six/",
+      url="https://github.com/benjaminp/six",
       tests_require=["pytest"],
       py_modules=["six"],
       description="Python 2 and 3 compatibility utilities",
       long_description=six_long_description,
       license="MIT",
-      classifiers=six_classifiers
+      classifiers=six_classifiers,
+      python_requires=">=2.7, !=3.0.*, !=3.1.*, !=3.2.*",
       )
diff --git a/six.egg-info/PKG-INFO b/six.egg-info/PKG-INFO
deleted file mode 100644
index cd5ff4b..0000000
--- a/six.egg-info/PKG-INFO
+++ /dev/null
@@ -1,41 +0,0 @@
-Metadata-Version: 1.1
-Name: six
-Version: 1.11.0
-Summary: Python 2 and 3 compatibility utilities
-Home-page: http://pypi.python.org/pypi/six/
-Author: Benjamin Peterson
-Author-email: benjamin@python.org
-License: MIT
-Description: .. image:: http://img.shields.io/pypi/v/six.svg
-           :target: https://pypi.python.org/pypi/six
-        
-        .. image:: https://travis-ci.org/benjaminp/six.svg?branch=master
-            :target: https://travis-ci.org/benjaminp/six
-        
-        .. image:: http://img.shields.io/badge/license-MIT-green.svg
-           :target: https://github.com/benjaminp/six/blob/master/LICENSE
-        
-        Six is a Python 2 and 3 compatibility library.  It provides utility functions
-        for smoothing over the differences between the Python versions with the goal of
-        writing Python code that is compatible on both Python versions.  See the
-        documentation for more information on what is provided.
-        
-        Six supports every Python version since 2.6.  It is contained in only one Python
-        file, so it can be easily copied into your project. (The copyright and license
-        notice must be retained.)
-        
-        Online documentation is at http://six.rtfd.org.
-        
-        Bugs can be reported to https://github.com/benjaminp/six.  The code can also
-        be found there.
-        
-        For questions about six or porting in general, email the python-porting mailing
-        list: https://mail.python.org/mailman/listinfo/python-porting
-        
-Platform: UNKNOWN
-Classifier: Programming Language :: Python :: 2
-Classifier: Programming Language :: Python :: 3
-Classifier: Intended Audience :: Developers
-Classifier: License :: OSI Approved :: MIT License
-Classifier: Topic :: Software Development :: Libraries
-Classifier: Topic :: Utilities
diff --git a/six.egg-info/SOURCES.txt b/six.egg-info/SOURCES.txt
deleted file mode 100644
index 9a7f3de..0000000
--- a/six.egg-info/SOURCES.txt
+++ /dev/null
@@ -1,15 +0,0 @@
-CHANGES
-LICENSE
-MANIFEST.in
-README.rst
-setup.cfg
-setup.py
-six.py
-test_six.py
-documentation/Makefile
-documentation/conf.py
-documentation/index.rst
-six.egg-info/PKG-INFO
-six.egg-info/SOURCES.txt
-six.egg-info/dependency_links.txt
-six.egg-info/top_level.txt
\ No newline at end of file
diff --git a/six.egg-info/dependency_links.txt b/six.egg-info/dependency_links.txt
deleted file mode 100644
index 8b13789..0000000
--- a/six.egg-info/dependency_links.txt
+++ /dev/null
@@ -1 +0,0 @@
-
diff --git a/six.egg-info/top_level.txt b/six.egg-info/top_level.txt
deleted file mode 100644
index ffe2fce..0000000
--- a/six.egg-info/top_level.txt
+++ /dev/null
@@ -1 +0,0 @@
-six
diff --git a/six.py b/six.py
index 6bf4fd3..4e15675 100644
--- a/six.py
+++ b/six.py
@@ -1,4 +1,4 @@
-# Copyright (c) 2010-2017 Benjamin Peterson
+# Copyright (c) 2010-2020 Benjamin Peterson
 #
 # Permission is hereby granted, free of charge, to any person obtaining a copy
 # of this software and associated documentation files (the "Software"), to deal
@@ -29,7 +29,7 @@ import sys
 import types
 
 __author__ = "Benjamin Peterson <benjamin@python.org>"
-__version__ = "1.11.0"
+__version__ = "1.16.0"
 
 
 # Useful for very coarse version differentiation.
@@ -71,6 +71,11 @@ else:
             MAXSIZE = int((1 << 63) - 1)
         del X
 
+if PY34:
+    from importlib.util import spec_from_loader
+else:
+    spec_from_loader = None
+
 
 def _add_doc(func, doc):
     """Add documentation to a function."""
@@ -186,6 +191,11 @@ class _SixMetaPathImporter(object):
             return self
         return None
 
+    def find_spec(self, fullname, path, target=None):
+        if fullname in self.known_modules:
+            return spec_from_loader(fullname, self)
+        return None
+
     def __get_module(self, fullname):
         try:
             return self.known_modules[fullname]
@@ -223,6 +233,12 @@ class _SixMetaPathImporter(object):
         return None
     get_source = get_code  # same as get_code
 
+    def create_module(self, spec):
+        return self.load_module(spec.name)
+
+    def exec_module(self, module):
+        pass
+
 _importer = _SixMetaPathImporter(__name__)
 
 
@@ -255,9 +271,11 @@ _moved_attributes = [
     MovedAttribute("zip_longest", "itertools", "itertools", "izip_longest", "zip_longest"),
     MovedModule("builtins", "__builtin__"),
     MovedModule("configparser", "ConfigParser"),
+    MovedModule("collections_abc", "collections", "collections.abc" if sys.version_info >= (3, 3) else "collections"),
     MovedModule("copyreg", "copy_reg"),
     MovedModule("dbm_gnu", "gdbm", "dbm.gnu"),
-    MovedModule("_dummy_thread", "dummy_thread", "_dummy_thread"),
+    MovedModule("dbm_ndbm", "dbm", "dbm.ndbm"),
+    MovedModule("_dummy_thread", "dummy_thread", "_dummy_thread" if sys.version_info < (3, 9) else "_thread"),
     MovedModule("http_cookiejar", "cookielib", "http.cookiejar"),
     MovedModule("http_cookies", "Cookie", "http.cookies"),
     MovedModule("html_entities", "htmlentitydefs", "html.entities"),
@@ -637,13 +655,16 @@ if PY3:
     import io
     StringIO = io.StringIO
     BytesIO = io.BytesIO
+    del io
     _assertCountEqual = "assertCountEqual"
     if sys.version_info[1] <= 1:
         _assertRaisesRegex = "assertRaisesRegexp"
         _assertRegex = "assertRegexpMatches"
+        _assertNotRegex = "assertNotRegexpMatches"
     else:
         _assertRaisesRegex = "assertRaisesRegex"
         _assertRegex = "assertRegex"
+        _assertNotRegex = "assertNotRegex"
 else:
     def b(s):
         return s
@@ -665,6 +686,7 @@ else:
     _assertCountEqual = "assertItemsEqual"
     _assertRaisesRegex = "assertRaisesRegexp"
     _assertRegex = "assertRegexpMatches"
+    _assertNotRegex = "assertNotRegexpMatches"
 _add_doc(b, """Byte literal""")
 _add_doc(u, """Text literal""")
 
@@ -681,6 +703,10 @@ def assertRegex(self, *args, **kwargs):
     return getattr(self, _assertRegex)(*args, **kwargs)
 
 
+def assertNotRegex(self, *args, **kwargs):
+    return getattr(self, _assertNotRegex)(*args, **kwargs)
+
+
 if PY3:
     exec_ = getattr(moves.builtins, "exec")
 
@@ -716,16 +742,7 @@ else:
 """)
 
 
-if sys.version_info[:2] == (3, 2):
-    exec_("""def raise_from(value, from_value):
-    try:
-        if from_value is None:
-            raise value
-        raise value from from_value
-    finally:
-        value = None
-""")
-elif sys.version_info[:2] > (3, 2):
+if sys.version_info[:2] > (3,):
     exec_("""def raise_from(value, from_value):
     try:
         raise value from from_value
@@ -805,13 +822,33 @@ if sys.version_info[:2] < (3, 3):
 _add_doc(reraise, """Reraise an exception.""")
 
 if sys.version_info[0:2] < (3, 4):
+    # This does exactly the same what the :func:`py3:functools.update_wrapper`
+    # function does on Python versions after 3.2. It sets the ``__wrapped__``
+    # attribute on ``wrapper`` object and it doesn't raise an error if any of
+    # the attributes mentioned in ``assigned`` and ``updated`` are missing on
+    # ``wrapped`` object.
+    def _update_wrapper(wrapper, wrapped,
+                        assigned=functools.WRAPPER_ASSIGNMENTS,
+                        updated=functools.WRAPPER_UPDATES):
+        for attr in assigned:
+            try:
+                value = getattr(wrapped, attr)
+            except AttributeError:
+                continue
+            else:
+                setattr(wrapper, attr, value)
+        for attr in updated:
+            getattr(wrapper, attr).update(getattr(wrapped, attr, {}))
+        wrapper.__wrapped__ = wrapped
+        return wrapper
+    _update_wrapper.__doc__ = functools.update_wrapper.__doc__
+
     def wraps(wrapped, assigned=functools.WRAPPER_ASSIGNMENTS,
               updated=functools.WRAPPER_UPDATES):
-        def wrapper(f):
-            f = functools.wraps(wrapped, assigned, updated)(f)
-            f.__wrapped__ = wrapped
-            return f
-        return wrapper
+        return functools.partial(_update_wrapper, wrapped=wrapped,
+                                 assigned=assigned, updated=updated)
+    wraps.__doc__ = functools.wraps.__doc__
+
 else:
     wraps = functools.wraps
 
@@ -824,7 +861,15 @@ def with_metaclass(meta, *bases):
     class metaclass(type):
 
         def __new__(cls, name, this_bases, d):
-            return meta(name, bases, d)
+            if sys.version_info[:2] >= (3, 7):
+                # This version introduced PEP 560 that requires a bit
+                # of extra care (we mimic what is done by __build_class__).
+                resolved_bases = types.resolve_bases(bases)
+                if resolved_bases is not bases:
+                    d['__orig_bases__'] = bases
+            else:
+                resolved_bases = bases
+            return meta(name, resolved_bases, d)
 
         @classmethod
         def __prepare__(cls, name, this_bases):
@@ -844,13 +889,75 @@ def add_metaclass(metaclass):
                 orig_vars.pop(slots_var)
         orig_vars.pop('__dict__', None)
         orig_vars.pop('__weakref__', None)
+        if hasattr(cls, '__qualname__'):
+            orig_vars['__qualname__'] = cls.__qualname__
         return metaclass(cls.__name__, cls.__bases__, orig_vars)
     return wrapper
 
 
+def ensure_binary(s, encoding='utf-8', errors='strict'):
+    """Coerce **s** to six.binary_type.
+
+    For Python 2:
+      - `unicode` -> encoded to `str`
+      - `str` -> `str`
+
+    For Python 3:
+      - `str` -> encoded to `bytes`
+      - `bytes` -> `bytes`
+    """
+    if isinstance(s, binary_type):
+        return s
+    if isinstance(s, text_type):
+        return s.encode(encoding, errors)
+    raise TypeError("not expecting type '%s'" % type(s))
+
+
+def ensure_str(s, encoding='utf-8', errors='strict'):
+    """Coerce *s* to `str`.
+
+    For Python 2:
+      - `unicode` -> encoded to `str`
+      - `str` -> `str`
+
+    For Python 3:
+      - `str` -> `str`
+      - `bytes` -> decoded to `str`
+    """
+    # Optimization: Fast return for the common case.
+    if type(s) is str:
+        return s
+    if PY2 and isinstance(s, text_type):
+        return s.encode(encoding, errors)
+    elif PY3 and isinstance(s, binary_type):
+        return s.decode(encoding, errors)
+    elif not isinstance(s, (text_type, binary_type)):
+        raise TypeError("not expecting type '%s'" % type(s))
+    return s
+
+
+def ensure_text(s, encoding='utf-8', errors='strict'):
+    """Coerce *s* to six.text_type.
+
+    For Python 2:
+      - `unicode` -> `unicode`
+      - `str` -> `unicode`
+
+    For Python 3:
+      - `str` -> `str`
+      - `bytes` -> decoded to `str`
+    """
+    if isinstance(s, binary_type):
+        return s.decode(encoding, errors)
+    elif isinstance(s, text_type):
+        return s
+    else:
+        raise TypeError("not expecting type '%s'" % type(s))
+
+
 def python_2_unicode_compatible(klass):
     """
-    A decorator that defines __unicode__ and __str__ methods under Python 2.
+    A class decorator that defines __unicode__ and __str__ methods under Python 2.
     Under Python 3 it does nothing.
 
     To support Python 2 and 3 with a single code base, define a __str__ method
diff --git a/test_six.py b/test_six.py
index 43e7426..7b8b03b 100644
--- a/test_six.py
+++ b/test_six.py
@@ -1,4 +1,4 @@
-# Copyright (c) 2010-2017 Benjamin Peterson
+# Copyright (c) 2010-2020 Benjamin Peterson
 #
 # Permission is hereby granted, free of charge, to any person obtaining a copy
 # of this software and associated documentation files (the "Software"), to deal
@@ -22,8 +22,9 @@ import operator
 import sys
 import types
 import unittest
+import abc
 
-import py
+import pytest
 
 import six
 
@@ -80,7 +81,7 @@ def test_MAXSIZE():
     except AttributeError:
         # Before Python 2.6.
         pass
-    py.test.raises(
+    pytest.raises(
         (ValueError, OverflowError),
         operator.mul, [None], six.MAXSIZE + 1)
 
@@ -112,7 +113,7 @@ except ImportError:
     except ImportError:
         have_gdbm = False
 
-@py.test.mark.parametrize("item_name",
+@pytest.mark.parametrize("item_name",
                           [item.name for item in six._moved_attributes])
 def test_move_items(item_name):
     """Ensure that everything loads correctly."""
@@ -120,70 +121,55 @@ def test_move_items(item_name):
         item = getattr(six.moves, item_name)
         if isinstance(item, types.ModuleType):
             __import__("six.moves." + item_name)
-    except AttributeError:
-        if item_name == "zip_longest" and sys.version_info < (2, 6):
-            py.test.skip("zip_longest only available on 2.6+")
     except ImportError:
         if item_name == "winreg" and not sys.platform.startswith("win"):
-            py.test.skip("Windows only module")
+            pytest.skip("Windows only module")
         if item_name.startswith("tkinter"):
             if not have_tkinter:
-                py.test.skip("requires tkinter")
-            if item_name == "tkinter_ttk" and sys.version_info[:2] <= (2, 6):
-                py.test.skip("ttk only available on 2.7+")
+                pytest.skip("requires tkinter")
         if item_name.startswith("dbm_gnu") and not have_gdbm:
-            py.test.skip("requires gdbm")
+            pytest.skip("requires gdbm")
         raise
-    if sys.version_info[:2] >= (2, 6):
-        assert item_name in dir(six.moves)
+    assert item_name in dir(six.moves)
 
 
-@py.test.mark.parametrize("item_name",
+@pytest.mark.parametrize("item_name",
                           [item.name for item in six._urllib_parse_moved_attributes])
 def test_move_items_urllib_parse(item_name):
     """Ensure that everything loads correctly."""
-    if item_name == "ParseResult" and sys.version_info < (2, 5):
-        py.test.skip("ParseResult is only found on 2.5+")
-    if item_name in ("parse_qs", "parse_qsl") and sys.version_info < (2, 6):
-        py.test.skip("parse_qs[l] is new in 2.6")
-    if sys.version_info[:2] >= (2, 6):
-        assert item_name in dir(six.moves.urllib.parse)
+    assert item_name in dir(six.moves.urllib.parse)
     getattr(six.moves.urllib.parse, item_name)
 
 
-@py.test.mark.parametrize("item_name",
+@pytest.mark.parametrize("item_name",
                           [item.name for item in six._urllib_error_moved_attributes])
 def test_move_items_urllib_error(item_name):
     """Ensure that everything loads correctly."""
-    if sys.version_info[:2] >= (2, 6):
-        assert item_name in dir(six.moves.urllib.error)
+    assert item_name in dir(six.moves.urllib.error)
     getattr(six.moves.urllib.error, item_name)
 
 
-@py.test.mark.parametrize("item_name",
+@pytest.mark.parametrize("item_name",
                           [item.name for item in six._urllib_request_moved_attributes])
 def test_move_items_urllib_request(item_name):
     """Ensure that everything loads correctly."""
-    if sys.version_info[:2] >= (2, 6):
-        assert item_name in dir(six.moves.urllib.request)
+    assert item_name in dir(six.moves.urllib.request)
     getattr(six.moves.urllib.request, item_name)
 
 
-@py.test.mark.parametrize("item_name",
+@pytest.mark.parametrize("item_name",
                           [item.name for item in six._urllib_response_moved_attributes])
 def test_move_items_urllib_response(item_name):
     """Ensure that everything loads correctly."""
-    if sys.version_info[:2] >= (2, 6):
-        assert item_name in dir(six.moves.urllib.response)
+    assert item_name in dir(six.moves.urllib.response)
     getattr(six.moves.urllib.response, item_name)
 
 
-@py.test.mark.parametrize("item_name",
+@pytest.mark.parametrize("item_name",
                           [item.name for item in six._urllib_robotparser_moved_attributes])
 def test_move_items_urllib_robotparser(item_name):
     """Ensure that everything loads correctly."""
-    if sys.version_info[:2] >= (2, 6):
-        assert item_name in dir(six.moves.urllib.robotparser)
+    assert item_name in dir(six.moves.urllib.robotparser)
     getattr(six.moves.urllib.robotparser, item_name)
 
 
@@ -243,7 +229,6 @@ def test_zip():
     assert six.advance_iterator(zip(range(2), range(2))) == (0, 0)
 
 
-@py.test.mark.skipif("sys.version_info < (2, 6)")
 def test_zip_longest():
     from six.moves import zip_longest
     it = zip_longest(range(2), range(1))
@@ -321,7 +306,7 @@ class TestCustomizedMoves:
 
 
     def test_empty_remove(self):
-        py.test.raises(AttributeError, six.remove_move, "eggs")
+        pytest.raises(AttributeError, six.remove_move, "eggs")
 
 
 def test_get_unbound_function():
@@ -337,7 +322,7 @@ def test_get_method_self():
             pass
     x = X()
     assert six.get_method_self(x.m) is x
-    py.test.raises(AttributeError, six.get_method_self, 42)
+    pytest.raises(AttributeError, six.get_method_self, 42)
 
 
 def test_get_method_function():
@@ -346,7 +331,7 @@ def test_get_method_function():
             pass
     x = X()
     assert six.get_method_function(x.m) is X.__dict__["m"]
-    py.test.raises(AttributeError, six.get_method_function, hasattr)
+    pytest.raises(AttributeError, six.get_method_function, hasattr)
 
 
 def test_get_function_closure():
@@ -364,7 +349,7 @@ def test_get_function_code():
         pass
     assert isinstance(six.get_function_code(f), types.CodeType)
     if not hasattr(sys, "pypy_version_info"):
-        py.test.raises(AttributeError, six.get_function_code, hasattr)
+        pytest.raises(AttributeError, six.get_function_code, hasattr)
 
 
 def test_get_function_defaults():
@@ -404,7 +389,7 @@ def test_dictionary_iterators(monkeypatch):
         it = meth(d)
         assert not isinstance(it, list)
         assert list(it) == list(getattr(d, name)())
-        py.test.raises(StopIteration, six.advance_iterator, it)
+        pytest.raises(StopIteration, six.advance_iterator, it)
         record = []
         def with_kw(*args, **kw):
             record.append(kw["kw"])
@@ -416,17 +401,7 @@ def test_dictionary_iterators(monkeypatch):
         monkeypatch.undo()
 
 
-@py.test.mark.skipif("sys.version_info[:2] < (2, 7)",
-                reason="view methods on dictionaries only available on 2.7+")
 def test_dictionary_views():
-    def stock_method_name(viewwhat):
-        """Given a method suffix like "keys" or "values", return the name
-        of the dict method that delivers those on the version of Python
-        we're running in."""
-        if six.PY3:
-            return viewwhat
-        return 'view' + viewwhat
-
     d = dict(zip(range(10), (range(11, 20))))
     for name in "keys", "values", "items":
         meth = getattr(six, "view" + name)
@@ -440,8 +415,8 @@ def test_advance_iterator():
     it = iter(l)
     assert six.next(it) == 1
     assert six.next(it) == 2
-    py.test.raises(StopIteration, six.next, it)
-    py.test.raises(StopIteration, six.next, it)
+    pytest.raises(StopIteration, six.next, it)
+    pytest.raises(StopIteration, six.next, it)
 
 
 def test_iterator():
@@ -489,7 +464,7 @@ def test_create_unbound_method():
     def f(self):
         return self
     u = six.create_unbound_method(f, X)
-    py.test.raises(TypeError, u)
+    pytest.raises(TypeError, u)
     if six.PY2:
         assert isinstance(u, types.MethodType)
     x = X()
@@ -537,13 +512,13 @@ def test_unichr():
 
 def test_int2byte():
     assert six.int2byte(3) == six.b("\x03")
-    py.test.raises(Exception, six.int2byte, 256)
+    pytest.raises(Exception, six.int2byte, 256)
 
 
 def test_byte2int():
     assert six.byte2int(six.b("\x03")) == 3
     assert six.byte2int(six.b("\x03\x04")) == 3
-    py.test.raises(IndexError, six.byte2int, six.b(""))
+    pytest.raises(IndexError, six.byte2int, six.b(""))
 
 
 def test_bytesindex():
@@ -554,7 +529,7 @@ def test_bytesiter():
     it = six.iterbytes(six.b("hi"))
     assert six.next(it) == ord("h")
     assert six.next(it) == ord("i")
-    py.test.raises(StopIteration, six.next, it)
+    pytest.raises(StopIteration, six.next, it)
 
 
 def test_StringIO():
@@ -643,7 +618,6 @@ def test_raise_from():
         # We should have done a raise f from None equivalent.
         assert val.__cause__ is None
         assert val.__context__ is ctx
-    if sys.version_info[:2] >= (3, 3):
         # And that should suppress the context on the exception.
         assert val.__suppress_context__
     # For all versions the outer exception should have raised successfully.
@@ -689,28 +663,10 @@ def test_print_():
     assert out.flushed
 
 
-@py.test.mark.skipif("sys.version_info[:2] >= (2, 6)")
-def test_print_encoding(monkeypatch):
-    # Fool the type checking in print_.
-    monkeypatch.setattr(six, "file", six.BytesIO, raising=False)
-    out = six.BytesIO()
-    out.encoding = "utf-8"
-    out.errors = None
-    six.print_(six.u("\u053c"), end="", file=out)
-    assert out.getvalue() == six.b("\xd4\xbc")
-    out = six.BytesIO()
-    out.encoding = "ascii"
-    out.errors = "strict"
-    py.test.raises(UnicodeEncodeError, six.print_, six.u("\u053c"), file=out)
-    out.errors = "backslashreplace"
-    six.print_(six.u("\u053c"), end="", file=out)
-    assert out.getvalue() == six.b("\\u053c")
-
-
 def test_print_exceptions():
-    py.test.raises(TypeError, six.print_, x=3)
-    py.test.raises(TypeError, six.print_, end=3)
-    py.test.raises(TypeError, six.print_, sep=42)
+    pytest.raises(TypeError, six.print_, x=3)
+    pytest.raises(TypeError, six.print_, end=3)
+    pytest.raises(TypeError, six.print_, sep=42)
 
 
 def test_with_metaclass():
@@ -744,7 +700,53 @@ def test_with_metaclass():
     assert Y.__mro__ == (Y, X, object)
 
 
-@py.test.mark.skipif("sys.version_info[:2] < (3, 0)")
+def test_with_metaclass_typing():
+    try:
+        import typing
+    except ImportError:
+        pytest.skip("typing module required")
+    class Meta(type):
+        pass
+    if sys.version_info[:2] < (3, 7):
+        # Generics with custom metaclasses were broken on older versions.
+        class Meta(Meta, typing.GenericMeta):
+            pass
+    T = typing.TypeVar('T')
+    class G(six.with_metaclass(Meta, typing.Generic[T])):
+        pass
+    class GA(six.with_metaclass(abc.ABCMeta, typing.Generic[T])):
+        pass
+    assert isinstance(G, Meta)
+    assert isinstance(GA, abc.ABCMeta)
+    assert G[int] is not G[G[int]]
+    assert GA[int] is not GA[GA[int]]
+    assert G.__bases__ == (typing.Generic,)
+    assert G.__orig_bases__ == (typing.Generic[T],)
+
+
+@pytest.mark.skipif("sys.version_info[:2] < (3, 7)")
+def test_with_metaclass_pep_560():
+    class Meta(type):
+        pass
+    class A:
+        pass
+    class B:
+        pass
+    class Fake:
+        def __mro_entries__(self, bases):
+            return (A, B)
+    fake = Fake()
+    class G(six.with_metaclass(Meta, fake)):
+        pass
+    class GA(six.with_metaclass(abc.ABCMeta, fake)):
+        pass
+    assert isinstance(G, Meta)
+    assert isinstance(GA, abc.ABCMeta)
+    assert G.__bases__ == (A, B)
+    assert G.__orig_bases__ == (fake,)
+
+
+@pytest.mark.skipif("sys.version_info[:2] < (3, 0)")
 def test_with_metaclass_prepare():
     """Test that with_metaclass causes Meta.__prepare__ to be called with the correct arguments."""
 
@@ -792,14 +794,33 @@ def test_wraps():
     def f(g, assign, update):
         def w():
             return 42
-        w.glue = {"foo" : "bar"}
+        w.glue = {"foo": "bar"}
+        w.xyzzy = {"qux": "quux"}
         return six.wraps(g, assign, update)(w)
-    k.glue = {"melon" : "egg"}
+    k.glue = {"melon": "egg"}
     k.turnip = 43
-    k = f(k, ["turnip"], ["glue"])
+    k = f(k, ["turnip", "baz"], ["glue", "xyzzy"])
     assert k.__name__ == "w"
     assert k.turnip == 43
-    assert k.glue == {"melon" : "egg", "foo" : "bar"}
+    assert not hasattr(k, "baz")
+    assert k.glue == {"melon": "egg", "foo": "bar"}
+    assert k.xyzzy == {"qux": "quux"}
+
+
+def test_wraps_raises_on_missing_updated_field_on_wrapper():
+    """Ensure six.wraps doesn't ignore missing attrs wrapper.
+
+    Because that's what happens in Py3's functools.update_wrapper.
+    """
+    def wrapped():
+        pass
+
+    def wrapper():
+        pass
+
+    with pytest.raises(AttributeError, match='has no attribute.*xyzzy'):
+        six.wraps(wrapped, [], ['xyzzy'])(wrapper)
+
 
 
 def test_add_metaclass():
@@ -857,7 +878,7 @@ def test_add_metaclass():
     assert MySlots.__slots__ == ["a", "b"]
     instance = MySlots()
     instance.a = "foo"
-    py.test.raises(AttributeError, setattr, instance, "c", "baz")
+    pytest.raises(AttributeError, setattr, instance, "c", "baz")
 
     # Test a class with string for slots.
     class MyStringSlots(object):
@@ -866,8 +887,8 @@ def test_add_metaclass():
     assert MyStringSlots.__slots__ == "ab"
     instance = MyStringSlots()
     instance.ab = "foo"
-    py.test.raises(AttributeError, setattr, instance, "a", "baz")
-    py.test.raises(AttributeError, setattr, instance, "b", "baz")
+    pytest.raises(AttributeError, setattr, instance, "a", "baz")
+    pytest.raises(AttributeError, setattr, instance, "b", "baz")
 
     class MySlotsWeakref(object):
         __slots__ = "__weakref__",
@@ -875,7 +896,26 @@ def test_add_metaclass():
     assert type(MySlotsWeakref) is Meta
 
 
-@py.test.mark.skipif("sys.version_info[:2] < (2, 7) or sys.version_info[:2] in ((3, 0), (3, 1))")
+@pytest.mark.skipif("sys.version_info[:2] < (3, 3)")
+def test_add_metaclass_nested():
+    # Regression test for https://github.com/benjaminp/six/issues/259
+    class Meta(type):
+        pass
+
+    class A:
+        class B: pass
+
+    expected = 'test_add_metaclass_nested.<locals>.A.B'
+
+    assert A.B.__qualname__ == expected
+
+    class A:
+        @six.add_metaclass(Meta)
+        class B: pass
+
+    assert A.B.__qualname__ == expected
+
+
 def test_assertCountEqual():
     class TestAssertCountEqual(unittest.TestCase):
         def test(self):
@@ -887,7 +927,6 @@ def test_assertCountEqual():
     TestAssertCountEqual('test').test()
 
 
-@py.test.mark.skipif("sys.version_info[:2] < (2, 7)")
 def test_assertRegex():
     class TestAssertRegex(unittest.TestCase):
         def test(self):
@@ -899,7 +938,17 @@ def test_assertRegex():
     TestAssertRegex('test').test()
 
 
-@py.test.mark.skipif("sys.version_info[:2] < (2, 7)")
+def test_assertNotRegex():
+    class TestAssertNotRegex(unittest.TestCase):
+        def test(self):
+            with self.assertRaises(AssertionError):
+                six.assertNotRegex(self, 'test', r'^t')
+
+            six.assertNotRegex(self, 'test', r'^a')
+
+    TestAssertNotRegex('test').test()
+
+
 def test_assertRaisesRegex():
     class TestAssertRaisesRegex(unittest.TestCase):
         def test(self):
@@ -932,3 +981,61 @@ def test_python_2_unicode_compatible():
         assert str(my_test) == six.u("hello")
 
     assert getattr(six.moves.builtins, 'bytes', str)(my_test) == six.b("hello")
+
+
+class EnsureTests:
+
+    # grinning face emoji
+    UNICODE_EMOJI = six.u("\U0001F600")
+    BINARY_EMOJI = b"\xf0\x9f\x98\x80"
+
+    def test_ensure_binary_raise_type_error(self):
+        with pytest.raises(TypeError):
+            six.ensure_str(8)
+
+    def test_errors_and_encoding(self):
+        six.ensure_binary(self.UNICODE_EMOJI, encoding='latin-1', errors='ignore')
+        with pytest.raises(UnicodeEncodeError):
+            six.ensure_binary(self.UNICODE_EMOJI, encoding='latin-1', errors='strict')
+
+    def test_ensure_binary_raise(self):
+        converted_unicode = six.ensure_binary(self.UNICODE_EMOJI, encoding='utf-8', errors='strict')
+        converted_binary = six.ensure_binary(self.BINARY_EMOJI, encoding="utf-8", errors='strict')
+        if six.PY2:
+            # PY2: unicode -> str
+            assert converted_unicode == self.BINARY_EMOJI and isinstance(converted_unicode, str)
+            # PY2: str -> str
+            assert converted_binary == self.BINARY_EMOJI and isinstance(converted_binary, str)
+        else:
+            # PY3: str -> bytes
+            assert converted_unicode == self.BINARY_EMOJI and isinstance(converted_unicode, bytes)
+            # PY3: bytes -> bytes
+            assert converted_binary == self.BINARY_EMOJI and isinstance(converted_binary, bytes)
+
+    def test_ensure_str(self):
+        converted_unicode = six.ensure_str(self.UNICODE_EMOJI, encoding='utf-8', errors='strict')
+        converted_binary = six.ensure_str(self.BINARY_EMOJI, encoding="utf-8", errors='strict')
+        if six.PY2:
+            # PY2: unicode -> str
+            assert converted_unicode == self.BINARY_EMOJI and isinstance(converted_unicode, str)
+            # PY2: str -> str
+            assert converted_binary == self.BINARY_EMOJI and isinstance(converted_binary, str)
+        else:
+            # PY3: str -> str
+            assert converted_unicode == self.UNICODE_EMOJI and isinstance(converted_unicode, str)
+            # PY3: bytes -> str
+            assert converted_binary == self.UNICODE_EMOJI and isinstance(converted_unicode, str)
+
+    def test_ensure_text(self):
+        converted_unicode = six.ensure_text(self.UNICODE_EMOJI, encoding='utf-8', errors='strict')
+        converted_binary = six.ensure_text(self.BINARY_EMOJI, encoding="utf-8", errors='strict')
+        if six.PY2:
+            # PY2: unicode -> unicode
+            assert converted_unicode == self.UNICODE_EMOJI and isinstance(converted_unicode, unicode)
+            # PY2: str -> unicode
+            assert converted_binary == self.UNICODE_EMOJI and isinstance(converted_unicode, unicode)
+        else:
+            # PY3: str -> str
+            assert converted_unicode == self.UNICODE_EMOJI and isinstance(converted_unicode, str)
+            # PY3: bytes -> str
+            assert converted_binary == self.UNICODE_EMOJI and isinstance(converted_unicode, str)
diff --git a/tox.ini b/tox.ini
new file mode 100644
index 0000000..a1e3467
--- /dev/null
+++ b/tox.ini
@@ -0,0 +1,11 @@
+[tox]
+envlist=py27,py33,py34,py35,py36,py37,py38,pypy,flake8
+
+[testenv]
+deps= pytest
+commands= python -m pytest -rfsxX {posargs}
+
+[testenv:flake8]
+basepython=python
+deps=flake8
+commands= flake8 six.py
```

