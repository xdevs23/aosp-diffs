```diff
diff --git a/.circleci/config.yml b/.circleci/config.yml
index e135408..c038660 100644
--- a/.circleci/config.yml
+++ b/.circleci/config.yml
@@ -1,31 +1,24 @@
 version: 2
 jobs:
-  py26:
-    macos:
-      # macOS 10.12, last version with Python 2.6
-      xcode: 9.0.1
+  python2.7:
+    machine:
+      image: ubuntu-2004:202101-01
+    resource_class: arm.medium
     steps:
       - checkout
-      - run: /usr/bin/python2.6 run.py deps
-      - run: /usr/bin/python2.6 run.py ci
-  pypy:
-    macos:
-      # macOS 10.14.4
-      xcode: 10.3.0
+      - run: python run.py deps
+      - run: python run.py ci-driver
+  python3.9:
+    machine:
+      image: ubuntu-2004:202101-01
+    resource_class: arm.medium
     steps:
       - checkout
-      - run: curl --location -O https://bitbucket.org/pypy/pypy/downloads/pypy2.7-v7.3.1-osx64.tar.bz2
-      - run: tar xvf pypy2.7-v7.3.1-osx64.tar.bz2
-      - run: mv pypy2.7-v7.3.1-osx64 pypy
-      - run: xattr -rc pypy
-      - run: ./pypy/bin/pypy -m ensurepip
-      - run: ./pypy/bin/pypy run.py deps
-      - run: ./pypy/bin/pypy run.py ci
+      - run: python run.py deps
+      - run: python3 run.py ci-driver
 workflows:
   version: 2
-  python-26:
+  arm64:
     jobs:
-      - py26
-  python-pypy:
-    jobs:
-      - pypy
+      - python2.7
+      - python3.9
diff --git a/.github/FUNDING.yml b/.github/FUNDING.yml
new file mode 100644
index 0000000..61bcab9
--- /dev/null
+++ b/.github/FUNDING.yml
@@ -0,0 +1,4 @@
+# These are supported funding model platforms
+
+github: wbond
+tidelift: "pypi/asn1crypto"
diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
index e91e6d6..46804fe 100644
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -2,54 +2,205 @@ name: CI
 on: [push, pull_request]
 
 jobs:
-  build:
-    name: Python ${{ matrix.python }} on ${{ matrix.os }} ${{ matrix.arch }}
-    runs-on: ${{ matrix.os }}
+  build-windows:
+    name: Python ${{ matrix.python }} on windows-2019 ${{ matrix.arch }}
+    runs-on: windows-2019
     strategy:
       matrix:
-        os:
-          - ubuntu-18.04
-          - macOS-latest
-          - windows-2019
         python:
           - '2.7'
-          - '3.7'
+          - '3.9'
+          # - 'pypy-3.7-v7.3.5'
         arch:
           - 'x86'
           - 'x64'
         exclude:
-          - os: ubuntu-18.04
-            arch: x86
-          - os: macOS-latest
+          - python: 'pypy-3.7-v7.3.5'
             arch: x86
     steps:
       - uses: actions/checkout@master
-      - uses: actions/setup-python@v1
+      - uses: actions/setup-python@v2
         with:
           python-version: ${{ matrix.python }}
           architecture: ${{ matrix.arch }}
       - name: Install dependencies
         run: python run.py deps
       - name: Run test suite
-        run: python run.py ci
-        env:
-          OSCRYPTO_USE_CTYPES: 'true'
+        run: python run.py ci-driver
+      - name: Run test suite (Windows legacy API)
+        run: python run.py ci-driver winlegacy
+
+  build-windows-old:
+    name: Python ${{ matrix.python }} on windows-2019 ${{ matrix.arch }}
+    runs-on: windows-2019
+    strategy:
+      matrix:
+        python:
+          - '2.6'
+          - '3.3'
+        arch:
+          - 'x86'
+          - 'x64'
+    steps:
+      - uses: actions/checkout@master
+
+      - name: Cache Python
+        id: cache-python
+        uses: actions/cache@v2
+        with:
+          path: ~/AppData/Local/Python${{ matrix.python }}-${{ matrix.arch }}
+          key: windows-2019-python-${{ matrix.python }}-${{ matrix.arch }}
+
+      - name: Install Python ${{ matrix.python }}
+        run: python run.py python-install ${{ matrix.python }} ${{ matrix.arch }} | Out-File -FilePath $env:GITHUB_PATH -Encoding utf8 -Append
+
+      - name: Install dependencies
+        run: python run.py deps
+      - name: Run test suite
+        run: python run.py ci-driver
+      - name: Run test suite (Windows legacy API)
+        run: python run.py ci-driver winlegacy
+
+  build-mac:
+    name: Python ${{ matrix.python }} on macos-10.15
+    runs-on: macos-10.15
+    strategy:
+      matrix:
+        python:
+          - '2.7'
+          - '3.9'
+          # - 'pypy-3.7-v7.3.5'
+    steps:
+      - uses: actions/checkout@master
+      - uses: actions/setup-python@v2
+        with:
+          python-version: ${{ matrix.python }}
+          architecture: x64
+      - name: Install dependencies
+        run: python run.py deps
+      - name: Run test suite
+        run: python run.py ci-driver
       - name: Run test suite (Mac cffi)
-        run: python run.py ci
-        if: runner.os == 'macOS'
+        run: python run.py ci-driver cffi
       - name: Run test suite (Mac OpenSSL)
-        run: python run.py ci
-        if: runner.os == 'macOS'
-        env:
-          OSCRYPTO_USE_OPENSSL: /usr/lib/libcrypto.dylib,/usr/lib/libssl.dylib
-          OSCRYPTO_USE_CTYPES: 'true'
+        run: python run.py ci-driver openssl
+        if: ${{ matrix.python }} != 'pypy-3.7-v7.3.5'
       - name: Run test suite (Mac OpenSSL/cffi)
-        run: python run.py ci
-        if: runner.os == 'macOS'
-        env:
-          OSCRYPTO_USE_OPENSSL: /usr/lib/libcrypto.dylib,/usr/lib/libssl.dylib
-      - name: Run test suite (Windows legacy API)
-        run: python run.py ci
-        if: runner.os == 'Windows'
-        env:
-          OSCRYPTO_USE_WINLEGACY: 'true'
+        run: python run.py ci-driver cffi openssl
+        if: ${{ matrix.python }} != 'pypy-3.7-v7.3.5'
+
+  build-mac-old:
+    name: Python ${{ matrix.python }} on macos-10.15
+    runs-on: macos-10.15
+    strategy:
+      matrix:
+        python:
+          - '2.6'
+          - '3.3'
+    steps:
+      - uses: actions/checkout@master
+
+      - name: Check pyenv
+        id: check-pyenv
+        uses: actions/cache@v2
+        with:
+          path: ~/.pyenv
+          key: macos-10.15-${{ matrix.python }}-pyenv
+
+      - name: Install Python ${{ matrix.python }}
+        run: python run.py pyenv-install ${{ matrix.python }} >> $GITHUB_PATH
+
+      - name: Install dependencies
+        run: python run.py deps
+      - name: Run test suite
+        run: python run.py ci-driver
+      - name: Run test suite (Mac cffi)
+        run: python run.py ci-driver cffi
+      - name: Run test suite (Mac OpenSSL)
+        run: python run.py ci-driver openssl
+      - name: Run test suite (Mac OpenSSL/cffi)
+        run: python run.py ci-driver cffi openssl
+
+  build-ubuntu:
+    name: Python ${{ matrix.python }} on ubuntu-18.04 x64
+    runs-on: ubuntu-18.04
+    strategy:
+      matrix:
+        python:
+          - '2.7'
+          - '3.6'
+          - '3.9'
+          - '3.10'
+          - 'pypy-3.7-v7.3.5'
+    steps:
+      - uses: actions/checkout@master
+      - uses: actions/setup-python@v2
+        with:
+          python-version: ${{ matrix.python }}
+          architecture: x64
+      - name: Install dependencies
+        run: python run.py deps
+      - name: Run test suite
+        run: python run.py ci-driver
+
+  build-ubuntu-old:
+    name: Python ${{ matrix.python }} on ubuntu-18.04 x64
+    runs-on: ubuntu-18.04
+    strategy:
+      matrix:
+        python:
+          - '2.6'
+          - '3.2'
+          - '3.3'
+    steps:
+      - uses: actions/checkout@master
+      - name: Setup deadsnakes/ppa
+        run: sudo apt-add-repository ppa:deadsnakes/ppa
+      - name: Update apt
+        run: sudo apt-get update
+      - name: Install Python ${{matrix.python}}
+        run: sudo apt-get install python${{matrix.python}}
+      - name: Install dependencies
+        run: python${{matrix.python}} run.py deps
+      - name: Run test suite
+        run: python${{matrix.python}} run.py ci-driver
+
+  build-arm:
+    name: Python 2.7/3.8 on arm
+    runs-on: [self-hosted, linux, ARM]
+    steps:
+      - uses: actions/checkout@master
+      - name: Install dependencies (2.7)
+        run: python2 run.py deps
+      - name: Run test suite (2.7)
+        run: python2 run.py ci-driver
+      - name: Cleanup deps (2.7)
+        if: always()
+        run: python2 run.py ci-cleanup
+      - name: Install dependencies (3.8)
+        run: python3 run.py deps
+      - name: Run test suite (3.8)
+        run: python3 run.py ci-driver
+      - name: Cleanup deps (3.8)
+        if: always()
+        run: python3 run.py ci-cleanup
+
+  build-arm64:
+    name: Python 2.7/3.8 on arm64
+    runs-on: [self-hosted, linux, ARM64]
+    steps:
+      - uses: actions/checkout@master
+      - name: Install dependencies (2.7)
+        run: python2 run.py deps
+      - name: Run test suite (2.7)
+        run: python2 run.py ci-driver
+      - name: Cleanup deps (2.7)
+        if: always()
+        run: python2 run.py ci-cleanup
+      - name: Install dependencies (3.8)
+        run: python3 run.py deps
+      - name: Run test suite (3.8)
+        run: python3 run.py ci-driver
+      - name: Cleanup deps (3.8)
+        if: always()
+        run: python3 run.py ci-cleanup
diff --git a/.travis.yml b/.travis.yml
deleted file mode 100644
index eb0ca1a..0000000
--- a/.travis.yml
+++ /dev/null
@@ -1,44 +0,0 @@
-sudo: false
-language: c
-branches:
-  except:
-    - /^[0-9]+\.[0-9]+\.[0-9]$/
-matrix:
-  include:
-    - os: linux
-      dist: trusty
-      language: python
-      python: "2.6"
-    - os: linux
-      dist: bionic
-      language: python
-      python: "2.7"
-    - os: linux
-      dist: trusty
-      language: python
-      python: "3.2"
-    - os: linux
-      dist: trusty
-      language: python
-      python: "3.3"
-    - os: linux
-      dist: bionic
-      language: python
-      python: "3.7"
-    - os: linux
-      arch: arm64
-      dist: bionic
-      language: python
-      python: "3.7"
-    - os: linux
-      arch: ppc64le
-      dist: bionic
-      language: python
-      python: "3.7"
-    - os: linux
-      dist: xenial
-      language: python
-      python: "pypy"
-script:
-  - python run.py deps
-  - python run.py ci
diff --git a/LICENSE b/LICENSE
index 8038d9a..07b49ae 100644
--- a/LICENSE
+++ b/LICENSE
@@ -1,4 +1,4 @@
-Copyright (c) 2015-2019 Will Bond <will@wbond.net>
+Copyright (c) 2015-2022 Will Bond <will@wbond.net>
 
 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
diff --git a/METADATA b/METADATA
index 02bee43..ad949ee 100644
--- a/METADATA
+++ b/METADATA
@@ -1,19 +1,20 @@
+# This project was upgraded with external_updater.
+# Usage: tools/external_updater/updater.sh update external/python/asn1crypto
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
+
 name: "asn1crypto"
 description: "A fast, pure Python library for parsing and serializing ASN.1 structures."
 third_party {
-  url {
-    type: HOMEPAGE
-    value: "https://github.com/wbond/asn1crypto"
-  }
-  url {
-    type: GIT
-    value: "https://github.com/wbond/asn1crypto"
-  }
-  version: "1.4.0"
   license_type: NOTICE
   last_upgrade_date {
-    year: 2020
-    month: 10
-    day: 28
+    year: 2025
+    month: 1
+    day: 22
+  }
+  homepage: "https://github.com/wbond/asn1crypto"
+  identifier {
+    type: "Git"
+    value: "https://github.com/wbond/asn1crypto"
+    version: "1.5.1"
   }
 }
diff --git a/SECURITY.md b/SECURITY.md
new file mode 100644
index 0000000..07813d3
--- /dev/null
+++ b/SECURITY.md
@@ -0,0 +1,37 @@
+# Security Policy
+
+## How to Report
+
+If you believe you've found an issue that has security implications, please do
+not post a public issue on GitHub. Instead, email the project lead, Will Bond,
+at will@wbond.net.
+
+You should receive a response within two business days, and follow up emails
+during the process of confirming the potential issue.
+
+## Supported Versions
+
+The asn1crypto project only provides security patches for the most recent
+release. This is primarily a function of available resources.
+
+## Disclosure Process
+
+The following process is used when handling a potential secuirty issue:
+
+ 1. The report should be emailed to will@wbond.net, and NOT posted on the
+    GitHub issue tracker.
+ 2. Confirmation of receipt of the report should happen within two business
+    days.
+ 3. Information will be collected and an investigation will be performed to
+    determine if a security issue exists.
+ 4. If no security issue is found, the process will end.
+ 5. A fix for the issue and announcement will be drafted.
+ 6. A release schedule and accouncement will be negotiated between the
+    reporter and the project
+ 7. The security contacts for Arch Linux, Conda, Debian, Fedora, FreeBSD, 
+    Ubuntu, and Tidelift will be contacted to notify them of an upcoming
+    security release.
+ 8. Fixes for all vulnerabilities will be performed, and new releases made,
+    but without mention of a security issue. These changes and releases will
+    be published before the announcement.
+ 9. An announcement will be made disclosing the vulnerability and the fix.
diff --git a/appveyor.yml b/appveyor.yml
deleted file mode 100644
index 564a665..0000000
--- a/appveyor.yml
+++ /dev/null
@@ -1,34 +0,0 @@
-version: "{build}"
-skip_tags: true
-environment:
-  matrix:
-    - PYTHON_EXE: "C:\\Python26\\python.exe"
-    - PYTHON_EXE: "C:\\Python26-x64\\python.exe"
-    - PYTHON_EXE: "C:\\Python26-x64\\python.exe"
-      OSCRYPTO_USE_WINLEGACY: "true"
-    - PYTHON_EXE: "C:\\Python33\\python.exe"
-    - PYTHON_EXE: "C:\\Python33\\python.exe"
-      OSCRYPTO_USE_WINLEGACY: "true"
-    - PYTHON_EXE: "C:\\Python33-x64\\python.exe"
-    - PYTHON_EXE: "C:\\pypy2-v5.10.0-win32\\pypy.exe"
-    - PYTHON_EXE: "C:\\pypy2-v5.10.0-win32\\pypy.exe"
-      OSCRYPTO_USE_WINLEGACY: "true"
-install:
-  - ps: |-
-      $env:PYTMP = "${env:TMP}\py";
-      if (!(Test-Path "$env:PYTMP")) {
-        New-Item -ItemType directory -Path "$env:PYTMP" | Out-Null;
-      }
-      if ("${env:PYTHON_EXE}" -eq "C:\pypy2-v5.10.0-win32\pypy.exe") {
-        if (!(Test-Path "${env:PYTMP}\pypy2-v5.10.0-win32.zip")) {
-          (New-Object Net.WebClient).DownloadFile('https://bitbucket.org/pypy/pypy/downloads/pypy2-v5.10.0-win32.zip', "${env:PYTMP}\pypy2-v5.10.0-win32.zip");
-        }
-        7z x -y "${env:PYTMP}\pypy2-v5.10.0-win32.zip" -oC:\ | Out-Null;
-        & ${env:PYTHON_EXE} -m ensurepip --upgrade;
-      }
-cache:
-  - '%TMP%\py\'
-build: off
-test_script:
-  - cmd: "%PYTHON_EXE% run.py deps"
-  - cmd: "%PYTHON_EXE% run.py ci"
diff --git a/asn1crypto/algos.py b/asn1crypto/algos.py
index d49be26..cdd0020 100644
--- a/asn1crypto/algos.py
+++ b/asn1crypto/algos.py
@@ -260,6 +260,9 @@ class SignedDigestAlgorithmId(ObjectIdentifier):
         '1.2.840.113549.1.1.1': 'rsassa_pkcs1v15',
         '1.2.840.10040.4.1': 'dsa',
         '1.2.840.10045.4': 'ecdsa',
+        # RFC 8410 -- https://tools.ietf.org/html/rfc8410
+        '1.3.101.112': 'ed25519',
+        '1.3.101.113': 'ed448',
     }
 
     _reverse_map = {
@@ -286,6 +289,8 @@ class SignedDigestAlgorithmId(ObjectIdentifier):
         'sha3_256_ecdsa': '2.16.840.1.101.3.4.3.10',
         'sha3_384_ecdsa': '2.16.840.1.101.3.4.3.11',
         'sha3_512_ecdsa': '2.16.840.1.101.3.4.3.12',
+        'ed25519': '1.3.101.112',
+        'ed448': '1.3.101.113',
     }
 
 
@@ -304,8 +309,8 @@ class SignedDigestAlgorithm(_ForceNullParameters, Sequence):
     def signature_algo(self):
         """
         :return:
-            A unicode string of "rsassa_pkcs1v15", "rsassa_pss", "dsa" or
-            "ecdsa"
+            A unicode string of "rsassa_pkcs1v15", "rsassa_pss", "dsa",
+            "ecdsa", "ed25519" or "ed448"
         """
 
         algorithm = self['algorithm'].native
@@ -334,6 +339,8 @@ class SignedDigestAlgorithm(_ForceNullParameters, Sequence):
             'sha3_384_ecdsa': 'ecdsa',
             'sha3_512_ecdsa': 'ecdsa',
             'ecdsa': 'ecdsa',
+            'ed25519': 'ed25519',
+            'ed448': 'ed448',
         }
         if algorithm in algo_map:
             return algo_map[algorithm]
@@ -350,7 +357,7 @@ class SignedDigestAlgorithm(_ForceNullParameters, Sequence):
         """
         :return:
             A unicode string of "md2", "md5", "sha1", "sha224", "sha256",
-            "sha384", "sha512", "sha512_224", "sha512_256"
+            "sha384", "sha512", "sha512_224", "sha512_256" or "shake256"
         """
 
         algorithm = self['algorithm'].native
@@ -371,6 +378,8 @@ class SignedDigestAlgorithm(_ForceNullParameters, Sequence):
             'sha256_ecdsa': 'sha256',
             'sha384_ecdsa': 'sha384',
             'sha512_ecdsa': 'sha512',
+            'ed25519': 'sha512',
+            'ed448': 'shake256',
         }
         if algorithm in algo_map:
             return algo_map[algorithm]
@@ -874,8 +883,7 @@ class EncryptionAlgorithm(_ForceNullParameters, Sequence):
             return cipher_lengths[encryption_algo]
 
         if encryption_algo == 'rc2':
-            rc2_params = self['parameters'].parsed['encryption_scheme']['parameters'].parsed
-            rc2_parameter_version = rc2_params['rc2_parameter_version'].native
+            rc2_parameter_version = self['parameters']['rc2_parameter_version'].native
 
             # See page 24 of
             # http://www.emc.com/collateral/white-papers/h11302-pkcs5v2-1-password-based-cryptography-standard-wp.pdf
@@ -1042,7 +1050,7 @@ class EncryptionAlgorithm(_ForceNullParameters, Sequence):
             return cipher_map[encryption_algo]
 
         if encryption_algo == 'rc5':
-            return self['parameters'].parsed['block_size_in_bits'].native / 8
+            return self['parameters']['block_size_in_bits'].native // 8
 
         if encryption_algo == 'pbes2':
             return self['parameters']['encryption_scheme'].encryption_block_size
@@ -1084,7 +1092,7 @@ class EncryptionAlgorithm(_ForceNullParameters, Sequence):
         encryption_algo = self['algorithm'].native
 
         if encryption_algo in set(['rc2', 'rc5']):
-            return self['parameters'].parsed['iv'].native
+            return self['parameters']['iv'].native
 
         # For DES/Triple DES and AES the IV is the entirety of the parameters
         octet_string_iv_oids = set([
diff --git a/asn1crypto/cms.py b/asn1crypto/cms.py
index 2115aed..c395b22 100644
--- a/asn1crypto/cms.py
+++ b/asn1crypto/cms.py
@@ -30,6 +30,7 @@ from .algos import (
     _ForceNullParameters,
     DigestAlgorithm,
     EncryptionAlgorithm,
+    EncryptionAlgorithmId,
     HmacAlgorithm,
     KdfAlgorithm,
     RSAESOAEPParams,
@@ -100,6 +101,8 @@ class CMSAttributeType(ObjectIdentifier):
         '1.2.840.113549.1.9.4': 'message_digest',
         '1.2.840.113549.1.9.5': 'signing_time',
         '1.2.840.113549.1.9.6': 'counter_signature',
+        # https://datatracker.ietf.org/doc/html/rfc2633#section-2.5.2
+        '1.2.840.113549.1.9.15': 'smime_capabilities',
         # https://tools.ietf.org/html/rfc2633#page-26
         '1.2.840.113549.1.9.16.2.11': 'encrypt_key_pref',
         # https://tools.ietf.org/html/rfc3161#page-20
@@ -273,7 +276,7 @@ class V2Form(Sequence):
 class AttCertIssuer(Choice):
     _alternatives = [
         ('v1_form', GeneralNames),
-        ('v2_form', V2Form, {'explicit': 0}),
+        ('v2_form', V2Form, {'implicit': 0}),
     ]
 
 
@@ -315,7 +318,7 @@ class SetOfSvceAuthInfo(SetOf):
 class RoleSyntax(Sequence):
     _fields = [
         ('role_authority', GeneralNames, {'implicit': 0, 'optional': True}),
-        ('role_name', GeneralName, {'implicit': 1}),
+        ('role_name', GeneralName, {'explicit': 1}),
     ]
 
 
@@ -337,7 +340,7 @@ class ClassList(BitString):
 class SecurityCategory(Sequence):
     _fields = [
         ('type', ObjectIdentifier, {'implicit': 0}),
-        ('value', Any, {'implicit': 1}),
+        ('value', Any, {'explicit': 1}),
     ]
 
 
@@ -347,9 +350,9 @@ class SetOfSecurityCategory(SetOf):
 
 class Clearance(Sequence):
     _fields = [
-        ('policy_id', ObjectIdentifier, {'implicit': 0}),
-        ('class_list', ClassList, {'implicit': 1, 'default': 'unclassified'}),
-        ('security_categories', SetOfSecurityCategory, {'implicit': 2, 'optional': True}),
+        ('policy_id', ObjectIdentifier),
+        ('class_list', ClassList, {'default': set(['unclassified'])}),
+        ('security_categories', SetOfSecurityCategory, {'optional': True}),
     ]
 
 
@@ -946,6 +949,21 @@ class SMIMEEncryptionKeyPreferences(SetOf):
     _child_spec = SMIMEEncryptionKeyPreference
 
 
+class SMIMECapabilityIdentifier(Sequence):
+    _fields = [
+        ('capability_id', EncryptionAlgorithmId),
+        ('parameters', Any, {'optional': True}),
+    ]
+
+
+class SMIMECapabilites(SequenceOf):
+    _child_spec = SMIMECapabilityIdentifier
+
+
+class SetOfSMIMECapabilites(SetOf):
+    _child_spec = SMIMECapabilites
+
+
 ContentInfo._oid_specs = {
     'data': OctetString,
     'signed_data': SignedData,
@@ -981,4 +999,5 @@ CMSAttribute._oid_specs = {
     'microsoft_nested_signature': SetOfContentInfo,
     'microsoft_time_stamp_token': SetOfContentInfo,
     'encrypt_key_pref': SMIMEEncryptionKeyPreferences,
+    'smime_capabilities': SetOfSMIMECapabilites,
 }
diff --git a/asn1crypto/core.py b/asn1crypto/core.py
index 7133367..364c6b5 100644
--- a/asn1crypto/core.py
+++ b/asn1crypto/core.py
@@ -4113,6 +4113,10 @@ class Sequence(Asn1Value):
         if self._header is not None and self._header[-1:] == b'\x80':
             force = True
 
+        # We can't force encoding if we don't have a spec
+        if force and self._fields == [] and self.__class__ is Sequence:
+            force = False
+
         if force:
             self._set_contents(force=force)
 
diff --git a/asn1crypto/csr.py b/asn1crypto/csr.py
index 7ea2848..7d5ba44 100644
--- a/asn1crypto/csr.py
+++ b/asn1crypto/csr.py
@@ -4,7 +4,7 @@
 ASN.1 type classes for certificate signing requests (CSR). Exports the
 following items:
 
- - CertificatationRequest()
+ - CertificationRequest()
 
 Other type classes are defined that help compose the types listed above.
 """
@@ -14,11 +14,14 @@ from __future__ import unicode_literals, division, absolute_import, print_functi
 from .algos import SignedDigestAlgorithm
 from .core import (
     Any,
+    BitString,
+    BMPString,
     Integer,
     ObjectIdentifier,
     OctetBitString,
     Sequence,
     SetOf,
+    UTF8String
 )
 from .keys import PublicKeyInfo
 from .x509 import DirectoryString, Extensions, Name
@@ -39,6 +42,12 @@ class CSRAttributeType(ObjectIdentifier):
         '1.2.840.113549.1.9.7': 'challenge_password',
         '1.2.840.113549.1.9.9': 'extended_certificate_attributes',
         '1.2.840.113549.1.9.14': 'extension_request',
+        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/a5eaae36-e9f3-4dc5-a687-bfa7115954f1
+        '1.3.6.1.4.1.311.13.2.2': 'microsoft_enrollment_csp_provider',
+        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/7c677cba-030d-48be-ba2b-01e407705f34
+        '1.3.6.1.4.1.311.13.2.3': 'microsoft_os_version',
+        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/64e5ff6d-c6dd-4578-92f7-b3d895f9b9c7
+        '1.3.6.1.4.1.311.21.20': 'microsoft_request_client_info',
     }
 
 
@@ -61,6 +70,31 @@ class SetOfExtensions(SetOf):
     _child_spec = Extensions
 
 
+class MicrosoftEnrollmentCSProvider(Sequence):
+    _fields = [
+        ('keyspec', Integer),
+        ('cspname', BMPString),  # cryptographic service provider name
+        ('signature', BitString),
+    ]
+
+
+class SetOfMicrosoftEnrollmentCSProvider(SetOf):
+    _child_spec = MicrosoftEnrollmentCSProvider
+
+
+class MicrosoftRequestClientInfo(Sequence):
+    _fields = [
+        ('clientid', Integer),
+        ('machinename', UTF8String),
+        ('username', UTF8String),
+        ('processname', UTF8String),
+    ]
+
+
+class SetOfMicrosoftRequestClientInfo(SetOf):
+    _child_spec = MicrosoftRequestClientInfo
+
+
 class CRIAttribute(Sequence):
     _fields = [
         ('type', CSRAttributeType),
@@ -72,6 +106,9 @@ class CRIAttribute(Sequence):
         'challenge_password': SetOfDirectoryString,
         'extended_certificate_attributes': SetOfAttributes,
         'extension_request': SetOfExtensions,
+        'microsoft_enrollment_csp_provider': SetOfMicrosoftEnrollmentCSProvider,
+        'microsoft_os_version': SetOfDirectoryString,
+        'microsoft_request_client_info': SetOfMicrosoftRequestClientInfo,
     }
 
 
diff --git a/asn1crypto/keys.py b/asn1crypto/keys.py
index 96b763e..b4a87ae 100644
--- a/asn1crypto/keys.py
+++ b/asn1crypto/keys.py
@@ -666,6 +666,11 @@ class PrivateKeyAlgorithmId(ObjectIdentifier):
         '1.2.840.10040.4.1': 'dsa',
         # https://tools.ietf.org/html/rfc3279#page-13
         '1.2.840.10045.2.1': 'ec',
+        # https://tools.ietf.org/html/rfc8410#section-9
+        '1.3.101.110': 'x25519',
+        '1.3.101.111': 'x448',
+        '1.3.101.112': 'ed25519',
+        '1.3.101.113': 'ed448',
     }
 
 
@@ -707,6 +712,12 @@ class PrivateKeyInfo(Sequence):
             'rsassa_pss': RSAPrivateKey,
             'dsa': Integer,
             'ec': ECPrivateKey,
+            # These should be treated as opaque octet strings according
+            # to RFC 8410
+            'x25519': OctetString,
+            'x448': OctetString,
+            'ed25519': OctetString,
+            'ed448': OctetString,
         }[algorithm]
 
     _spec_callbacks = {
@@ -741,7 +752,7 @@ class PrivateKeyInfo(Sequence):
                 type_name(private_key)
             ))
 
-        if algorithm == 'rsa':
+        if algorithm == 'rsa' or algorithm == 'rsassa_pss':
             if not isinstance(private_key, RSAPrivateKey):
                 private_key = RSAPrivateKey.load(private_key)
             params = Null()
@@ -882,7 +893,7 @@ class PrivateKeyInfo(Sequence):
     def algorithm(self):
         """
         :return:
-            A unicode string of "rsa", "dsa" or "ec"
+            A unicode string of "rsa", "rsassa_pss", "dsa" or "ec"
         """
 
         if self._algorithm is None:
@@ -897,7 +908,7 @@ class PrivateKeyInfo(Sequence):
         """
 
         if self._bit_size is None:
-            if self.algorithm == 'rsa':
+            if self.algorithm == 'rsa' or self.algorithm == 'rsassa_pss':
                 prime = self['private_key'].parsed['modulus'].native
             elif self.algorithm == 'dsa':
                 prime = self['private_key_algorithm']['parameters']['p'].native
@@ -1017,6 +1028,11 @@ class PublicKeyAlgorithmId(ObjectIdentifier):
         '1.2.840.10045.2.1': 'ec',
         # https://tools.ietf.org/html/rfc3279#page-10
         '1.2.840.10046.2.1': 'dh',
+        # https://tools.ietf.org/html/rfc8410#section-9
+        '1.3.101.110': 'x25519',
+        '1.3.101.111': 'x448',
+        '1.3.101.112': 'ed25519',
+        '1.3.101.113': 'ed448',
     }
 
 
@@ -1063,6 +1079,12 @@ class PublicKeyInfo(Sequence):
             # decompose the byte string into the constituent X and Y coords
             'ec': (ECPointBitString, None),
             'dh': Integer,
+            # These should be treated as opaque bit strings according
+            # to RFC 8410, and need not even be valid ASN.1
+            'x25519': (OctetBitString, None),
+            'x448': (OctetBitString, None),
+            'ed25519': (OctetBitString, None),
+            'ed448': (OctetBitString, None),
         }[algorithm]
 
     _spec_callbacks = {
@@ -1098,7 +1120,7 @@ class PublicKeyInfo(Sequence):
                 type_name(public_key)
             ))
 
-        if algorithm != 'rsa':
+        if algorithm != 'rsa' and algorithm != 'rsassa_pss':
             raise ValueError(unwrap(
                 '''
                 algorithm must "rsa", not %s
@@ -1200,7 +1222,7 @@ class PublicKeyInfo(Sequence):
     def algorithm(self):
         """
         :return:
-            A unicode string of "rsa", "dsa" or "ec"
+            A unicode string of "rsa", "rsassa_pss", "dsa" or "ec"
         """
 
         if self._algorithm is None:
@@ -1218,7 +1240,7 @@ class PublicKeyInfo(Sequence):
             if self.algorithm == 'ec':
                 self._bit_size = int(((len(self['public_key'].native) - 1) / 2) * 8)
             else:
-                if self.algorithm == 'rsa':
+                if self.algorithm == 'rsa' or self.algorithm == 'rsassa_pss':
                     prime = self['public_key'].parsed['modulus'].native
                 elif self.algorithm == 'dsa':
                     prime = self['algorithm']['parameters']['p'].native
diff --git a/asn1crypto/parser.py b/asn1crypto/parser.py
index c4f91f6..2f5a63e 100644
--- a/asn1crypto/parser.py
+++ b/asn1crypto/parser.py
@@ -20,6 +20,7 @@ from .util import int_from_bytes, int_to_bytes
 
 _PY2 = sys.version_info <= (3,)
 _INSUFFICIENT_DATA_MESSAGE = 'Insufficient data - %s bytes requested but only %s available'
+_MAX_DEPTH = 10
 
 
 def emit(class_, method, tag, contents):
@@ -136,7 +137,7 @@ def peek(contents):
     return consumed
 
 
-def _parse(encoded_data, data_len, pointer=0, lengths_only=False):
+def _parse(encoded_data, data_len, pointer=0, lengths_only=False, depth=0):
     """
     Parses a byte string into component parts
 
@@ -154,83 +155,89 @@ def _parse(encoded_data, data_len, pointer=0, lengths_only=False):
         number of bytes in the header and the integer number of bytes in the
         contents. Internal use only.
 
+    :param depth:
+        The recursion depth when evaluating indefinite-length encoding.
+
     :return:
         A 2-element tuple:
          - 0: A tuple of (class_, method, tag, header, content, trailer)
          - 1: An integer indicating how many bytes were consumed
     """
 
-    if data_len < pointer + 2:
-        raise ValueError(_INSUFFICIENT_DATA_MESSAGE % (2, data_len - pointer))
+    if depth > _MAX_DEPTH:
+        raise ValueError('Indefinite-length recursion limit exceeded')
 
     start = pointer
+
+    if data_len < pointer + 1:
+        raise ValueError(_INSUFFICIENT_DATA_MESSAGE % (1, data_len - pointer))
     first_octet = ord(encoded_data[pointer]) if _PY2 else encoded_data[pointer]
+
     pointer += 1
 
     tag = first_octet & 31
+    constructed = (first_octet >> 5) & 1
     # Base 128 length using 8th bit as continuation indicator
     if tag == 31:
         tag = 0
         while True:
+            if data_len < pointer + 1:
+                raise ValueError(_INSUFFICIENT_DATA_MESSAGE % (1, data_len - pointer))
             num = ord(encoded_data[pointer]) if _PY2 else encoded_data[pointer]
             pointer += 1
+            if num == 0x80 and tag == 0:
+                raise ValueError('Non-minimal tag encoding')
             tag *= 128
             tag += num & 127
             if num >> 7 == 0:
                 break
+        if tag < 31:
+            raise ValueError('Non-minimal tag encoding')
 
+    if data_len < pointer + 1:
+        raise ValueError(_INSUFFICIENT_DATA_MESSAGE % (1, data_len - pointer))
     length_octet = ord(encoded_data[pointer]) if _PY2 else encoded_data[pointer]
     pointer += 1
+    trailer = b''
 
     if length_octet >> 7 == 0:
-        if lengths_only:
-            return (pointer, pointer + (length_octet & 127))
         contents_end = pointer + (length_octet & 127)
 
     else:
         length_octets = length_octet & 127
         if length_octets:
+            if data_len < pointer + length_octets:
+                raise ValueError(_INSUFFICIENT_DATA_MESSAGE % (length_octets, data_len - pointer))
             pointer += length_octets
             contents_end = pointer + int_from_bytes(encoded_data[pointer - length_octets:pointer], signed=False)
-            if lengths_only:
-                return (pointer, contents_end)
 
         else:
             # To properly parse indefinite length values, we need to scan forward
             # parsing headers until we find a value with a length of zero. If we
             # just scanned looking for \x00\x00, nested indefinite length values
             # would not work.
+            if not constructed:
+                raise ValueError('Indefinite-length element must be constructed')
             contents_end = pointer
-            while contents_end < data_len:
-                sub_header_end, contents_end = _parse(encoded_data, data_len, contents_end, lengths_only=True)
-                if contents_end == sub_header_end and encoded_data[contents_end - 2:contents_end] == b'\x00\x00':
-                    break
-            if lengths_only:
-                return (pointer, contents_end)
-            if contents_end > data_len:
-                raise ValueError(_INSUFFICIENT_DATA_MESSAGE % (contents_end, data_len))
-            return (
-                (
-                    first_octet >> 6,
-                    (first_octet >> 5) & 1,
-                    tag,
-                    encoded_data[start:pointer],
-                    encoded_data[pointer:contents_end - 2],
-                    b'\x00\x00'
-                ),
-                contents_end
-            )
+            while data_len < contents_end + 2 or encoded_data[contents_end:contents_end+2] != b'\x00\x00':
+                _, contents_end = _parse(encoded_data, data_len, contents_end, lengths_only=True, depth=depth+1)
+            contents_end += 2
+            trailer = b'\x00\x00'
 
     if contents_end > data_len:
-        raise ValueError(_INSUFFICIENT_DATA_MESSAGE % (contents_end, data_len))
+        raise ValueError(_INSUFFICIENT_DATA_MESSAGE % (contents_end - pointer, data_len - pointer))
+
+    if lengths_only:
+        return (pointer, contents_end)
+
     return (
         (
             first_octet >> 6,
-            (first_octet >> 5) & 1,
+            constructed,
             tag,
             encoded_data[start:pointer],
-            encoded_data[pointer:contents_end],
-            b''
+            encoded_data[pointer:contents_end-len(trailer)],
+            trailer
         ),
         contents_end
     )
diff --git a/asn1crypto/tsp.py b/asn1crypto/tsp.py
index bd40810..f006da9 100644
--- a/asn1crypto/tsp.py
+++ b/asn1crypto/tsp.py
@@ -169,7 +169,7 @@ class MetaData(Sequence):
     ]
 
 
-class TimeStampAndCRL(SequenceOf):
+class TimeStampAndCRL(Sequence):
     _fields = [
         ('time_stamp', EncapsulatedContentInfo),
         ('crl', CertificateList, {'optional': True}),
diff --git a/asn1crypto/version.py b/asn1crypto/version.py
index 3cf4892..966b57a 100644
--- a/asn1crypto/version.py
+++ b/asn1crypto/version.py
@@ -2,5 +2,5 @@
 from __future__ import unicode_literals, division, absolute_import, print_function
 
 
-__version__ = '1.4.0'
-__version_info__ = (1, 4, 0)
+__version__ = '1.5.1'
+__version_info__ = (1, 5, 1)
diff --git a/asn1crypto/x509.py b/asn1crypto/x509.py
index 16f7deb..8cfb2c7 100644
--- a/asn1crypto/x509.py
+++ b/asn1crypto/x509.py
@@ -987,7 +987,7 @@ class Name(Choice):
 
         :param name_dict:
             A dict of name information, e.g. {"common_name": "Will Bond",
-            "country_name": "US", "organization": "Codex Non Sufficit LC"}
+            "country_name": "US", "organization_name": "Codex Non Sufficit LC"}
 
         :param use_printable:
             A bool - if PrintableString should be used for encoding instead of
@@ -2079,6 +2079,8 @@ class ExtensionId(ObjectIdentifier):
         '2.16.840.1.113730.1.1': 'netscape_certificate_type',
         # https://tools.ietf.org/html/rfc6962.html#page-14
         '1.3.6.1.4.1.11129.2.4.2': 'signed_certificate_timestamp_list',
+        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/3aec3e50-511a-42f9-a5d5-240af503e470
+        '1.3.6.1.4.1.311.20.2': 'microsoft_enroll_certtype',
     }
 
 
@@ -2114,6 +2116,9 @@ class Extension(Sequence):
         'entrust_version_extension': EntrustVersionInfo,
         'netscape_certificate_type': NetscapeCertificateType,
         'signed_certificate_timestamp_list': OctetString,
+        # Not UTF8String as Microsofts docs claim, see:
+        # https://www.alvestrand.no/objectid/1.3.6.1.4.1.311.20.2.html
+        'microsoft_enroll_certtype': BMPString,
     }
 
 
diff --git a/changelog.md b/changelog.md
index 46eb459..70dcf49 100644
--- a/changelog.md
+++ b/changelog.md
@@ -1,5 +1,43 @@
 # changelog
 
+## 1.5.1
+
+ - Handle RSASSA-PSS in `keys.PrivateKeyInfo.bit_size` and
+   `keys.PublicKeyInfo.bit_size`
+ - Handle RSASSA-PSS in `keys.PrivateKeyInfo.wrap` and
+   `keys.PublicKeyInfo.wrap`
+ - Updated docs for `keys.PrivateKeyInfo.algorithm` and
+   `keys.PublicKeyInfo.algorithm` to reflect that they can return
+   `"rsassa_pss"`
+
+## 1.5.0
+
+ - Fix `tsp.TimeStampAndCRL` to be a `core.Sequence` instead of a
+   `core.SequenceOf` *via @joernheissler*
+ - Added OIDs for Edwards curves from RFC 8410 - via @MatthiasValvekens
+ - Fixed convenience attributes on `algos.EncryptionAlgorithm` when the
+   algorithm is RC2 *via @joernheissler*
+ - Added Microsoft OIDs `microsoft_enrollment_csp_provider`
+   (`1.3.6.1.4.1.311.13.2.2`), `microsoft_os_version`
+   (`1.3.6.1.4.1.311.13.2.3`) and `microsoft_request_client_info`
+   (`1.3.6.1.4.1.311.21.20`)
+   to `csr.CSRAttributeType` along with supporting extension structures
+   *via @qha*
+ - Added Microsoft OID `microsoft_enroll_certtype` (`1.3.6.1.4.1.311.20.2`)
+   to `x509.ExtensionId` *via @qha*
+ - Fixed a few bugs with parsing indefinite-length encodings *via @davidben*
+ - Added various bounds checks to parsing engine *via @davidben*
+ - Fixed a bug with tags not always being minimally encoded *via @davidben*
+ - Fixed `cms.RoleSyntax`, `cms.SecurityCategory` and `cms.AttCertIssuer` to
+   have explicit instead of implicit tagging *via @MatthiasValvekens*
+ - Fixed tagging of, and default value for fields in `cms.Clearance` *via
+   @MatthiasValvekens*
+ - Fixed calling `.dump(force=True)` when the value has undefined/unknown
+   `core.Sequence` fields. Previously the value would be truncated, now
+   the existing encoding is preserved.
+ - Added sMIME capabilities (`1.2.840.113549.1.9.15`) support from RFC 2633
+   to `cms.CMSAttribute` *via Hellzed*
+
 ## 1.4.0
 
  - `core.ObjectIdentifier` and all derived classes now obey X.660 Â§7.6 and
diff --git a/dev/_pep425.py b/dev/_pep425.py
index 949686a..9591b47 100644
--- a/dev/_pep425.py
+++ b/dev/_pep425.py
@@ -166,12 +166,13 @@ def _pep425tags():
         if sys.platform == 'win32':
             if 'amd64' in sys.version.lower():
                 arches = ['win_amd64']
-            arches = [sys.platform]
+            else:
+                arches = [sys.platform]
         elif hasattr(os, 'uname'):
             (plat, _, _, _, machine) = os.uname()
             plat = plat.lower().replace('/', '')
             machine.replace(' ', '_').replace('/', '_')
-            if plat == 'linux' and sys.maxsize == 2147483647:
+            if plat == 'linux' and sys.maxsize == 2147483647 and 'arm' not in machine:
                 machine = 'i686'
             arch = '%s_%s' % (plat, machine)
             if _pep425_supports_manylinux():
diff --git a/dev/ci-cleanup.py b/dev/ci-cleanup.py
new file mode 100644
index 0000000..92ca6da
--- /dev/null
+++ b/dev/ci-cleanup.py
@@ -0,0 +1,28 @@
+# coding: utf-8
+from __future__ import unicode_literals, division, absolute_import, print_function
+
+import os
+import shutil
+
+from . import build_root, other_packages
+
+
+def run():
+    """
+    Cleans up CI dependencies - used for persistent GitHub Actions
+    Runners since they don't clean themselves up.
+    """
+
+    print("Removing ci dependencies")
+    deps_dir = os.path.join(build_root, 'modularcrypto-deps')
+    if os.path.exists(deps_dir):
+        shutil.rmtree(deps_dir, ignore_errors=True)
+
+    print("Removing modularcrypto packages")
+    for other_package in other_packages:
+        pkg_dir = os.path.join(build_root, other_package)
+        if os.path.exists(pkg_dir):
+            shutil.rmtree(pkg_dir, ignore_errors=True)
+    print()
+
+    return True
diff --git a/dev/ci-driver.py b/dev/ci-driver.py
new file mode 100644
index 0000000..af9d7e4
--- /dev/null
+++ b/dev/ci-driver.py
@@ -0,0 +1,73 @@
+# coding: utf-8
+from __future__ import unicode_literals, division, absolute_import, print_function
+
+import os
+import platform
+import sys
+import subprocess
+
+
+run_args = [
+    {
+        'name': 'cffi',
+        'kwarg': 'cffi',
+    },
+    {
+        'name': 'openssl',
+        'kwarg': 'openssl',
+    },
+    {
+        'name': 'winlegacy',
+        'kwarg': 'winlegacy',
+    },
+]
+
+
+def _write_env(env, key, value):
+    sys.stdout.write("%s: %s\n" % (key, value))
+    sys.stdout.flush()
+    if sys.version_info < (3,):
+        env[key.encode('utf-8')] = value.encode('utf-8')
+    else:
+        env[key] = value
+
+
+def run(**_):
+    """
+    Runs CI, setting various env vars
+
+    :return:
+        A bool - if the CI ran successfully
+    """
+
+    env = os.environ.copy()
+    options = set(sys.argv[2:])
+
+    newline = False
+    if 'cffi' not in options:
+        _write_env(env, 'OSCRYPTO_USE_CTYPES', 'true')
+        newline = True
+    if 'openssl' in options and sys.platform == 'darwin':
+        mac_version_info = tuple(map(int, platform.mac_ver()[0].split('.')[:2]))
+        if mac_version_info < (10, 15):
+            _write_env(env, 'OSCRYPTO_USE_OPENSSL', '/usr/lib/libcrypto.dylib,/usr/lib/libssl.dylib')
+        else:
+            _write_env(env, 'OSCRYPTO_USE_OPENSSL', '/usr/lib/libcrypto.35.dylib,/usr/lib/libssl.35.dylib')
+        newline = True
+    if 'winlegacy' in options:
+        _write_env(env, 'OSCRYPTO_USE_WINLEGACY', 'true')
+        newline = True
+
+    if newline:
+        sys.stdout.write("\n")
+
+    proc = subprocess.Popen(
+        [
+            sys.executable,
+            'run.py',
+            'ci',
+        ],
+        env=env
+    )
+    proc.communicate()
+    return proc.returncode == 0
diff --git a/dev/ci.py b/dev/ci.py
index 59dd073..946d5b8 100644
--- a/dev/ci.py
+++ b/dev/ci.py
@@ -20,6 +20,7 @@ else:
 
 if sys.version_info[0:2] != (3, 2):
     from .coverage import run as run_coverage
+    from .coverage import coverage
     run_tests = None
 
 else:
@@ -44,7 +45,7 @@ def run():
         lint_result = True
 
     if run_coverage:
-        print('\nRunning tests (via coverage.py)')
+        print('\nRunning tests (via coverage.py %s)' % coverage.__version__)
         sys.stdout.flush()
         tests_result = run_coverage(ci=True)
     else:
diff --git a/codecov.json b/dev/codecov.json
similarity index 100%
rename from codecov.json
rename to dev/codecov.json
diff --git a/dev/coverage.py b/dev/coverage.py
index eb03b53..bb99a4f 100644
--- a/dev/coverage.py
+++ b/dev/coverage.py
@@ -136,7 +136,7 @@ def _codecov_submit():
     env_name, root = _env_info()
 
     try:
-        with open(os.path.join(root, 'codecov.json'), 'rb') as f:
+        with open(os.path.join(root, 'dev/codecov.json'), 'rb') as f:
             json_data = json.loads(f.read().decode('utf-8'))
     except (OSError, ValueError, UnicodeDecodeError, KeyError):
         print('error reading codecov.json')
@@ -566,6 +566,8 @@ def _do_request(method, url, headers, data=None, query_params=None, timeout=20):
         else:
             args = [
                 'curl',
+                '--http1.1',
+                '--connect-timeout', '5',
                 '--request',
                 method,
                 '--location',
@@ -584,7 +586,7 @@ def _do_request(method, url, headers, data=None, query_params=None, timeout=20):
             stdout, stderr = _execute(
                 args,
                 os.getcwd(),
-                re.compile(r'Failed to connect to|TLS|SSLRead|outstanding|cleanly'),
+                re.compile(r'Failed to connect to|TLS|SSLRead|outstanding|cleanly|timed out'),
                 6
             )
     finally:
@@ -626,7 +628,7 @@ def _do_request(method, url, headers, data=None, query_params=None, timeout=20):
     return (content_type, encoding, body)
 
 
-def _execute(params, cwd, retry=None, retries=0):
+def _execute(params, cwd, retry=None, retries=0, backoff=2):
     """
     Executes a subprocess
 
@@ -659,11 +661,11 @@ def _execute(params, cwd, retry=None, retries=0):
             stderr_str = stderr.decode('utf-8')
             if isinstance(retry, Pattern):
                 if retry.search(stderr_str) is not None:
-                    time.sleep(5)
-                    return _execute(params, cwd, retry, retries - 1)
+                    time.sleep(backoff)
+                    return _execute(params, cwd, retry, retries - 1, backoff * 2)
             elif retry in stderr_str:
-                time.sleep(5)
-                return _execute(params, cwd, retry, retries - 1)
+                time.sleep(backoff)
+                return _execute(params, cwd, retry, retries - 1, backoff * 2)
         e = OSError('subprocess exit code for "%s" was %d: %s' % (' '.join(params), code, stderr))
         e.stdout = stdout
         e.stderr = stderr
diff --git a/dev/deps.py b/dev/deps.py
index 8f52336..9f558a1 100644
--- a/dev/deps.py
+++ b/dev/deps.py
@@ -361,6 +361,14 @@ def _extract_package(deps_dir, pkg_path, pkg_dir):
         root = os.path.abspath(os.path.join(deps_dir, '..'))
         install_lib = os.path.basename(deps_dir)
 
+        # Ensure we pick up previously installed packages when running
+        # setup.py. This is important for things like setuptools.
+        env = os.environ.copy()
+        if sys.version_info >= (3,):
+            env['PYTHONPATH'] = deps_dir
+        else:
+            env[b'PYTHONPATH'] = deps_dir.encode('utf-8')
+
         _execute(
             [
                 sys.executable,
@@ -370,7 +378,8 @@ def _extract_package(deps_dir, pkg_path, pkg_dir):
                 '--install-lib=%s' % install_lib,
                 '--no-compile'
             ],
-            setup_dir
+            setup_dir,
+            env=env
         )
 
     finally:
@@ -629,7 +638,17 @@ def _parse_requires(path):
             package = package.strip()
             cond = cond.strip()
             cond = cond.replace('sys_platform', repr(sys_platform))
-            cond = cond.replace('python_version', repr(python_version))
+            cond = re.sub(
+                r'[\'"]'
+                r'(\d+(?:\.\d+)*)'
+                r'([-._]?(?:alpha|a|beta|b|preview|pre|c|rc)\.?\d*)?'
+                r'(-\d+|(?:[-._]?(?:rev|r|post)\.?\d*))?'
+                r'([-._]?dev\.?\d*)?'
+                r'[\'"]',
+                r'_tuple_from_ver(\g<0>)',
+                cond
+            )
+            cond = cond.replace('python_version', '_tuple_from_ver(%r)' % python_version)
             if not eval(cond):
                 continue
         else:
@@ -667,7 +686,7 @@ def _parse_requires(path):
     return packages
 
 
-def _execute(params, cwd, retry=None):
+def _execute(params, cwd, retry=None, env=None):
     """
     Executes a subprocess
 
@@ -688,7 +707,8 @@ def _execute(params, cwd, retry=None):
         params,
         stdout=subprocess.PIPE,
         stderr=subprocess.PIPE,
-        cwd=cwd
+        cwd=cwd,
+        env=env
     )
     stdout, stderr = proc.communicate()
     code = proc.wait()
diff --git a/dev/pyenv-install.py b/dev/pyenv-install.py
new file mode 100644
index 0000000..f43d6de
--- /dev/null
+++ b/dev/pyenv-install.py
@@ -0,0 +1,144 @@
+# coding: utf-8
+from __future__ import unicode_literals, division, absolute_import, print_function
+
+import os
+import subprocess
+import sys
+
+
+run_args = [
+    {
+        'name': 'version',
+        'kwarg': 'version',
+    },
+]
+
+
+def _write_env(env, key, value):
+    sys.stdout.write("%s: %s\n" % (key, value))
+    sys.stdout.flush()
+    if sys.version_info < (3,):
+        env[key.encode('utf-8')] = value.encode('utf-8')
+    else:
+        env[key] = value
+
+
+def run(version=None):
+    """
+    Installs a version of Python on Mac using pyenv
+
+    :return:
+        A bool - if Python was installed successfully
+    """
+
+    if sys.platform == 'win32':
+        raise ValueError('pyenv-install is not designed for Windows')
+
+    if version not in set(['2.6', '3.3']):
+        raise ValueError('Invalid version: %r' % version)
+
+    python_path = os.path.expanduser('~/.pyenv/versions/%s/bin' % version)
+    if os.path.exists(os.path.join(python_path, 'python')):
+        print(python_path)
+        return True
+
+    stdout = ""
+    stderr = ""
+
+    proc = subprocess.Popen(
+        'command -v pyenv',
+        shell=True,
+        stdout=subprocess.PIPE,
+        stderr=subprocess.PIPE
+    )
+    proc.communicate()
+    if proc.returncode != 0:
+        proc = subprocess.Popen(
+            ['brew', 'install', 'pyenv'],
+            stdout=subprocess.PIPE,
+            stderr=subprocess.PIPE
+        )
+        so, se = proc.communicate()
+        stdout += so.decode('utf-8')
+        stderr += se.decode('utf-8')
+        if proc.returncode != 0:
+            print(stdout)
+            print(stderr, file=sys.stderr)
+            return False
+
+    pyenv_script = './%s' % version
+    try:
+        with open(pyenv_script, 'wb') as f:
+            if version == '2.6':
+                contents = '#require_gcc\n' \
+                    'install_package "openssl-1.0.2k" "https://www.openssl.org/source/old/1.0.2/openssl-1.0.2k.tar.gz' \
+                    '#6b3977c61f2aedf0f96367dcfb5c6e578cf37e7b8d913b4ecb6643c3cb88d8c0" mac_openssl\n' \
+                    'install_package "readline-8.0" "https://ftpmirror.gnu.org/readline/readline-8.0.tar.gz' \
+                    '#e339f51971478d369f8a053a330a190781acb9864cf4c541060f12078948e461" mac_readline' \
+                    ' --if has_broken_mac_readline\n' \
+                    'install_package "Python-2.6.9" "https://www.python.org/ftp/python/2.6.9/Python-2.6.9.tgz' \
+                    '#7277b1285d8a82f374ef6ebaac85b003266f7939b3f2a24a3af52f9523ac94db" standard verify_py26'
+            elif version == '3.3':
+                contents = '#require_gcc\n' \
+                    'install_package "openssl-1.0.2k" "https://www.openssl.org/source/old/1.0.2/openssl-1.0.2k.tar.gz' \
+                    '#6b3977c61f2aedf0f96367dcfb5c6e578cf37e7b8d913b4ecb6643c3cb88d8c0" mac_openssl\n' \
+                    'install_package "readline-8.0" "https://ftpmirror.gnu.org/readline/readline-8.0.tar.gz' \
+                    '#e339f51971478d369f8a053a330a190781acb9864cf4c541060f12078948e461" mac_readline' \
+                    ' --if has_broken_mac_readline\n' \
+                    'install_package "Python-3.3.7" "https://www.python.org/ftp/python/3.3.7/Python-3.3.7.tar.xz' \
+                    '#85f60c327501c36bc18c33370c14d472801e6af2f901dafbba056f61685429fe" standard verify_py33'
+            f.write(contents.encode('utf-8'))
+
+        args = ['pyenv', 'install', pyenv_script]
+        stdin = None
+        stdin_contents = None
+        env = os.environ.copy()
+
+        if version == '2.6':
+            _write_env(env, 'PYTHON_CONFIGURE_OPTS', '--enable-ipv6')
+            stdin = subprocess.PIPE
+            stdin_contents = '--- configure  2021-08-05 20:17:26.000000000 -0400\n' \
+                '+++ configure   2021-08-05 20:21:30.000000000 -0400\n' \
+                '@@ -10300,17 +10300,8 @@\n' \
+                ' rm -f core conftest.err conftest.$ac_objext \\\n' \
+                '     conftest$ac_exeext conftest.$ac_ext\n' \
+                ' \n' \
+                '-if test "$buggygetaddrinfo" = "yes"; then\n' \
+                '-\tif test "$ipv6" = "yes"; then\n' \
+                '-\t\techo \'Fatal: You must get working getaddrinfo() function.\'\n' \
+                '-\t\techo \'       or you can specify "--disable-ipv6"\'.\n' \
+                '-\t\texit 1\n' \
+                '-\tfi\n' \
+                '-else\n' \
+                '-\n' \
+                ' $as_echo "#define HAVE_GETADDRINFO 1" >>confdefs.h\n' \
+                ' \n' \
+                '-fi\n' \
+                ' for ac_func in getnameinfo\n' \
+                ' do :\n' \
+                '   ac_fn_c_check_func "$LINENO" "getnameinfo" "ac_cv_func_getnameinfo"'
+            stdin_contents = stdin_contents.encode('ascii')
+            args.append('--patch')
+
+        proc = subprocess.Popen(
+            args,
+            stdout=subprocess.PIPE,
+            stderr=subprocess.PIPE,
+            stdin=stdin,
+            env=env
+        )
+        so, se = proc.communicate(stdin_contents)
+        stdout += so.decode('utf-8')
+        stderr += se.decode('utf-8')
+
+        if proc.returncode != 0:
+            print(stdout)
+            print(stderr, file=sys.stderr)
+            return False
+
+    finally:
+        if os.path.exists(pyenv_script):
+            os.unlink(pyenv_script)
+
+    print(python_path)
+    return True
diff --git a/dev/python-install.py b/dev/python-install.py
new file mode 100644
index 0000000..99302ae
--- /dev/null
+++ b/dev/python-install.py
@@ -0,0 +1,77 @@
+# coding: utf-8
+from __future__ import unicode_literals, division, absolute_import, print_function
+
+import os
+import shutil
+import subprocess
+import sys
+from urllib.parse import urlparse
+from urllib.request import urlopen
+
+
+run_args = [
+    {
+        'name': 'version',
+        'kwarg': 'version',
+    },
+    {
+        'name': 'arch',
+        'kwarg': 'arch',
+    },
+]
+
+
+def run(version=None, arch=None):
+    """
+    Installs a version of Python on Windows
+
+    :return:
+        A bool - if Python was installed successfully
+    """
+
+    if sys.platform != 'win32':
+        raise ValueError('python-install is only designed for Windows')
+
+    if version not in set(['2.6', '3.3']):
+        raise ValueError('Invalid version: %r' % version)
+
+    if arch not in set(['x86', 'x64']):
+        raise ValueError('Invalid arch: %r' % arch)
+
+    if version == '2.6':
+        if arch == 'x64':
+            url = 'https://www.python.org/ftp/python/2.6.6/python-2.6.6.amd64.msi'
+        else:
+            url = 'https://www.python.org/ftp/python/2.6.6/python-2.6.6.msi'
+    else:
+        if arch == 'x64':
+            url = 'https://www.python.org/ftp/python/3.3.5/python-3.3.5.amd64.msi'
+        else:
+            url = 'https://www.python.org/ftp/python/3.3.5/python-3.3.5.msi'
+
+    home = os.environ.get('USERPROFILE')
+    msi_filename = os.path.basename(urlparse(url).path)
+    msi_path = os.path.join(home, msi_filename)
+    install_path = os.path.join(os.environ.get('LOCALAPPDATA'), 'Python%s-%s' % (version, arch))
+
+    if os.path.exists(os.path.join(install_path, 'python.exe')):
+        print(install_path)
+        return True
+
+    try:
+        with urlopen(url) as r, open(msi_path, 'wb') as f:
+            shutil.copyfileobj(r, f)
+
+        proc = subprocess.Popen(
+            'msiexec /passive /a %s TARGETDIR=%s' % (msi_filename, install_path),
+            shell=True,
+            cwd=home
+        )
+        proc.communicate()
+
+    finally:
+        if os.path.exists(msi_path):
+            os.unlink(msi_path)
+
+    print(install_path)
+    return True
diff --git a/docs/universal_types.md b/docs/universal_types.md
index 048a135..7dd65d0 100644
--- a/docs/universal_types.md
+++ b/docs/universal_types.md
@@ -100,10 +100,10 @@ re-interpreted.
 ```python
 from asn1crypto.core import BitString, OctetBitString, IntegerBitString
 
-bit = BitString({
+bit = BitString((
     0, 0, 0, 0, 0, 0, 0, 1,
     0, 0, 0, 0, 0, 0, 1, 0,
-})
+))
 
 # Will print (0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0)
 print(bit.native)
diff --git a/readme.md b/readme.md
index 62c070e..4f1061f 100644
--- a/readme.md
+++ b/readme.md
@@ -9,6 +9,7 @@ A fast, pure Python library for parsing and serializing ASN.1 structures.
  - [Dependencies](#dependencies)
  - [Installation](#installation)
  - [License](#license)
+ - [Security Policy](#security-policy)
  - [Documentation](#documentation)
  - [Continuous Integration](#continuous-integration)
  - [Testing](#testing)
@@ -16,8 +17,6 @@ A fast, pure Python library for parsing and serializing ASN.1 structures.
  - [CI Tasks](#ci-tasks)
 
 [![GitHub Actions CI](https://github.com/wbond/asn1crypto/workflows/CI/badge.svg)](https://github.com/wbond/asn1crypto/actions?workflow=CI)
-[![Travis CI](https://api.travis-ci.org/wbond/asn1crypto.svg?branch=master)](https://travis-ci.org/wbond/asn1crypto)
-[![AppVeyor](https://ci.appveyor.com/api/projects/status/github/wbond/asn1crypto?branch=master&svg=true)](https://ci.appveyor.com/project/wbond/asn1crypto)
 [![CircleCI](https://circleci.com/gh/wbond/asn1crypto.svg?style=shield)](https://circleci.com/gh/wbond/asn1crypto)
 [![PyPI](https://img.shields.io/pypi/v/asn1crypto.svg)](https://pypi.org/project/asn1crypto/)
 
@@ -111,11 +110,11 @@ faster to an order of magnitude or more.
 
 ## Current Release
 
-1.4.0 - [changelog](changelog.md)
+1.5.0 - [changelog](changelog.md)
 
 ## Dependencies
 
-Python 2.6, 2.7, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8 or pypy. *No third-party
+Python 2.6, 2.7, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 3.10 or pypy. *No third-party
 packages required.*
 
 ## Installation
@@ -129,6 +128,11 @@ pip install asn1crypto
 *asn1crypto* is licensed under the terms of the MIT license. See the
 [LICENSE](LICENSE) file for the exact license text.
 
+## Security Policy
+
+The security policies for this project are covered in
+[SECURITY.md](https://github.com/wbond/asn1crypto/blob/master/SECURITY.md).
+
 ## Documentation
 
 The documentation for *asn1crypto* is composed of tutorials on basic usage and
@@ -157,10 +161,8 @@ links to the source for the various pre-defined type classes.
 
 Various combinations of platforms and versions of Python are tested via:
 
- - [AppVeyor](https://ci.appveyor.com/project/wbond/asn1crypto/history)
- - [CircleCI](https://circleci.com/gh/wbond/asn1crypto)
- - [GitHub Actions](https://github.com/wbond/asn1crypto/actions)
- - [Travis CI](https://travis-ci.org/wbond/asn1crypto/builds)
+ - [macOS, Linux, Windows](https://github.com/wbond/asn1crypto/actions/workflows/ci.yml) via GitHub Actions
+ - [arm64](https://circleci.com/gh/wbond/asn1crypto) via CircleCI
 
 ## Testing
 
diff --git a/requires/coverage b/requires/coverage
index 39126eb..52ac529 100644
--- a/requires/coverage
+++ b/requires/coverage
@@ -1,2 +1,5 @@
+setuptools == 39.2.0 ; python_version == '3.3'
 coverage == 4.4.1 ; python_version == '2.6'
-coverage == 4.5.4 ; python_version != '3.2' and python_version != '2.6'
+coverage == 4.2 ; python_version == '3.3' and sys_platform == "win32"
+coverage == 4.5.4 ; (python_version == '3.3' and sys_platform != "win32") or python_version == '3.4'
+coverage == 5.5 ; python_version == '2.7' or python_version >= '3.5'
diff --git a/setup.py b/setup.py
index 991eb59..cb9bfab 100644
--- a/setup.py
+++ b/setup.py
@@ -10,7 +10,7 @@ from setuptools.command.egg_info import egg_info
 
 
 PACKAGE_NAME = 'asn1crypto'
-PACKAGE_VERSION = '1.4.0'
+PACKAGE_VERSION = '1.5.1'
 PACKAGE_ROOT = os.path.dirname(os.path.abspath(__file__))
 
 
@@ -137,6 +137,8 @@ setup(
         'Programming Language :: Python :: 3.6',
         'Programming Language :: Python :: 3.7',
         'Programming Language :: Python :: 3.8',
+        'Programming Language :: Python :: 3.9',
+        'Programming Language :: Python :: 3.10',
         'Programming Language :: Python :: Implementation :: CPython',
         'Programming Language :: Python :: Implementation :: PyPy',
 
diff --git a/tests/__init__.py b/tests/__init__.py
index 3b87410..8863093 100644
--- a/tests/__init__.py
+++ b/tests/__init__.py
@@ -6,8 +6,8 @@ import os
 import unittest
 
 
-__version__ = '1.4.0'
-__version_info__ = (1, 4, 0)
+__version__ = '1.5.1'
+__version_info__ = (1, 5, 1)
 
 
 def _import_from(mod, path, mod_dir=None):
diff --git a/tests/fixtures/example-attr-cert.der b/tests/fixtures/example-attr-cert.der
new file mode 100644
index 0000000..a89e8e2
Binary files /dev/null and b/tests/fixtures/example-attr-cert.der differ
diff --git a/tests/fixtures/keys/test-ed25519.crt b/tests/fixtures/keys/test-ed25519.crt
new file mode 100644
index 0000000..94006ff
Binary files /dev/null and b/tests/fixtures/keys/test-ed25519.crt differ
diff --git a/tests/fixtures/keys/test-ed25519.key b/tests/fixtures/keys/test-ed25519.key
new file mode 100644
index 0000000..6620d80
Binary files /dev/null and b/tests/fixtures/keys/test-ed25519.key differ
diff --git a/tests/fixtures/keys/test-ed448.crt b/tests/fixtures/keys/test-ed448.crt
new file mode 100644
index 0000000..bd7409b
Binary files /dev/null and b/tests/fixtures/keys/test-ed448.crt differ
diff --git a/tests/fixtures/keys/test-ed448.key b/tests/fixtures/keys/test-ed448.key
new file mode 100644
index 0000000..72c933a
Binary files /dev/null and b/tests/fixtures/keys/test-ed448.key differ
diff --git a/tests/fixtures/rc2_algo.der b/tests/fixtures/rc2_algo.der
new file mode 100644
index 0000000..444f698
--- /dev/null
+++ b/tests/fixtures/rc2_algo.der
@@ -0,0 +1 @@
+0*†H†÷0:QñÞÃÀlèï
\ No newline at end of file
diff --git a/tests/fixtures/rc5_algo.der b/tests/fixtures/rc5_algo.der
new file mode 100644
index 0000000..9eb3f80
Binary files /dev/null and b/tests/fixtures/rc5_algo.der differ
diff --git a/tests/fixtures/smime-signature-generated-by-thunderbird.p7s b/tests/fixtures/smime-signature-generated-by-thunderbird.p7s
new file mode 100644
index 0000000..c75b2a9
Binary files /dev/null and b/tests/fixtures/smime-signature-generated-by-thunderbird.p7s differ
diff --git a/tests/fixtures/test-windows-host.csr b/tests/fixtures/test-windows-host.csr
new file mode 100644
index 0000000..1ec8b51
Binary files /dev/null and b/tests/fixtures/test-windows-host.csr differ
diff --git a/tests/setup.py b/tests/setup.py
index 94aa438..cf4c5e2 100644
--- a/tests/setup.py
+++ b/tests/setup.py
@@ -10,7 +10,7 @@ from setuptools.command.egg_info import egg_info
 
 
 PACKAGE_NAME = 'asn1crypto'
-PACKAGE_VERSION = '1.4.0'
+PACKAGE_VERSION = '1.5.1'
 TEST_PACKAGE_NAME = '%s_tests' % PACKAGE_NAME
 TESTS_ROOT = os.path.dirname(os.path.abspath(__file__))
 
diff --git a/tests/test_algos.py b/tests/test_algos.py
index 37b2d15..931e1f8 100644
--- a/tests/test_algos.py
+++ b/tests/test_algos.py
@@ -42,3 +42,24 @@ class AlgoTests(unittest.TestCase):
         self.assertEqual(scheme['parameters']['aes_nonce'].native, b'z\xb7\xbd\xb7\xe1\xc6\xc0\x11\xc1?\xf00')
         self.assertEqual(scheme['parameters']['aes_icvlen'].__class__, core.Integer)
         self.assertEqual(scheme['parameters']['aes_icvlen'].native, 8)
+
+    def test_rc2_parameters(self):
+        with open(os.path.join(fixtures_dir, 'rc2_algo.der'), 'rb') as f:
+            algo = algos.EncryptionAlgorithm.load(f.read())
+        self.assertEqual(algo.encryption_block_size, 8)
+        self.assertEqual(algo.encryption_iv, b'Q\xf1\xde\xc3\xc0l\xe8\xef')
+        self.assertEqual(algo.encryption_cipher, 'rc2')
+        self.assertEqual(algo.encryption_mode, 'cbc')
+        self.assertEqual(algo.key_length, 16)
+
+    def test_rc5_parameters(self):
+        with open(os.path.join(fixtures_dir, 'rc5_algo.der'), 'rb') as f:
+            algo = algos.EncryptionAlgorithm.load(f.read())
+        self.assertEqual(algo.encryption_block_size, 16)
+        self.assertEqual(algo.encryption_iv, b'abcd\0\1\2\3')
+        self.assertEqual(algo.encryption_cipher, 'rc5')
+        self.assertEqual(algo.encryption_mode, 'cbc')
+
+        params = algo["parameters"]
+        self.assertEqual(params["version"].native, 'v1-0')
+        self.assertEqual(params["rounds"].native, 42)
diff --git a/tests/test_cms.py b/tests/test_cms.py
index 2afd7ca..8f9b1e6 100644
--- a/tests/test_cms.py
+++ b/tests/test_cms.py
@@ -21,6 +21,30 @@ tests_root = os.path.dirname(__file__)
 fixtures_dir = os.path.join(tests_root, 'fixtures')
 
 
+class ClearanceTests(unittest.TestCase):
+
+    def test_clearance_decode_bad_tagging(self):
+        rfc_3281_wrong_tagging = b'\x30\x08\x80\x02\x88\x37\x81\x02\x02\x4c'
+        # This test documents the fact that we can't deal with the "wrong"
+        # version of Clearance in RFC 3281
+        self.assertRaises(
+            ValueError,
+            lambda: cms.Clearance.load(rfc_3281_wrong_tagging).native
+        )
+
+    def test_clearance_decode_correct_tagging(self):
+        correct_tagging = b'\x30\x08\x06\x02\x88\x37\x03\x02\x02\x4c'
+        clearance_obj = cms.Clearance.load(correct_tagging)
+        self.assertEqual(
+            util.OrderedDict([
+                ('policy_id', '2.999'),
+                ('class_list', set(['secret', 'top_secret', 'unclassified'])),
+                ('security_categories', None)
+            ]),
+            clearance_obj.native
+        )
+
+
 class CMSTests(unittest.TestCase):
 
     def test_create_content_info_data(self):
@@ -887,6 +911,60 @@ class CMSTests(unittest.TestCase):
             signer['signature'].native
         )
 
+    def test_parse_content_info_smime_capabilities(self):
+        with open(os.path.join(fixtures_dir, 'smime-signature-generated-by-thunderbird.p7s'), 'rb') as f:
+            info = cms.ContentInfo.load(f.read())
+
+        signed_attrs = info['content']['signer_infos'][0]['signed_attrs']
+
+        self.assertEqual(
+            'smime_capabilities',
+            signed_attrs[3]['type'].native
+        )
+        smime_capabilities = signed_attrs[3]
+
+        self.assertEqual(
+            1,
+            len(smime_capabilities['values'])
+        )
+        self.assertEqual(
+            7,
+            len(smime_capabilities['values'][0])
+        )
+        self.assertEqual(
+            [capability.native for capability in smime_capabilities['values'][0]],
+            [
+                util.OrderedDict([
+                    ('capability_id', 'aes256_cbc'),
+                    ('parameters', None),
+                ]),
+                util.OrderedDict([
+                    ('capability_id', 'aes128_cbc'),
+                    ('parameters', None),
+                ]),
+                util.OrderedDict([
+                    ('capability_id', 'tripledes_3key'),
+                    ('parameters', None),
+                ]),
+                util.OrderedDict([
+                    ('capability_id', 'rc2'),
+                    ('parameters', 128),
+                ]),
+                util.OrderedDict([
+                    ('capability_id', 'rc2'),
+                    ('parameters', 64),
+                ]),
+                util.OrderedDict([
+                    ('capability_id', 'des'),
+                    ('parameters', None),
+                ]),
+                util.OrderedDict([
+                    ('capability_id', 'rc2'),
+                    ('parameters', 40),
+                ]),
+            ]
+        )
+
     def test_bad_teletex_inside_pkcs7(self):
         with open(os.path.join(fixtures_dir, 'mozilla-generated-by-openssl.pkcs7.der'), 'rb') as f:
             content = cms.ContentInfo.load(f.read())['content']
@@ -901,3 +979,25 @@ class CMSTests(unittest.TestCase):
             ]),
             content['certificates'][0].chosen['tbs_certificate']['subject'].native
         )
+
+    def test_parse_attribute_cert(self):
+        # regression test for tagging issue in AttCertIssuer
+
+        with open(os.path.join(fixtures_dir, 'example-attr-cert.der'), 'rb') as f:
+            ac_bytes = f.read()
+        ac_parsed = cms.AttributeCertificateV2.load(ac_bytes)
+        self.assertEqual(ac_bytes, ac_parsed.dump(force=True))
+
+        ac_info = ac_parsed['ac_info']
+        self.assertIsInstance(ac_info['issuer'].chosen, cms.V2Form)
+        self.assertEqual(1, len(ac_info['issuer'].chosen['issuer_name']))
+
+    def test_create_role_syntax(self):
+        rs = cms.RoleSyntax({'role_name': {'rfc822_name': 'test@example.com'}})
+        self.assertEqual(
+            util.OrderedDict([
+                ('role_authority', None),
+                ('role_name', 'test@example.com')
+            ]),
+            rs.native
+        )
diff --git a/tests/test_core.py b/tests/test_core.py
index 9821c63..7ac9196 100644
--- a/tests/test_core.py
+++ b/tests/test_core.py
@@ -978,6 +978,18 @@ class CoreTests(unittest.TestCase):
         st = SetTest({'two': 2, 'one': 1})
         self.assertEqual(b'1\x06\x81\x01\x01\x82\x01\x02', st.dump())
 
+    def test_force_dump_unknown_sequence(self):
+        seq = Seq({
+            'id': '1.2.3',
+            'value': 1
+        })
+        der = seq.dump(force=True)
+        # Ensure we don't erase the contents of a sequence we don't know
+        # the fields for when force re-encoding
+        unknown_seq = core.Sequence.load(der)
+        unknown_der = unknown_seq.dump(force=True)
+        self.assertEqual(der, unknown_der)
+
     def test_dump_set_of(self):
         st = SetOfTest([3, 2, 1])
         self.assertEqual(b'1\x09\x02\x01\x01\x02\x01\x02\x02\x01\x03', st.dump())
diff --git a/tests/test_csr.py b/tests/test_csr.py
index b950971..785c015 100644
--- a/tests/test_csr.py
+++ b/tests/test_csr.py
@@ -139,3 +139,114 @@ class CSRTests(unittest.TestCase):
             ],
             cri['attributes'].native
         )
+
+    def test_parse_csr3(self):
+        with open(os.path.join(fixtures_dir, 'test-windows-host.csr'), 'rb') as f:
+            certification_request = csr.CertificationRequest.load(f.read())
+
+        cri = certification_request['certification_request_info']
+
+        self.assertEqual(
+            'v1',
+            cri['version'].native
+        )
+
+        self.assertEqual(
+            util.OrderedDict([
+                ('common_name', 'windows.host.example.net'),
+            ]),
+            cri['subject'].native
+        )
+        self.assertEqual(
+            util.OrderedDict([
+                ('algorithm', 'rsa'),
+                ('parameters', None),
+            ]),
+            cri['subject_pk_info']['algorithm'].native
+        )
+        self.assertEqual(
+            0x00bd5b280774e2e64a2c022abd50de7817aaec50367e94b9c6459ca876daaf3bc3d7ffc41bf902422ac9af7d369eeb23245c5d8e2dda5434463f1d3e596c066a3cbe936bd89b4b7b9923ff6e654608cd3aa1fbc36543165752dde12c889c7aee4b5423e311e507bfd9fa60166290ae766005209120b651c3cdeceabba90b115341d656cb1fe94f372ba7c170bd15261685e92303205a7e5141928415f748d77ee4c6ecf8749b80c07d99f99f9aff629be62840e43e4696d6602df2a7a5e1bf11925021f2df2f4d27ef42e4decb0dc615c29eecaca628721a0c3c70c2700b7c658d6b7b7b6285593fd7d5ae086447bdc30429c7231db6b831d44e4c019887542f5f,  # noqa
+            cri['subject_pk_info']['public_key'].parsed['modulus'].native
+        )
+        self.assertEqual(
+            65537,
+            cri['subject_pk_info']['public_key'].parsed['public_exponent'].native
+        )
+        self.assertEqual(
+            [
+                util.OrderedDict([
+                    ('type', 'microsoft_os_version'),
+                    ('values', ['6.2.9200.2']),
+                ]),
+                util.OrderedDict([
+                    ('type', 'microsoft_request_client_info'),
+                    (
+                        'values',
+                        [
+                            util.OrderedDict([
+                                ('clientid', 5),
+                                ('machinename', 'windows.host.example.net'),
+                                ('username', 'locuser'),
+                                ('processname', 'MMC.EXE'),
+                            ])
+                        ])
+                    ]
+                ),
+                util.OrderedDict([
+                    ('type', 'microsoft_enrollment_csp_provider'),
+                    (
+                        'values',
+                        [
+                            util.OrderedDict([
+                                ('keyspec', 1),
+                                ('cspname', 'Microsoft RSA SChannel Cryptographic Provider'),
+                                ('signature', ()),
+                            ])
+                        ]
+                    ),
+                ]),
+                util.OrderedDict([
+                    ('type', 'extension_request'),
+                    (
+                        'values',
+                        [
+                            [
+                                util.OrderedDict([
+                                    ('extn_id', 'microsoft_enroll_certtype'),
+                                    ('critical', False),
+                                    (
+                                        'extn_value',
+                                        'Machine',
+                                    )
+                                ]),
+                                util.OrderedDict([
+                                    ('extn_id', 'extended_key_usage'),
+                                    ('critical', False),
+                                    (
+                                        'extn_value',
+                                        ['client_auth', 'server_auth'],
+                                    ),
+                                ]),
+                                util.OrderedDict([
+                                    ('extn_id', 'key_usage'),
+                                    ('critical', False),
+                                    (
+                                        'extn_value',
+                                        set(['digital_signature', 'key_encipherment']),
+                                    ),
+                                ]),
+                                util.OrderedDict([
+                                    ('extn_id', 'key_identifier'),
+                                    ('critical', False),
+                                    (
+                                        'extn_value',
+                                        bytearray.fromhex('2a 98 4b c1 ff 6e 16 ed 2d 69 35 0a 26 e7 1f 8c 05 4f b8 e6'),  # noqa
+                                    ),
+                                ]),
+                            ]
+                        ]
+                    ),
+                ]),
+            ],
+            cri['attributes'].native
+        )
diff --git a/tests/test_init.py b/tests/test_init.py
index b986458..2f41f7f 100644
--- a/tests/test_init.py
+++ b/tests/test_init.py
@@ -123,6 +123,9 @@ class InitTests(unittest.TestCase):
             else:
                 modname = '%s.%s' % (module.__name__, modname)
 
+            if sys.version_info < (3,) and sys.platform == 'win32' and b'\r\n' in full_code:
+                full_code = full_code.replace(b'\r\n', b'\n')
+
             imports = set([])
             module_node = ast.parse(full_code, filename=full_path)
             walk_ast(module_node, modname, imports)
diff --git a/tests/test_keys.py b/tests/test_keys.py
index eefd48f..2cd8a0e 100644
--- a/tests/test_keys.py
+++ b/tests/test_keys.py
@@ -204,6 +204,26 @@ class KeysTests(unittest.TestCase):
             key['public_key'].native
         )
 
+    def test_parse_ed25519_private_key(self):
+        with open(os.path.join(fixtures_dir, 'keys/test-ed25519.key'), 'rb') as f:
+            key = keys.PrivateKeyInfo.load(f.read())
+
+        self.assertEqual(
+            b'\xab),,c\x03o\xed)r5\x95+p\xb0\xbbc Lu\xc1\xfd\xc8FH\xfe\xce\x83\xf0F\x0f\xd7',
+            key['private_key'].native
+        )
+
+    def test_parse_ed448_private_key(self):
+        with open(os.path.join(fixtures_dir, 'keys/test-ed448.key'), 'rb') as f:
+            key = keys.PrivateKeyInfo.load(f.read())
+
+        self.assertEqual(
+            b'yQ\xf0<\x99\x89\tU\xda}\x84\x027\xa8\xc0\xdb\x0fs\xafd\xdcQ\xa1'
+            b'\xa6(7g\x06\x07\x8d#\xb1&\x11\x15\xfb\xd3\xfd\x0b\x03\xc7\x80\xe1'
+            b'\xf2\x82\xb6\xedo\xb1Sk\x828#M\xb2\\',
+            key['private_key'].native
+        )
+
     def test_parse_rsa_public_key(self):
         with open(os.path.join(fixtures_dir, 'keys/test-public-rsa-der.key'), 'rb') as f:
             key = keys.RSAPublicKey.load(f.read())
diff --git a/tests/test_parser.py b/tests/test_parser.py
index 4148a84..0daf060 100644
--- a/tests/test_parser.py
+++ b/tests/test_parser.py
@@ -88,3 +88,66 @@ class ParserTests(unittest.TestCase):
         self.assertEqual(b'\x7f\x81\x80\x00\x00', result[3])
         self.assertEqual(b'', result[4])
         self.assertEqual(b'', result[5])
+
+    def test_parser_insufficient_data(self):
+        # No tag
+        with self.assertRaises(ValueError):
+            parser.parse(b'')
+
+        # Long-form tag is truncated
+        with self.assertRaises(ValueError):
+            parser.parse(b'\xbf')
+        with self.assertRaises(ValueError):
+            parser.parse(b'\xbf\x81')
+
+        # No length
+        with self.assertRaises(ValueError):
+            parser.parse(b'\x04')
+        with self.assertRaises(ValueError):
+            parser.parse(b'\xbf\x1f')
+
+        # Long-form length is truncated
+        with self.assertRaises(ValueError):
+            parser.parse(b'\x04\x81')
+        with self.assertRaises(ValueError):
+            parser.parse(b'\x04\x82\x01')
+
+        # Contents are truncated
+        with self.assertRaises(ValueError):
+            parser.parse(b'\x04\x02\x00')
+        with self.assertRaises(ValueError):
+            parser.parse(b'\x04\x81\x80' + (b'\x00' * 127))
+
+    def test_parser_bounded_recursion(self):
+        with self.assertRaises(ValueError):
+            parser.parse(b'\x30\x80' * 1000)
+
+    def test_parser_indef_missing_eoc(self):
+        with self.assertRaises(ValueError):
+            parser.parse(b'\x30\x80')
+        with self.assertRaises(ValueError):
+            parser.parse(b'\x30\x80\x30\x80\x00\x00')
+
+    def test_parser_indef_long_zero_length(self):
+        # The parser should not confuse the long-form zero length for an EOC.
+        result = parser.parse(b'\x30\x80\x30\x82\x00\x00\x00\x00')
+        self.assertIsInstance(result, tuple)
+        self.assertEqual(0, result[0])
+        self.assertEqual(1, result[1])
+        self.assertEqual(16, result[2])
+        self.assertEqual(b'\x30\x80', result[3])
+        self.assertEqual(b'\x30\x82\x00\x00', result[4])
+        self.assertEqual(b'\x00\x00', result[5])
+
+    def test_parser_indef_primitive(self):
+        with self.assertRaises(ValueError):
+            parser.parse(b'\x04\x80\x00\x00')
+
+    def test_parse_nonminimal_tag(self):
+        with self.assertRaises(ValueError):
+            # Should be b'\x04\x00'
+            parser.parse(b'\x1f\x04\x00')
+
+        with self.assertRaises(ValueError):
+            # Should be b'\xbf\x1f\x00'
+            parser.parse(b'\xbf\x80\x1f\x00')
diff --git a/tests/test_util.py b/tests/test_util.py
index a5fb5e3..2291f13 100644
--- a/tests/test_util.py
+++ b/tests/test_util.py
@@ -1,9 +1,10 @@
 # coding: utf-8
 from __future__ import unicode_literals, division, absolute_import, print_function
 
-import unittest
-import sys
 import os
+import platform
+import sys
+import unittest
 from datetime import date, datetime, time, timedelta
 
 from asn1crypto import util
@@ -132,7 +133,7 @@ class UtilTests(unittest.TestCase):
         self.assertEqual('0000-01-01', util.extended_date(0, 1, 1).strftime('%Y-%m-%d'))
         self.assertEqual('Sat Saturday Jan January', util.extended_date(0, 1, 1).strftime('%a %A %b %B'))
         self.assertEqual('Tue Tuesday Feb February 29', util.extended_date(0, 2, 29).strftime('%a %A %b %B %d'))
-        if sys.platform == 'win32' and sys.version_info < (3, 5):
+        if sys.platform == 'win32' and sys.version_info < (3, 5) and platform.python_implementation() != 'PyPy':
             self.assertEqual('01/01/00 00:00:00', util.extended_date(0, 1, 1).strftime('%c'))
         else:
             self.assertEqual('Sat Jan  1 00:00:00 0000', util.extended_date(0, 1, 1).strftime('%c'))
@@ -177,7 +178,7 @@ class UtilTests(unittest.TestCase):
         self.assertEqual('0000-01-01 00:00:00', util.extended_datetime(0, 1, 1).strftime('%Y-%m-%d %H:%M:%S'))
         self.assertEqual('Sat Saturday Jan January', util.extended_datetime(0, 1, 1).strftime('%a %A %b %B'))
         self.assertEqual('Tue Tuesday Feb February 29', util.extended_datetime(0, 2, 29).strftime('%a %A %b %B %d'))
-        if sys.platform == 'win32' and sys.version_info < (3, 5):
+        if sys.platform == 'win32' and sys.version_info < (3, 5) and platform.python_implementation() != 'PyPy':
             self.assertEqual('01/01/00 00:00:00', util.extended_datetime(0, 1, 1).strftime('%c'))
         else:
             self.assertEqual('Sat Jan  1 00:00:00 0000', util.extended_datetime(0, 1, 1).strftime('%c'))
diff --git a/tests/test_x509.py b/tests/test_x509.py
index cfeb485..79f41b0 100644
--- a/tests/test_x509.py
+++ b/tests/test_x509.py
@@ -3492,6 +3492,67 @@ class X509Tests(unittest.TestCase):
             extensions.native
         )
 
+    def test_parse_ed25519_certificate(self):
+        cert = self._load_cert('keys/test-ed25519.crt')
+
+        tbs_certificate = cert['tbs_certificate']
+        signature = tbs_certificate['signature']
+        subject_public_key_info = tbs_certificate['subject_public_key_info']
+        subject_public_key_algorithm = subject_public_key_info['algorithm']
+
+        self.assertEqual(
+            'ed25519',
+            signature['algorithm'].native
+        )
+        self.assertEqual(
+            None,
+            signature['parameters'].native
+        )
+        self.assertEqual(
+            None,
+            subject_public_key_info['algorithm']['parameters'].native
+        )
+        self.assertEqual(
+            'ed25519',
+            subject_public_key_algorithm['algorithm'].native
+        )
+        self.assertEqual(
+            b'\x17ZZS\xb8\x8e=\xc7\xf9P\xf9\xe8\xcd=\x9a\x15\x06\xec=\xcf\xfa'
+            b'\xa3\xfb\x93M\xb3\x89V\xce*N\xed',
+            subject_public_key_info['public_key'].native
+        )
+
+    def test_parse_ed448_certificate(self):
+        cert = self._load_cert('keys/test-ed448.crt')
+
+        tbs_certificate = cert['tbs_certificate']
+        signature = tbs_certificate['signature']
+        subject_public_key_info = tbs_certificate['subject_public_key_info']
+        subject_public_key_algorithm = subject_public_key_info['algorithm']
+
+        self.assertEqual(
+            'ed448',
+            signature['algorithm'].native
+        )
+        self.assertEqual(
+            None,
+            signature['parameters'].native
+        )
+        self.assertEqual(
+            None,
+            subject_public_key_info['algorithm']['parameters'].native
+        )
+        self.assertEqual(
+            'ed448',
+            subject_public_key_algorithm['algorithm'].native
+        )
+        self.assertEqual(
+            b'\xdc\'\x19\xbb\xff\xec\xef\xae\xc4\'\x91\xa1\xe7}\xbaN\xe1\xbe'
+            b'\x94\x04CL\x17\xc4\xba\xca\x96\xb8"\xa1H>\xf4\xd6\xc6^\xe7\xd8'
+            b'\n\xf3}\xe5\xba6]\xbd\x8d\xe1\xfc\x99\xafr_K\xfej\x00',
+            subject_public_key_info['public_key'].native
+        )
+
     def test_repeated_subject_fields(self):
         cert = self._load_cert('self-signed-repeated-subject-fields.der')
         self.assertEqual(
diff --git a/tox.ini b/tox.ini
index dbf71ee..096968a 100644
--- a/tox.ini
+++ b/tox.ini
@@ -1,5 +1,5 @@
 [tox]
-envlist = py26,py27,py32,py33,py34,py35,py36,py37,py38,pypy
+envlist = py26,py27,py32,py33,py34,py35,py36,py37,py38,py39,py310,pypy
 
 [testenv]
 deps = -rrequires/ci
```

