```diff
diff --git a/.github/workflows/python-package.yml b/.github/workflows/python-package.yml
index 3ee553d..af3d922 100644
--- a/.github/workflows/python-package.yml
+++ b/.github/workflows/python-package.yml
@@ -18,12 +18,12 @@ jobs:
     strategy:
       fail-fast: false
       matrix:
-        python-version: [3.6, 3.7, 3.8, 3.9, '3.10']
+        python-version: [3.7, 3.8, 3.9, '3.10', '3.11', '3.12.0-beta - 3.12']
 
     steps:
-      - uses: actions/checkout@v2
+      - uses: actions/checkout@v3
       - name: Set up Python ${{ matrix.python-version }}
-        uses: actions/setup-python@v2
+        uses: actions/setup-python@v4
         with:
           python-version: ${{ matrix.python-version }}
       - name: Install dependencies
@@ -42,12 +42,12 @@ jobs:
     strategy:
       fail-fast: false
       matrix:
-        python-version: [3.6, 3.7, 3.8, 3.9, '3.10']
+        python-version: [3.7, 3.8, 3.9, '3.10', '3.11', '3.12.0-beta - 3.12']
 
     steps:
-      - uses: actions/checkout@v2
+      - uses: actions/checkout@v3
       - name: Set up Python ${{ matrix.python-version }}
-        uses: actions/setup-python@v2
+        uses: actions/setup-python@v4
         with:
           python-version: ${{ matrix.python-version }}
       - name: Install dependencies
diff --git a/.travis.yml b/.travis.yml
deleted file mode 100644
index 5c5e2ad..0000000
--- a/.travis.yml
+++ /dev/null
@@ -1,15 +0,0 @@
-language: python
-python:
-  - "3.6"
-  - "3.7"
-  - "3.8"
-  - "3.9"
-  - "3.10-dev"
-os: linux
-arch:
-  - ppc64le
-dist: focal
-install:
-  - pip install --upgrade pip
-  - pip install tox-travis
-script: tox
diff --git a/ChangeLog.md b/ChangeLog.md
index 3cda728..b32802e 100644
--- a/ChangeLog.md
+++ b/ChangeLog.md
@@ -1,3 +1,31 @@
+## 1.6.0
+
+*   Resolve an internal source of potential flakiness on the bind/close port
+    checks when used in active environments by calling `.shutdown()` before
+    `.close()`.
+
+## 1.6.0b1
+
+*   Add `-h` and `--help` text to the command line tool.
+*   The command line interface now defaults to associating the returned port
+    with its parent process PID (usually the calling script) when no argument
+    was given as that makes more sense.
+*   When portpicker is used as a command line tool from a script, if a port is
+    chosen without a portserver it can now be kept bound to a socket by a
+    child process for a user specified timeout. When successful, this helps
+    minimize race conditions as subsequent portpicker CLI invocations within
+    the timeout window cannot choose the same port.
+*   Some pylint based refactorings to portpicker and portpicker\_test.
+*   Drop 3.6 from our CI test matrix and metadata. It probably still works
+    there, but expect our unittests to include 3.7-ism's in the future. We'll
+    *attempt* to avoid modern constructs in portpicker.py itself but zero
+    guarantees. Using an old Python? Use an old portpicker.
+
+## 1.5.2
+
+*   Do not re-pick a known used (not-yet-returned) port when running stand alone
+    without a portserver.
+
 ## 1.5.1
 
 *   When not using a portserver *(you really should)*, try the `bind(0)`
diff --git a/METADATA b/METADATA
index 8480a2c..7cf9cca 100644
--- a/METADATA
+++ b/METADATA
@@ -1,16 +1,20 @@
+# This project was upgraded with external_updater.
+# Usage: tools/external_updater/updater.sh update external/python/portpicker
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
+
 name: "python_portpicker"
-description:
-    "This module is useful for finding unused network ports on a host."
+description: "This module is useful for finding unused network ports on a host."
 third_party {
-  url {
-    type: HOMEPAGE
-    value: "https://github.com/google/python_portpicker"
+  license_type: NOTICE
+  last_upgrade_date {
+    year: 2025
+    month: 1
+    day: 16
   }
-  url {
-    type: GIT
+  homepage: "https://github.com/google/python_portpicker"
+  identifier {
+    type: "Git"
     value: "https://github.com/google/python_portpicker"
+    version: "v1.6.0"
   }
-  version: "b05ca660bc9ce2ff9753256238927b91e234c34b"
-  last_upgrade_date { year: 2022 month: 5 day: 17 }
-  license_type: NOTICE
 }
diff --git a/OWNERS b/OWNERS
index eb86f14..9d0371a 100644
--- a/OWNERS
+++ b/OWNERS
@@ -6,3 +6,4 @@ murj@google.com
 # Mobly team - use for mobly bugs
 angli@google.com
 lancefluger@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/README.md b/README.md
index bd56703..09bc0f5 100644
--- a/README.md
+++ b/README.md
@@ -1,8 +1,7 @@
 # Python portpicker module
 
 [![PyPI version](https://badge.fury.io/py/portpicker.svg)](https://badge.fury.io/py/portpicker)
-![GH Action Status](https://github.com/google/python_portpicker/actions/workflows/python-package.yml/badge.svg)
-[![Travis CI org Status](https://travis-ci.org/google/python_portpicker.svg?branch=master)](https://travis-ci.org/google/python_portpicker)
+[![GH Action Status](https://github.com/google/python_portpicker/actions/workflows/python-package.yml/badge.svg)](https://github.com/google/python_portpicker/actions)
 
 This module is useful for finding unused network ports on a host. If you need
 legacy Python 2 support, use the 1.3.x releases.
diff --git a/pyproject.toml b/pyproject.toml
index b1236df..932b7de 100644
--- a/pyproject.toml
+++ b/pyproject.toml
@@ -5,7 +5,7 @@ build-backend = "setuptools.build_meta"
 [tool.tox]
 legacy_tox_ini = """
 [tox]
-envlist = py{36,37,38,39}
+envlist = py{37,38,39,310,311}
 isolated_build = true
 skip_missing_interpreters = true
 # minimum tox version
@@ -17,5 +17,5 @@ deps =
 commands =
     check-manifest --ignore 'src/tests/**'
     python -c 'from setuptools import setup; setup()' check -m -s
-    py.test -s {posargs}
+    py.test -vv -s {posargs}
 """
diff --git a/setup.cfg b/setup.cfg
index 63c1ac4..f17d17c 100644
--- a/setup.cfg
+++ b/setup.cfg
@@ -1,7 +1,7 @@
 # https://setuptools.readthedocs.io/en/latest/setuptools.html#configuring-setup-using-setup-cfg-files
 [metadata]
 name = portpicker
-version = 1.5.1b1
+version = 1.6.0
 maintainer = Google LLC
 maintainer_email = greg@krypto.org
 license = Apache 2.0
@@ -22,11 +22,12 @@ classifiers =
     Intended Audience :: Developers
     Programming Language :: Python
     Programming Language :: Python :: 3
-    Programming Language :: Python :: 3.6
     Programming Language :: Python :: 3.7
     Programming Language :: Python :: 3.8
     Programming Language :: Python :: 3.9
     Programming Language :: Python :: 3.10
+    Programming Language :: Python :: 3.11
+    Programming Language :: Python :: 3.12
     Programming Language :: Python :: Implementation :: CPython
     Programming Language :: Python :: Implementation :: PyPy
 platforms = POSIX, Windows
diff --git a/src/portpicker.py b/src/portpicker.py
index fc2825b..33805d4 100644
--- a/src/portpicker.py
+++ b/src/portpicker.py
@@ -35,6 +35,9 @@ Typical usage:
   test_port = portpicker.pick_unused_port()
 """
 
+# pylint: disable=consider-using-f-string
+# Some people still use this on old Pythons despite our test matrix and
+# supported versions.  Be kind for now, until it gets in our way.
 from __future__ import print_function
 
 import logging
@@ -42,11 +45,14 @@ import os
 import random
 import socket
 import sys
+import time
 
+_winapi = None  # pylint: disable=invalid-name
 if sys.platform == 'win32':
-    import _winapi
-else:
-    _winapi = None
+    try:
+        import _winapi
+    except ImportError:
+        _winapi = None
 
 # The legacy Bind, IsPortFree, etc. names are not exported.
 __all__ = ('bind', 'is_port_free', 'pick_unused_port', 'return_port',
@@ -107,8 +113,33 @@ def bind(port, socket_type, socket_proto):
     Returns:
       The port number on success or None on failure.
     """
+    return _bind(port, socket_type, socket_proto)
+
+
+def _bind(port, socket_type, socket_proto, return_socket=None,
+          return_family=socket.AF_INET6):
+    """Internal implementation of bind.
+
+    Args:
+      port, socket_type, socket_proto: see bind().
+      return_socket: If supplied, a list that we will append an open bound
+          reuseaddr socket on the port in question to.
+      return_family: The socket family to return in return_socket.
+
+    Returns:
+      The port number on success or None on failure.
+    """
+    # Our return family must come last when returning a bound socket
+    # as we cannot keep it bound while testing a bind on the other
+    # family with many network stack configurations.
+    if return_socket is None or return_family == socket.AF_INET:
+        socket_families = (socket.AF_INET6, socket.AF_INET)
+    elif return_family == socket.AF_INET6:
+        socket_families = (socket.AF_INET, socket.AF_INET6)
+    else:
+        raise ValueError('unknown return_family %s' % return_family)
     got_socket = False
-    for family in (socket.AF_INET6, socket.AF_INET):
+    for family in socket_families:
         try:
             sock = socket.socket(family, socket_type, socket_proto)
             got_socket = True
@@ -123,27 +154,51 @@ def bind(port, socket_type, socket_proto):
         except socket.error:
             return None
         finally:
-            sock.close()
+            if return_socket is None or family != return_family:
+                try:
+                    # Adding this resolved 1 in ~500 flakiness that we were
+                    # seeing from an integration test framework managing a set
+                    # of ports with is_port_free().  close() doesn't move the
+                    # TCP state machine along quickly.
+                    sock.shutdown(socket.SHUT_RDWR)
+                except OSError:
+                    pass
+                sock.close()
+        if return_socket is not None and family == return_family:
+            return_socket.append(sock)
+            break  # Final iteration due to pre-loop logic; don't close.
     return port if got_socket else None
 
-Bind = bind  # legacy API. pylint: disable=invalid-name
-
 
 def is_port_free(port):
     """Check if specified port is free.
 
     Args:
       port: integer, port to check
+
     Returns:
-      boolean, whether it is free to use for both TCP and UDP
+      bool, whether port is free to use for both TCP and UDP.
     """
-    return bind(port, *_PROTOS[0]) and bind(port, *_PROTOS[1])
+    return _is_port_free(port)
+
+
+def _is_port_free(port, return_sockets=None):
+    """Internal implementation of is_port_free.
 
-IsPortFree = is_port_free  # legacy API. pylint: disable=invalid-name
+    Args:
+      port: integer, port to check
+      return_sockets: If supplied, a list that we will append open bound
+        sockets on the port in question to rather than closing them.
+
+    Returns:
+      bool, whether port is free to use for both TCP and UDP.
+    """
+    return (_bind(port, *_PROTOS[0], return_socket=return_sockets) and
+            _bind(port, *_PROTOS[1], return_socket=return_sockets))
 
 
 def pick_unused_port(pid=None, portserver_address=None):
-    """A pure python implementation of PickUnusedPort.
+    """Picks an unused port and reserves it for use by a given process id.
 
     Args:
       pid: PID to tell the portserver to associate the reservation with. If
@@ -156,12 +211,30 @@ def pick_unused_port(pid=None, portserver_address=None):
         address, the environment will be checked for a PORTSERVER_ADDRESS
         variable.  If that is not set, no port server will be used.
 
+    If no portserver is used, no pid based reservation is managed by any
+    central authority. Race conditions and duplicate assignments may occur.
+
     Returns:
       A port number that is unused on both TCP and UDP.
 
     Raises:
       NoFreePortFoundError: No free port could be found.
     """
+    return _pick_unused_port(pid, portserver_address)
+
+
+def _pick_unused_port(pid=None, portserver_address=None,
+                     noserver_bind_timeout=0):
+    """Internal implementation of pick_unused_port.
+
+    Args:
+      pid, portserver_address: See pick_unused_port().
+      noserver_bind_timeout: If no portserver was used, this is the number of
+        seconds we will attempt to keep a child process around with the ports
+        returned open and bound SO_REUSEADDR style to help avoid race condition
+        port reuse. A non-zero value attempts os.fork(). Do not use it in a
+        multithreaded process.
+    """
     try:  # Instead of `if _free_ports:` to handle the race condition.
         port = _free_ports.pop()
     except KeyError:
@@ -179,12 +252,46 @@ def pick_unused_port(pid=None, portserver_address=None):
                                          pid=pid)
         if port:
             return port
-    return _pick_unused_port_without_server()
+    return _pick_unused_port_without_server(bind_timeout=noserver_bind_timeout)
+
 
-PickUnusedPort = pick_unused_port  # legacy API. pylint: disable=invalid-name
+def _spawn_bound_port_holding_daemon(port, bound_sockets, timeout):
+    """If possible, fork()s a daemon process to hold bound_sockets open.
 
+    Emits a warning to stderr if it cannot.
 
-def _pick_unused_port_without_server():  # Protected. pylint: disable=invalid-name
+    Args:
+      port: The port number the sockets are bound to (informational).
+      bound_sockets: The list of bound sockets our child process will hold
+          open. If the list is empty, no action is taken.
+      timeout: A positive number of seconds the child should sleep for before
+          closing the sockets and exiting.
+    """
+    if bound_sockets and timeout > 0:
+        try:
+            fork_pid = os.fork()  # This concept only works on POSIX.
+        except Exception as err:  # pylint: disable=broad-except
+            print('WARNING: Cannot timeout unbinding close of port', port,
+                  ' closing on exit. -', err, file=sys.stderr)
+        else:
+            if fork_pid == 0:
+                # This child process inherits and holds bound_sockets open
+                # for bind_timeout seconds.
+                try:
+                    # Close the stdio fds as may be connected to
+                    # a pipe that will cause a grandparent process
+                    # to wait on before returning. (cl/427587550)
+                    os.close(sys.stdin.fileno())
+                    os.close(sys.stdout.fileno())
+                    os.close(sys.stderr.fileno())
+                    time.sleep(timeout)
+                    for held_socket in bound_sockets:
+                        held_socket.close()
+                finally:
+                    os._exit(0)
+
+
+def _pick_unused_port_without_server(bind_timeout=0):
     """Pick an available network port without the help of a port server.
 
     This code ensures that the port is available on both TCP and UDP.
@@ -192,6 +299,11 @@ def _pick_unused_port_without_server():  # Protected. pylint: disable=invalid-na
     This function is an implementation detail of PickUnusedPort(), and
     should not be called by code outside of this module.
 
+    Args:
+      bind_timeout: number of seconds to attempt to keep a child process
+          process around bound SO_REUSEADDR style to the port. If we cannot
+          do that we emit a warning to stderr.
+
     Returns:
       A port number that is unused on both TCP and UDP.
 
@@ -201,27 +313,42 @@ def _pick_unused_port_without_server():  # Protected. pylint: disable=invalid-na
     # Next, try a few times to get an OS-assigned port.
     # Ambrose discovered that on the 2.6 kernel, calling Bind() on UDP socket
     # returns the same port over and over. So always try TCP first.
+    port = None
+    bound_sockets = [] if bind_timeout > 0 else None
     for _ in range(10):
         # Ask the OS for an unused port.
-        port = bind(0, _PROTOS[0][0], _PROTOS[0][1])
+        port = _bind(0, socket.SOCK_STREAM, socket.IPPROTO_TCP, bound_sockets)
         # Check if this port is unused on the other protocol.
-        if port and bind(port, _PROTOS[1][0], _PROTOS[1][1]):
+        if (port and port not in _random_ports and
+            _bind(port, socket.SOCK_DGRAM, socket.IPPROTO_UDP, bound_sockets)):
             _random_ports.add(port)
+            _spawn_bound_port_holding_daemon(port, bound_sockets, bind_timeout)
             return port
+        if bound_sockets:
+            for held_socket in bound_sockets:
+                held_socket.close()
+            del bound_sockets[:]
 
     # Try random ports as a last resort.
     rng = random.Random()
     for _ in range(10):
         port = int(rng.randrange(15000, 25000))
-        if is_port_free(port):
-            _random_ports.add(port)
-            return port
+        if port not in _random_ports:
+            if _is_port_free(port, bound_sockets):
+                _random_ports.add(port)
+                _spawn_bound_port_holding_daemon(
+                        port, bound_sockets, bind_timeout)
+                return port
+            if bound_sockets:
+                for held_socket in bound_sockets:
+                    held_socket.close()
+                del bound_sockets[:]
 
     # Give up.
     raise NoFreePortFoundError()
 
 
-def _get_linux_port_from_port_server(portserver_address, pid):
+def _posix_get_port_from_port_server(portserver_address, pid):
     # An AF_UNIX address may start with a zero byte, in which case it is in the
     # "abstract namespace", and doesn't have any filesystem representation.
     # See 'man 7 unix' for details.
@@ -232,7 +359,7 @@ def _get_linux_port_from_port_server(portserver_address, pid):
     try:
         # Create socket.
         if hasattr(socket, 'AF_UNIX'):
-            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) # pylint: disable=no-member
+            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
         else:
             # fallback to AF_INET if this is not unix
             sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
@@ -254,7 +381,7 @@ def _get_linux_port_from_port_server(portserver_address, pid):
         return None
 
 
-def _get_windows_port_from_port_server(portserver_address, pid):
+def _windows_get_port_from_port_server(portserver_address, pid):
     if portserver_address[0] == '@':
         portserver_address = '\\\\.\\pipe\\' + portserver_address[1:]
 
@@ -276,6 +403,7 @@ def _get_windows_port_from_port_server(portserver_address, pid):
               file=sys.stderr)
         return None
 
+
 def get_port_from_port_server(portserver_address, pid=None):
     """Request a free a port from a system-wide portserver.
 
@@ -304,9 +432,9 @@ def get_port_from_port_server(portserver_address, pid=None):
         pid = os.getpid()
 
     if _winapi:
-        buf = _get_windows_port_from_port_server(portserver_address, pid)
+        buf = _windows_get_port_from_port_server(portserver_address, pid)
     else:
-        buf = _get_linux_port_from_port_server(portserver_address, pid)
+        buf = _posix_get_port_from_port_server(portserver_address, pid)
 
     if buf is None:
         return None
@@ -320,12 +448,48 @@ def get_port_from_port_server(portserver_address, pid=None):
     return port
 
 
-GetPortFromPortServer = get_port_from_port_server  # legacy API. pylint: disable=invalid-name
+# Legacy APIs.
+# pylint: disable=invalid-name
+Bind = bind
+GetPortFromPortServer = get_port_from_port_server
+IsPortFree = is_port_free
+PickUnusedPort = pick_unused_port
+# pylint: enable=invalid-name
 
 
 def main(argv):
-    """If passed an arg, treat it as a PID, otherwise portpicker uses getpid."""
-    port = pick_unused_port(pid=int(argv[1]) if len(argv) > 1 else None)
+    """If passed an arg, treat it as a PID, otherwise we use getppid().
+
+    A second optional argument can be a bind timeout in seconds that will be
+    used ONLY if no portserver is found. We attempt to leave a process around
+    holding the port open and bound with SO_REUSEADDR set for timeout seconds.
+    If the timeout bind was not possible, a warning is emitted to stderr.
+
+      #!/bin/bash
+      port="$(python -m portpicker $$ 1.23)"
+      test_my_server "$port"
+
+    This will pick a port for your script's PID and assign it to $port, if no
+    portserver was used, it attempts to keep a socket bound to $port for 1.23
+    seconds after the portpicker process has exited. This is a convenient hack
+    to attempt to prevent port reallocation during scripts outside of
+    portserver managed environments.
+
+    Older versions of the portpicker CLI ignore everything beyond the first arg.
+    Older versions also used getpid() instead of getppid(), so script users are
+    strongly encouraged to be explicit and pass $$ or your languages equivalent
+    to associate the port with the PID of the controlling process.
+    """
+    # Our command line is trivial so I avoid an argparse import. If we ever
+    # grow more than 1-2 args, switch to a using argparse.
+    if '-h' in argv or '--help' in argv:
+        print(argv[0], 'usage:\n')
+        import inspect
+        print(inspect.getdoc(main))
+        sys.exit(1)
+    pid=int(argv[1]) if len(argv) > 1 else os.getppid()
+    bind_timeout=float(argv[2]) if len(argv) > 2 else 0
+    port = _pick_unused_port(pid=pid, noserver_bind_timeout=bind_timeout)
     if not port:
         sys.exit(1)
     print(port)
diff --git a/src/tests/portpicker_test.py b/src/tests/portpicker_test.py
index c2925db..9967648 100644
--- a/src/tests/portpicker_test.py
+++ b/src/tests/portpicker_test.py
@@ -1,4 +1,4 @@
-#!/usr/bin/python
+#!/usr/bin/python3
 #
 # Copyright 2007 Google Inc. All Rights Reserved.
 #
@@ -14,32 +14,27 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 #
-"""Unittests for the portpicker module."""
+"""Unittests for portpicker."""
 
-from __future__ import print_function
+# pylint: disable=invalid-name,protected-access,missing-class-docstring,missing-function-docstring
+
+from contextlib import ExitStack
 import errno
 import os
-import random
 import socket
+import subprocess
 import sys
+import time
 import unittest
-from contextlib import ExitStack
-
-if sys.platform == 'win32':
-    import _winapi
-else:
-    _winapi = None
-
-try:
-    # pylint: disable=no-name-in-module
-    from unittest import mock  # Python >= 3.3.
-except ImportError:
-    import mock  # https://pypi.python.org/pypi/mock
+from unittest import mock
 
 import portpicker
+_winapi = portpicker._winapi
+
+# pylint: disable=invalid-name,protected-access,missing-class-docstring,missing-function-docstring
 
 
-class PickUnusedPortTest(unittest.TestCase):
+class CommonTestMixin:
     def IsUnusedTCPPort(self, port):
         return self._bind(port, socket.SOCK_STREAM, socket.IPPROTO_TCP)
 
@@ -47,21 +42,69 @@ class PickUnusedPortTest(unittest.TestCase):
         return self._bind(port, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
 
     def setUp(self):
+        super().setUp()
         # So we can Bind even if portpicker.bind is stubbed out.
         self._bind = portpicker.bind
         portpicker._owned_ports.clear()
         portpicker._free_ports.clear()
         portpicker._random_ports.clear()
 
-    def testPickUnusedPortActuallyWorks(self):
-        """This test can be flaky."""
-        for _ in range(10):
-            port = portpicker.pick_unused_port()
-            self.assertTrue(self.IsUnusedTCPPort(port))
-            self.assertTrue(self.IsUnusedUDPPort(port))
 
-    @unittest.skipIf('PORTSERVER_ADDRESS' not in os.environ,
-                     'no port server to test against')
+@unittest.skipIf(
+        ('PORTSERVER_ADDRESS' not in os.environ) and
+        not hasattr(socket, 'AF_UNIX'),
+        'no existing port server; test launching code requires AF_UNIX.')
+class PickUnusedPortTestWithAPortServer(CommonTestMixin, unittest.TestCase):
+
+    @classmethod
+    def setUpClass(cls):
+        cls.portserver_process = None
+        if 'PORTSERVER_ADDRESS' not in os.environ:
+            # Launch a portserver child process for our tests to use if we are
+            # able to. Obviously not host-exclusive, but good for integration
+            # testing purposes on CI without a portserver of its own.
+            cls.portserver_address = '@pid%d-test-ports' % os.getpid()
+            try:
+                cls.portserver_process = subprocess.Popen(
+                        ['portserver.py',  # Installed in PATH within the venv.
+                         '--portserver_address=%s' % cls.portserver_address])
+            except EnvironmentError as err:
+                raise unittest.SkipTest(
+                        'Unable to launch portserver.py: %s' % err)
+            linux_addr = '\0' + cls.portserver_address[1:]  # The @ means 0.
+            # loop for a few seconds waiting for that socket to work.
+            err = '???'
+            for _ in range(123):
+                time.sleep(0.05)
+                try:
+                    ps_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
+                    ps_sock.connect(linux_addr)
+                except socket.error as err:  # pylint: disable=unused-variable
+                    continue
+                ps_sock.close()
+                break
+            else:
+                # The socket failed or never accepted connections, assume our
+                # portserver setup attempt failed and bail out.
+                if cls.portserver_process.poll() is not None:
+                    cls.portserver_process.kill()
+                    cls.portserver_process.wait()
+                cls.portserver_process = None
+                raise unittest.SkipTest(
+                        'Unable to connect to our own portserver.py: %s' % err)
+            # Point child processes at our shiny portserver process.
+            os.environ['PORTSERVER_ADDRESS'] = cls.portserver_address
+
+    @classmethod
+    def tearDownClass(cls):
+        if cls.portserver_process:
+            if os.environ.get('PORTSERVER_ADDRESS') == cls.portserver_address:
+                del os.environ['PORTSERVER_ADDRESS']
+            if cls.portserver_process.poll() is None:
+                cls.portserver_process.kill()
+                cls.portserver_process.wait()
+            cls.portserver_process = None
+
     def testPickUnusedCanSuccessfullyUsePortServer(self):
 
         with mock.patch.object(portpicker, '_pick_unused_port_without_server'):
@@ -75,8 +118,6 @@ class PickUnusedPortTest(unittest.TestCase):
             self.assertTrue(self.IsUnusedTCPPort(port))
             self.assertTrue(self.IsUnusedUDPPort(port))
 
-    @unittest.skipIf('PORTSERVER_ADDRESS' not in os.environ,
-                     'no port server to test against')
     def testPickUnusedCanSuccessfullyUsePortServerAddressKwarg(self):
 
         with mock.patch.object(portpicker, '_pick_unused_port_without_server'):
@@ -93,10 +134,8 @@ class PickUnusedPortTest(unittest.TestCase):
                 self.assertTrue(self.IsUnusedTCPPort(port))
                 self.assertTrue(self.IsUnusedUDPPort(port))
             finally:
-              os.environ['PORTSERVER_ADDRESS'] = addr
+                os.environ['PORTSERVER_ADDRESS'] = addr
 
-    @unittest.skipIf('PORTSERVER_ADDRESS' not in os.environ,
-                     'no port server to test against')
     def testGetPortFromPortServer(self):
         """Exercise the get_port_from_port_server() helper function."""
         for _ in range(10):
@@ -105,6 +144,16 @@ class PickUnusedPortTest(unittest.TestCase):
             self.assertTrue(self.IsUnusedTCPPort(port))
             self.assertTrue(self.IsUnusedUDPPort(port))
 
+
+class PickUnusedPortTest(CommonTestMixin, unittest.TestCase):
+
+    def testPickUnusedPortActuallyWorks(self):
+        """This test can be flaky."""
+        for _ in range(10):
+            port = portpicker.pick_unused_port()
+            self.assertTrue(self.IsUnusedTCPPort(port))
+            self.assertTrue(self.IsUnusedUDPPort(port))
+
     def testSendsPidToPortServer(self):
         with ExitStack() as stack:
             if _winapi:
@@ -253,12 +302,11 @@ class PickUnusedPortTest(unittest.TestCase):
             # Only successfully return a port if an OS-assigned port is
             # requested, or if we're checking that the last OS-assigned port
             # is unused on the other protocol.
-            if port == 0 or port == self.last_assigned_port:
+            if port in (0, self.last_assigned_port):
                 self.last_assigned_port = self._bind(port, socket_type,
                                                      socket_proto)
                 return self.last_assigned_port
-            else:
-                return None
+            return None
 
         with mock.patch.object(portpicker, 'bind', error_for_explicit_ports):
             # Without server, this can be little flaky, so check that it
@@ -295,7 +343,7 @@ class PickUnusedPortTest(unittest.TestCase):
 
         # Now test the second part, the fallback from above, which asks the
         # OS for a port.
-        def mock_port_free(port):
+        def mock_port_free(unused_port):
             return False
 
         with mock.patch.object(portpicker, 'is_port_free', mock_port_free):
@@ -386,5 +434,92 @@ class PickUnusedPortTest(unittest.TestCase):
                          portpicker.GetPortFromPortServer)
 
 
+def get_open_listen_tcp_ports():
+    netstat = subprocess.run(['netstat', '-lnt'], capture_output=True,
+                             encoding='utf-8')
+    if netstat.returncode != 0:
+        raise unittest.SkipTest('Unable to run netstat -lnt to list binds.')
+    rows = (line.split() for line in netstat.stdout.splitlines())
+    listen_addrs = (row[3] for row in rows if row[0].startswith('tcp'))
+    listen_ports = [int(addr.split(':')[-1]) for addr in listen_addrs]
+    return listen_ports
+
+
+@unittest.skipUnless((sys.executable and os.access(sys.executable, os.X_OK))
+                     or (os.environ.get('TEST_PORTPICKER_CLI') and
+                         os.access(os.environ['TEST_PORTPICKER_CLI'], os.X_OK)),
+                     'sys.executable portpicker.__file__ not launchable and '
+                     ' no TEST_PORTPICKER_CLI supplied.')
+class PortpickerCommandLineTests(unittest.TestCase):
+    def setUp(self):
+        self.main_py = portpicker.__file__
+
+    def _run_portpicker(self, pp_args, env_override=None):
+        env = dict(os.environ)
+        if env_override:
+            env.update(env_override)
+        if os.environ.get('TEST_PORTPICKER_CLI'):
+            pp_command = [os.environ['TEST_PORTPICKER_CLI']]
+        else:
+            pp_command = [sys.executable, '-m', 'portpicker']
+        return subprocess.run(pp_command + pp_args,
+                              capture_output=True,
+                              env=env,
+                              encoding='utf-8',
+                              check=False)
+
+    def test_command_line_help(self):
+        cmd = self._run_portpicker(['-h'])
+        self.assertNotEqual(0, cmd.returncode)
+        self.assertIn('usage', cmd.stdout)
+        self.assertIn('passed an arg', cmd.stdout)
+        cmd = self._run_portpicker(['--help'])
+        self.assertNotEqual(0, cmd.returncode)
+        self.assertIn('usage', cmd.stdout)
+        self.assertIn('passed an arg', cmd.stdout)
+
+    def test_command_line_help_text_dedented(self):
+        cmd = self._run_portpicker(['-h'])
+        self.assertNotEqual(0, cmd.returncode)
+        self.assertIn('\nIf passed an arg', cmd.stdout)
+        self.assertIn('\n  #!/bin/bash', cmd.stdout)
+        self.assertIn('\nOlder versions ', cmd.stdout)
+
+    def test_command_line_interface(self):
+        cmd = self._run_portpicker([str(os.getpid())])
+        cmd.check_returncode()
+        port = int(cmd.stdout)
+        self.assertNotEqual(0, port, msg=cmd)
+        listen_ports = sorted(get_open_listen_tcp_ports())
+        self.assertNotIn(port, listen_ports, msg='expected nothing to be bound to port.')
+
+    def test_command_line_interface_no_portserver(self):
+        cmd = self._run_portpicker([str(os.getpid())],
+                                   env_override={'PORTSERVER_ADDRESS': ''})
+        cmd.check_returncode()
+        port = int(cmd.stdout)
+        self.assertNotEqual(0, port, msg=cmd)
+        listen_ports = sorted(get_open_listen_tcp_ports())
+        self.assertNotIn(port, listen_ports, msg='expected nothing to be bound to port.')
+
+    def test_command_line_interface_no_portserver_bind_timeout(self):
+        # This test is timing sensitive and leaves that bind process hanging
+        # around consuming resources until it dies on its own unless the test
+        # runner kills the process group upon exit.
+        timeout = 9.5
+        before = time.monotonic()
+        cmd = self._run_portpicker([str(os.getpid()), str(timeout)],
+                                   env_override={'PORTSERVER_ADDRESS': ''})
+        self.assertEqual(0, cmd.returncode, msg=(cmd.stdout, cmd.stderr))
+        port = int(cmd.stdout)
+        self.assertNotEqual(0, port, msg=cmd)
+        if 'WARNING' in cmd.stderr:
+            raise unittest.SkipTest('bind timeout not supported on this platform.')
+        listen_ports = sorted(get_open_listen_tcp_ports())
+        self.assertIn(port, listen_ports, msg='expected port to be bound. '
+                      '%f seconds elapsed of %f bind timeout.' %
+                      (time.monotonic() - before, timeout))
+
+
 if __name__ == '__main__':
     unittest.main()
diff --git a/src/tests/portserver_test.py b/src/tests/portserver_test.py
index b7de094..f0dec17 100644
--- a/src/tests/portserver_test.py
+++ b/src/tests/portserver_test.py
@@ -34,7 +34,12 @@ import portpicker
 if sys.platform == 'win32':
     sys.path.append(os.path.join(os.path.split(sys.executable)[0]))
 
-import portserver
+try:
+    import portserver
+except ImportError:
+    # Or if testing from a third_party/py/portpicker/ style installed
+    # package tree find it this way.
+    from portpicker import portserver
 
 
 def setUpModule():
```

