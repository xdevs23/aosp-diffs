```diff
diff --git a/Android.bp b/Android.bp
index 4b2b251..9bb474b 100644
--- a/Android.bp
+++ b/Android.bp
@@ -62,6 +62,7 @@ cc_library {
 
     cflags: [
         "-D_GNU_SOURCE",
+        "-Wno-gnu",
         "-Wno-unused-parameter",
     ],
 
diff --git a/Documentation/install-docs.sh.in b/Documentation/install-docs.sh.in
new file mode 100755
index 0000000..eca9b1f
--- /dev/null
+++ b/Documentation/install-docs.sh.in
@@ -0,0 +1,20 @@
+#!/bin/bash
+# SPDX-License-Identifier: LGPL-2.1
+#
+# Copyright (c) 2023 Daniel Wagner, SUSE LLC
+
+for section in 1 3 5; do
+    while IFS= read -r -d '' man; do
+        [ ! -d "${DESTDIR}@MANDIR@/man${section}" ] && install -d "${DESTDIR}@MANDIR@/man${section}"
+
+        echo Installing "${man}" to "${DESTDIR}@MANDIR@/man${section}"
+        install -m 0644 "${man}" "${DESTDIR}@MANDIR@/man${section}/"
+    done< <(find "@SRCDIR@" -name "*\.${section}" -type f -print0)
+done
+
+while IFS= read -r -d '' html; do
+    [ ! -d "${DESTDIR}@HTMLDIR@"  ] && install -d "${DESTDIR}@HTMLDIR@"
+
+    echo Installing "${html}" to "${DESTDIR}@HTMLDIR@"
+    install -m 0644 "${html}" "${DESTDIR}@HTMLDIR@"
+done< <(find "@SRCDIR@" -name "*\.html" -type f -print0)
diff --git a/Documentation/libtracefs-cpu-buf.txt b/Documentation/libtracefs-cpu-buf.txt
new file mode 100644
index 0000000..943cb1f
--- /dev/null
+++ b/Documentation/libtracefs-cpu-buf.txt
@@ -0,0 +1,171 @@
+libtracefs(3)
+=============
+
+NAME
+----
+tracefs_cpu_read_buf, tracefs_cpu_buffered_read_buf, tracefs_cpu_flush_buf
+- Reading trace_pipe_raw data returning a kbuffer
+
+SYNOPSIS
+--------
+[verse]
+--
+*#include <tracefs.h>*
+
+struct kbuffer pass:[*]*tracefs_cpu_read_buf*(struct tracefs_cpu pass:[*]_tcpu_, bool _nonblock_);
+struct kbuffer pass:[*]*tracefs_cpu_buffered_read_buf*(struct tracefs_cpu pass:[*]_tcpu_, bool _nonblock_);
+struct kbuffer pass:[*]*tracefs_cpu_flush_buf*(struct tracefs_cpu pass:[*]_tcpu_);
+--
+
+DESCRIPTION
+-----------
+This set of APIs can be used to read the raw data from the trace_pipe_raw
+files in the tracefs file system and return a kbuffer structure to read it with.
+
+The *tracefs_cpu_read_buf()* reads the trace_pipe_raw files associated to _tcpu_
+and returns a kbuffer structure that can be used to iterate the events.
+If _nonblock_ is set, and there's no data available, it will return immediately.
+Otherwise depending on how _tcpu_ was opened, it will block. If _tcpu_ was
+opened with nonblock set, then this _nonblock_ will make no difference.
+
+The *tracefs_cpu_buffered_read_buf()* is basically the same as *tracefs_cpu_read_buf()*
+except that it uses a pipe through splice to buffer reads. This will batch
+reads keeping the reading from the ring buffer less intrusive to the system,
+as just reading all the time can cause quite a disturbance. Note, one
+difference between this and *tracefs_cpu_read()* is that it will read only in
+sub buffer pages. If the ring buffer has not filled a page, then it will not
+return anything, even with _nonblock_ set.  Calls to *tracefs_cpu_flush_buf()*
+or *tracefs_cpu_flush()* should be done to read the rest of the file at the
+end of the trace.
+
+The *tracefs_cpu_flush_buf()* reads the trace_pipe_raw file associated by the
+_tcpu_ and puts it into _buffer_, which must be the size of the sub buffer
+which is retrieved.  This should be called at the end of tracing
+to get the rest of the data. This call will convert the file descriptor of
+trace_pipe_raw into non-blocking mode.
+
+RETURN VALUE
+------------
+The functions *tracefs_cpu_read_buf()*, tracefs_cpu_buffered_read_buf()* and
+*tracefs_cpu_flush()* returns a kbuffer descriptor that can be iterated
+over to find the events. Note, this descriptor is part of the tracefs_cpu structure
+and should not be freed. It will be freed. It returns NULL on error or if nonblock
+is set and there are no events available. In the case of no events, errno will be
+set with EAGAIN.
+
+EXAMPLE
+-------
+[source,c]
+--
+#include <stdlib.h>
+#include <ctype.h>
+#include <tracefs.h>
+
+static void read_page(struct tep_handle *tep, struct kbuffer *kbuf)
+{
+	static struct trace_seq seq;
+	struct tep_record record;
+
+	if (seq.buffer)
+		trace_seq_reset(&seq);
+	else
+		trace_seq_init(&seq);
+
+	while ((record.data = kbuffer_read_event(kbuf, &record.ts))) {
+		record.size = kbuffer_event_size(kbuf);
+		kbuffer_next_event(kbuf, NULL);
+		tep_print_event(tep, &seq, &record,
+				"%s-%d %9d\t%s: %s\n",
+				TEP_PRINT_COMM,
+				TEP_PRINT_PID,
+				TEP_PRINT_TIME,
+				TEP_PRINT_NAME,
+				TEP_PRINT_INFO);
+		trace_seq_do_printf(&seq);
+		trace_seq_reset(&seq);
+	}
+}
+
+int main (int argc, char **argv)
+{
+	struct tracefs_cpu *tcpu;
+	struct tep_handle *tep;
+	struct kbuffer *kbuf;
+	int cpu;
+
+	if (argc < 2 || !isdigit(argv[1][0])) {
+		printf("usage: %s cpu\n\n", argv[0]);
+		exit(-1);
+	}
+
+	cpu = atoi(argv[1]);
+
+	tep = tracefs_local_events(NULL);
+	if (!tep) {
+		perror("Reading trace event formats");
+		exit(-1);
+	}
+
+	tcpu = tracefs_cpu_open(NULL, cpu, 0);
+	if (!tcpu) {
+		perror("Open CPU 0 file");
+		exit(-1);
+	}
+
+	while ((kbuf = tracefs_cpu_buffered_read_buf(tcpu, true))) {
+		read_page(tep, kbuf);
+	}
+
+	kbuf = tracefs_cpu_flush_buf(tcpu);
+	if (kbuf)
+		read_page(tep, kbuf);
+
+	tracefs_cpu_close(tcpu);
+	tep_free(tep);
+
+	return 0;
+}
+--
+FILES
+-----
+[verse]
+--
+*tracefs.h*
+	Header file to include in order to have access to the library APIs.
+*-ltracefs*
+	Linker switch to add when building a program that uses the library.
+--
+
+SEE ALSO
+--------
+*tracefs_cpu_open*(3)
+*tracefs_cpu_close*(3)
+*tracefs_cpu_read*(3)
+*tracefs_cpu_buffered_read*(3)
+*tracefs_cpu_flush*(3)
+*libtracefs*(3),
+*libtraceevent*(3),
+*trace-cmd*(1)
+
+AUTHOR
+------
+[verse]
+--
+*Steven Rostedt* <rostedt@goodmis.org>
+--
+REPORTING BUGS
+--------------
+Report bugs to  <linux-trace-devel@vger.kernel.org>
+
+LICENSE
+-------
+libtracefs is Free Software licensed under the GNU LGPL 2.1
+
+RESOURCES
+---------
+https://git.kernel.org/pub/scm/libs/libtrace/libtracefs.git/
+
+COPYING
+-------
+Copyright \(C) 2022 Google, Inc. Free use of this software is granted under
+the terms of the GNU Public License (GPL).
diff --git a/Documentation/libtracefs-cpu-map.txt b/Documentation/libtracefs-cpu-map.txt
new file mode 100644
index 0000000..d961123
--- /dev/null
+++ b/Documentation/libtracefs-cpu-map.txt
@@ -0,0 +1,218 @@
+libtracefs(3)
+=============
+
+NAME
+----
+tracefs_cpu_open_mapped, tracefs_cpu_is_mapped, tracefs_mapped_is_supported, tracefs_cpu_map, tracefs_cpu_unmap - Memory mapping of the ring buffer
+
+SYNOPSIS
+--------
+[verse]
+--
+*#include <tracefs.h>*
+
+bool *tracefs_cpu_is_mapped*(struct tracefs_cpu pass:[*]tcpu);
+bool *tracefs_mapped_is_supported*(void);
+int *tracefs_cpu_map*(struct tracefs_cpu pass:[*]tcpu);
+void *tracefs_cpu_unmap*(struct tracefs_cpu pass:[*]tcpu);
+struct tracefs_cpu pass:[*]*tracefs_cpu_open_mapped*(struct tracefs_instance pass:[*]instance,
+					    int cpu, bool nonblock);
+--
+
+DESCRIPTION
+-----------
+If the trace_pipe_raw supports memory mapping, this is usually a more efficient
+method to stream data from the kernel ring buffer than by reading it, as it does
+not require copying the memory that is being read.
+
+If memory mapping is supported by the kernel and the application asks to use the
+memory mapping via either *tracefs_cpu_map()* or by *tracefs_cpu_open_mapped()*
+then the functions *tracefs_cpu_read*(3) and *tracefs_cpu_read_buf*(3) will use
+the mapping directly instead of calling the read system call.
+
+Note, mapping will cause *tracefs_cpu_buffered_read*(3) and *tracefs_cpu_buffered_read_buf*(3)
+to act just like *tracefs_cpu_read*(3) and *tracefs_cpu_read_buf*(3) respectively
+as it doesn't make sense to use a splice pipe when mapped. The kernel will do
+a copy for splice reads on mapping, and then another copy in the function when
+it can avoid the copying if the ring buffer is memory mapped.
+
+If the _tcpu_ is memory mapped it will also force *tracefs_cpu_write*(3) and
+*tracefs_cpu_pipe*(3) to copy from the mapping instead of using splice.
+Thus care must be used when determining to map the ring buffer or not,
+and why it does not get mapped by default.
+
+The *tracefs_cpu_is_mapped()* function will return true if _tcpu_ currently has
+its ring buffer memory mapped and false otherwise. This does not return whether or
+not that the kernel supports memory mapping, but that can usually be determined
+by calling *tracefs_cpu_map()*.
+
+The *tracefs_mapped_is_supported()* returns true if the ring buffer can be
+memory mapped.
+
+The *tracefs_cpu_map()* function will attempt to map the ring buffer associated
+to _tcpu_ if it is not already mapped.
+
+The *tracefs_cpu_unmap()* function will unmap the ring buffer associated to
+_tcpu_ if it is mapped.
+
+The *tracefs_cpu_open_mapped()* is equivalent to calling *tracefs_cpu_open*(3) followed
+by *tracefs_cpu_map()* on the returned _tcpu_ of *tracefs_cpu_open*(3). Note, this
+will still succeed if the mapping fails, in which case it acts the same as
+*tracefs_cpu_open*(3). If knowing if the mapping succeed or not, *tracefs_cpu_is_mapped()*
+should be called on the return _tcpu_.
+
+RETURN VALUE
+------------
+*tracefs_cpu_is_mapped()* returns true if the given _tcpu_ has its ring buffer
+memory mapped or false otherwise.
+
+*tracefs_mapped_is_supported()* returns true if the tracing ring buffer can be
+memory mapped or false if it cannot be or an error occurred.
+
+*tracefs_cpu_map()* returns 0 on success and -1 on error in mapping. If 0 is
+returned then *tracefs_cpu_is_mapped()* will return true afterward, or false
+if the mapping failed.
+
+*tracefs_cpu_open_mapped()* returns an allocated tracefs_cpu on success of creation
+regardless if it succeed in mapping the ring buffer or not. It returns NULL for
+the same reasons *tracefs_cpu_open*(3) returns NULL. If success of mapping is
+to be known, then calling *tracefs_cpu_is_mapped()* afterward is required.
+
+EXAMPLE
+-------
+[source,c]
+--
+#include <stdlib.h>
+#include <ctype.h>
+#include <tracefs.h>
+
+static void read_subbuf(struct tep_handle *tep, struct kbuffer *kbuf)
+{
+	static struct trace_seq seq;
+	struct tep_record record;
+	int missed_events;
+
+	if (seq.buffer)
+		trace_seq_reset(&seq);
+	else
+		trace_seq_init(&seq);
+
+	while ((record.data = kbuffer_read_event(kbuf, &record.ts))) {
+		record.size = kbuffer_event_size(kbuf);
+		missed_events = kbuffer_missed_events(kbuf);
+		if (missed_events) {
+			printf("[MISSED EVENTS");
+			if (missed_events > 0)
+				printf(": %d]\n", missed_events);
+			else
+				printf("]\n");
+		}
+		kbuffer_next_event(kbuf, NULL);
+		tep_print_event(tep, &seq, &record,
+				"%s-%d %6.1000d\t%s: %s\n",
+				TEP_PRINT_COMM,
+				TEP_PRINT_PID,
+				TEP_PRINT_TIME,
+				TEP_PRINT_NAME,
+				TEP_PRINT_INFO);
+		trace_seq_do_printf(&seq);
+		trace_seq_reset(&seq);
+	}
+}
+
+int main (int argc, char **argv)
+{
+	struct tracefs_cpu *tcpu;
+	struct tep_handle *tep;
+	struct kbuffer *kbuf;
+	bool mapped;
+	int cpu;
+
+	if (argc < 2 || !isdigit(argv[1][0])) {
+		printf("usage: %s cpu\n\n", argv[0]);
+		exit(-1);
+	}
+
+	cpu = atoi(argv[1]);
+
+	tep = tracefs_local_events(NULL);
+	if (!tep) {
+		perror("Reading trace event formats");
+		exit(-1);
+	}
+
+	tcpu = tracefs_cpu_open_mapped(NULL, cpu, 0);
+	if (!tcpu) {
+		perror("Open CPU 0 file");
+		exit(-1);
+	}
+
+	/*
+	 * If this kernel supports mapping, use normal read,
+	 * otherwise use the piped buffer read, although if
+	 * the mapping succeeded, tracefs_cpu_buffered_read_buf()
+	 * acts the same as tracefs_cpu_read_buf(). But this is just
+	 * an example on how to use tracefs_cpu_is_mapped().
+	 */
+	mapped = tracefs_cpu_is_mapped(tcpu);
+	if (!mapped)
+		printf("Was not able to map, falling back to buffered read\n");
+	while ((kbuf = mapped ? tracefs_cpu_read_buf(tcpu, true) :
+			tracefs_cpu_buffered_read_buf(tcpu, true))) {
+		read_subbuf(tep, kbuf);
+	}
+
+	kbuf = tracefs_cpu_flush_buf(tcpu);
+	if (kbuf)
+		read_subbuf(tep, kbuf);
+
+	tracefs_cpu_close(tcpu);
+	tep_free(tep);
+
+	return 0;
+}
+--
+
+FILES
+-----
+[verse]
+--
+*tracefs.h*
+	Header file to include in order to have access to the library APIs.
+*-ltracefs*
+	Linker switch to add when building a program that uses the library.
+--
+
+SEE ALSO
+--------
+*tracefs_cpu_open*(3),
+*tracefs_cpu_read*(3),
+*tracefs_cpu_read_buf*(3),
+*tracefs_cpu_buffered_read*(3),
+*tracefs_cpu_buffered_read_buf*(3),
+*libtracefs*(3),
+*libtraceevent*(3),
+*trace-cmd*(1)
+
+AUTHOR
+------
+[verse]
+--
+*Steven Rostedt* <rostedt@goodmis.org>
+--
+REPORTING BUGS
+--------------
+Report bugs to  <linux-trace-devel@vger.kernel.org>
+
+LICENSE
+-------
+libtracefs is Free Software licensed under the GNU LGPL 2.1
+
+RESOURCES
+---------
+https://git.kernel.org/pub/scm/libs/libtrace/libtracefs.git/
+
+COPYING
+-------
+Copyright \(C) 2022 Google, Inc. Free use of this software is granted under
+the terms of the GNU Public License (GPL).
diff --git a/Documentation/libtracefs-cpu-open.txt b/Documentation/libtracefs-cpu-open.txt
index c5a900a..613a71d 100644
--- a/Documentation/libtracefs-cpu-open.txt
+++ b/Documentation/libtracefs-cpu-open.txt
@@ -3,7 +3,7 @@ libtracefs(3)
 
 NAME
 ----
-tracefs_cpu_open, tracefs_cpu_close, tracefs_cpu_alloc_fd, tracefs_cpu_free_fd - Opening trace_pipe_raw data for reading
+tracefs_cpu_open, tracefs_cpu_close, tracefs_cpu_alloc_fd, tracefs_cpu_free_fd, tracefs_cpu_snapshot_open - Opening trace_pipe_raw data for reading
 
 SYNOPSIS
 --------
@@ -17,6 +17,9 @@ void *tracefs_cpu_close*(struct tracefs_cpu pass:[*]_tcpu_);
 
 struct tracefs_cpu pass:[*]*tracefs_cpu_alloc_fd*(int _fd_, int _subbuf_size_, bool _nonblock_);
 void *tracefs_cpu_free_fd*(struct tracefs_cpu pass:[*]_tcpu_);
+
+struct tracefs_cpu pass:[*]*tracefs_cpu_snapshot_open*(struct tracefs_instance pass:[*]_instance_,
+					     int _cpu_, bool _nonblock_);
 --
 
 DESCRIPTION
@@ -47,10 +50,17 @@ the file descriptor passed in. Note that *tracefs_cpu_free_fd()* should not be u
 on the descriptor returned by *tracefs_cpu_open()* as it will not close the file descriptor
 created by it.
 
+The *tracefs_cpu_snapshot_open()* is similar to *tracefs_cpu_open()* except that it
+opens the snapshot buffer (see *tracefs_snapshot_snap*(3)). The snapshot buffer
+does not have a writer to it, it is only created by a snapshot action that swaps
+the current ring buffer with the snapshot buffer. The _nonblock_, when false, acts a little
+differently here too. Reads are not affected by the "buffer_percent" file. If the
+snapshot buffer is empty, it will block until a new snapshot happens.
+
 RETURN VALUE
 ------------
-The *tracefs_cpu_open()* returns a struct tracefs_cpu descriptor that can be
-used by the other functions or NULL on error.
+The *tracefs_cpu_open()* and *tracefs_cpu_snapshot_open() both return a struct
+tracefs_cpu descriptor that can be used by the other functions or NULL on error.
 
 The *tracefs_cpu_alloc_fd()* returns a struct tracefs_cpu descriptor that can
 be used by the *tracefs_cpu_read*(3) related functions, where the descriptor
diff --git a/Documentation/libtracefs-cpu.txt b/Documentation/libtracefs-cpu.txt
index d6215d9..6fb6524 100644
--- a/Documentation/libtracefs-cpu.txt
+++ b/Documentation/libtracefs-cpu.txt
@@ -212,6 +212,9 @@ SEE ALSO
 --------
 *tracefs_cpu_open*(3)
 *tracefs_cpu_close*(3)
+*tracefs_cpu_read_buf*(3)
+*tracefs_cpu_buffered_read_buf*(3)
+*tracefs_cpu_flush_buf*(3)
 *libtracefs*(3),
 *libtraceevent*(3),
 *trace-cmd*(1)
diff --git a/Documentation/libtracefs-events-file.txt b/Documentation/libtracefs-events-file.txt
index 425eebd..1a298b3 100644
--- a/Documentation/libtracefs-events-file.txt
+++ b/Documentation/libtracefs-events-file.txt
@@ -23,8 +23,7 @@ int *tracefs_event_file_append*(struct tracefs_instance pass:[*]_instance_, cons
 int *tracefs_event_file_clear*(struct tracefs_instance pass:[*]_instance_, const char pass:[*]_system_, const char pass:[*]_event_,
 			     const char pass:[*]_file_);
 bool *tracefs_event_file_exists*(struct tracefs_instance pass:[*]_instance_, const char pass:[*]_system_, const char pass:[*]_event_,
-			       const char pass:[*]_file_)
-
+			       const char pass:[*]_file_);
 --
 
 DESCRIPTION
diff --git a/Documentation/libtracefs-events-tep.txt b/Documentation/libtracefs-events-tep.txt
index 22d3dd5..ba46532 100644
--- a/Documentation/libtracefs-events-tep.txt
+++ b/Documentation/libtracefs-events-tep.txt
@@ -4,7 +4,7 @@ libtracefs(3)
 NAME
 ----
 tracefs_local_events, tracefs_local_events_system, tracefs_fill_local_events,
-tracefs_load_cmdlines -
+tracefs_load_cmdlines, tracefs_load_headers -
 Initialize a tep handler with trace events from the local system.
 
 SYNOPSIS
@@ -17,6 +17,7 @@ struct tep_handle pass:[*]*tracefs_local_events*(const char pass:[*]_tracing_dir
 struct tep_handle pass:[*]*tracefs_local_events_system*(const char pass:[*]_tracing_dir_, const char pass:[*] const pass:[*]_sys_names_);
 int *tracefs_fill_local_events*(const char pass:[*]_tracing_dir_, struct tep_handle pass:[*]_tep_, int pass:[*]_parsing_failures_);
 int *tracefs_load_cmdlines*(const char pass:[*]_tracing_dir_, struct tep_handle pass:[*]_tep_);
+int *tracefs_load_headers*(const char pass:[*]_tracing_dir_, struct tep_handle pass:[*]_tep_);
 --
 
 DESCRIPTION
@@ -55,6 +56,10 @@ The *tracefs_load_cmdlines()* does just that. The _tracing_dir_ is
 the directory of the mount point to load from, or NULL to use the
 mount point of the tracefs file system.
 
+The *tracefs_load_headers()* will reade the "header_page" of the events
+directory that will update the _tep_ handle with information on how to parse the
+tracing ring buffer sub-buffer.
+
 RETURN VALUE
 ------------
 The *tracefs_local_events()* and *tracefs_local_events_system()* functions
diff --git a/Documentation/libtracefs-filter-pid.txt b/Documentation/libtracefs-filter-pid.txt
new file mode 100644
index 0000000..fa56b02
--- /dev/null
+++ b/Documentation/libtracefs-filter-pid.txt
@@ -0,0 +1,181 @@
+libtracefs(3)
+=============
+
+NAME
+----
+tracefs_filter_pid_function, tracefs_filter_pid_events, tracefs_filter_pid_function_clear, tracefs_filter_pid_events_clear -
+Add and remove PID filtering for functions and events
+
+SYNOPSIS
+--------
+[verse]
+--
+*#include <tracefs.h>*
+
+int *tracefs_filter_pid_function*(struct tracefs_instance pass:[*]_instance,_ int _pid_,
+				bool _reset_, bool _notrace_);
+int *tracefs_filter_pid_function_clear*(struct tracefs_instance pass:[*]_instance_, bool _notrace_);
+int *tracefs_filter_pid_events*(struct tracefs_instance pass:[*]_instance_, int _pid_,
+			     bool _reset_, bool _notrace_);
+int *tracefs_filter_pid_events_clear*(struct tracefs_instance pass:[*]_instance_, bool _notrace_);
+--
+
+DESCRIPTION
+-----------
+Both events and functions can be filtered by PID, but they are done separately.
+PID filtering for functions affect the function and function_graph tracer, where
+as PID filtering for events affect all events such as _sched_switch_ and _sched_waking_.
+If the *TRACEFS_OPTION_FUNCTION_FORK* is enabled (see *tracefs_option_enable*(3)),
+any PID that is set as part of the function PID filtering will automatically
+have its children added when they are spawned, as well as the PID removed when
+they exit. If the *TRACEFS_OPTION_EVENT_FORK* is set, the same is true for
+event PID filtering. This also includes the _notrace_ option where the child
+threads and processes of PIDs that are labled as notrace will also not be
+traced.
+
+The *tracefs_filter_pid_function()* affects function PID filtering and *tracefs_filter_pid_events()*
+affects the PID event filtering. For both functions, they add a _pid_ to be filtered in the given _instance_.
+If _reset_ is true, then any PIDs already being filtered will be removed, otherwise
+the _pid_ is simply added to the filtering. If _notrace_ is true, then the PID
+is added to the list of PIDs that are not to be traced. Note, that _reset_ only affects
+the list associated with _notrace_. That is, if both _reset_ and _notrace_ are true,
+then it will not affect PIDs that are to be traced. Same is if _reset_ is true and _notrace_
+is false, it will not affect PIDs that are not to be traced.
+
+The *tracefs_filter_pid_function_clear()* affects function PID filtering and
+*tracefs_filter_pid_events_clear()* affects the PID event filtering. For both
+functions it will clear all the PIDs that are being filtered for the given
+filter. If _notrace_ is true it clears all the PIDs that are not to be traced
+otherwise if it is false, it clears all the PIDs that are to be traced.
+
+RETURN VALUE
+------------
+All the functions return 0 on success and -1 on error.
+
+EXAMPLE
+-------
+[source,c]
+--
+#include <stdlib.h>
+#include <stdio.h>
+#include <ctype.h>
+#include <tracefs.h>
+
+static void usage(char **argv)
+{
+	fprintf(stderr, "usage: %s [-e|-f][-c|-n] pid [pid ...]\n", argv[0]);
+	fprintf(stderr, "   -e enable event filter\n");
+	fprintf(stderr, "   -f enable function filter\n");
+	fprintf(stderr, "     (default is both, function and event)\n");
+	fprintf(stderr, "   -c clear the filter\n");
+	fprintf(stderr, "   -n notrace filter\n");
+	exit(-1);
+}
+
+int main (int argc, char **argv)
+{
+	bool events = false;
+	bool funcs = false;
+	bool neg = false;
+	bool clear = false;
+	bool reset = true;
+	int i;
+
+	for (i = 1; i < argc && argv[i][0] == '-'; i++) {
+		char *arg = argv[i];
+		int c;
+		for (c = 1; arg[c]; c++) {
+			switch (arg[c]) {
+			case 'e': events = true; break;
+			case 'f': funcs = true; break;
+			case 'n': neg = true; break;
+			case 'c': clear = true; break;
+			default:
+				usage(argv);
+			}
+		}
+		if (c == 1)
+			usage(argv);
+	}
+
+	if (i == argc && !clear)
+		usage(argv);
+
+	if (!events && !funcs) {
+		events = true;
+		funcs = true;
+	}
+
+	if (clear) {
+		if (events)
+			tracefs_filter_pid_events_clear(NULL, neg);
+		if (funcs)
+			tracefs_filter_pid_function_clear(NULL, neg);
+		exit(0);
+	}
+
+	for (; i < argc; i++) {
+		int pid = atoi(argv[i]);
+
+		if (events)
+			tracefs_filter_pid_events(NULL, pid, reset, neg);
+		if (funcs)
+			tracefs_filter_pid_function(NULL, pid, reset, neg);
+
+		reset = false;
+	}
+
+	exit(0);
+}
+
+--
+
+FILES
+-----
+[verse]
+--
+*tracefs.h*
+	Header file to include in order to have access to the library APIs.
+*-ltracefs*
+	Linker switch to add when building a program that uses the library.
+--
+
+SEE ALSO
+--------
+*libtracefs*(3),
+*libtraceevent*(3),
+*trace-cmd*(1),
+*tracefs_hist_alloc*(3),
+*tracefs_hist_alloc_2d*(3),
+*tracefs_hist_alloc_nd*(3),
+*tracefs_hist_free*(3),
+*tracefs_hist_add_key*(3),
+*tracefs_hist_add_value*(3),
+*tracefs_hist_add_name*(3),
+*tracefs_hist_start*(3),
+*tracefs_hist_destory*(3),
+*tracefs_hist_add_sort_key*(3),
+*tracefs_hist_sort_key_direction*(3)
+
+AUTHOR
+------
+[verse]
+--
+*Steven Rostedt* <rostedt@goodmis.org>
+--
+REPORTING BUGS
+--------------
+Report bugs to  <linux-trace-devel@vger.kernel.org>
+
+LICENSE
+-------
+libtracefs is Free Software licensed under the GNU LGPL 2.1
+
+RESOURCES
+---------
+https://git.kernel.org/pub/scm/libs/libtrace/libtracefs.git/
+
+COPYING
+-------
+Copyright \(C) 2023 Google, LLC. Free use of this software is granted under
+the terms of the GNU Public License (GPL).
diff --git a/Documentation/libtracefs-guest.txt b/Documentation/libtracefs-guest.txt
new file mode 100644
index 0000000..16ce020
--- /dev/null
+++ b/Documentation/libtracefs-guest.txt
@@ -0,0 +1,188 @@
+libtracefs(3)
+=============
+
+NAME
+----
+tracefs_find_cid_pid, tracefs_instance_find_cid_pid, tracefs_time_conversion -
+helper functions to handle tracing guests
+
+SYNOPSIS
+--------
+[verse]
+--
+*#include <tracefs.h>*
+
+char pass:[*]*tracefs_find_cid_pid*(int _cid_);
+char pass:[*]*tracefs_instance_find_cid_pid*(struct tracefs_instance pass:[*]_instance_, int _cid_);
+int *tracefs_time_conversion*(int _cpu_, int pass:[*]_shift_, int pass:[*]_multi_, long long pass:[*]offset);
+--
+
+DESCRIPTION
+-----------
+The *tracefs_find_cid_pid*() will use tracing to follow the wakeups of connecting to
+the given _cid_ in order to find the pid of the guest thread that belongs to the vsocket cid.
+It will then read the proc file system to find the thread leader, and it will return
+the pid of the thread leader.
+
+The *tracefs_instance_find_cid_pid*() is the same as *tracefs_find_cid_pid*() but defines
+the instance to use to perform the tracing in. If NULL it will use the top level
+buffer to perform the tracing.
+
+The *tracefs_time_conversion*() will return the values used by the kernel to convert
+the raw time stamp counter into nanoseconds for the given _cpu_. Pointers for _shift_, _multi_
+and _offset_ can be NULL to be ignored, otherwise they are set with the shift, multiplier
+and offset repectively.
+
+RETURN VALUE
+------------
+Both *tracefs_find_cid_pid*() and *tracefs_instance_find_cid_pid*() will return the
+pid of the guest main thread that belongs to the _cid_, or -1 on error (or not found).
+
+EXAMPLE
+-------
+[source,c]
+--
+#include <stdlib.h>
+#include <unistd.h>
+#include <tracefs.h>
+
+#define MAX_CID		256
+
+static void find_cid(struct tracefs_instance *instance, int cid)
+{
+	int pid;
+
+	pid = tracefs_instance_find_cid_pid(instance, cid);
+	if (pid >= 0)
+		printf("%d\t%d\n", cid, pid);
+}
+
+static int find_cids(void)
+{
+	struct tracefs_instance *instance;
+	char *name;
+	int cid;
+	int ret;
+
+	ret = asprintf(&name, "vsock_find-%d\n", getpid());
+	if (ret < 0)
+		return ret;
+
+	instance = tracefs_instance_create(name);
+	free(name);
+	if (!instance)
+		return -1;
+
+	for (cid = 0; cid < MAX_CID; cid++)
+		find_cid(instance, cid);
+
+	tracefs_event_disable(instance, NULL, NULL);
+	tracefs_instance_destroy(instance);
+	tracefs_instance_free(instance);
+	return 0;
+}
+
+struct time_info {
+	int		shift;
+	int		multi;
+};
+
+static void show_time_conversion(void)
+{
+	struct time_info *tinfo;
+	int cpus;
+	int cpu;
+	int ret;
+
+	cpus = sysconf(_SC_NPROCESSORS_CONF);
+	tinfo = calloc(cpus, sizeof(*tinfo));
+	if (!tinfo)
+		exit(-1);
+
+	for (cpu = 0; cpu < cpus; cpu++) {
+		ret  = tracefs_time_conversion(cpu,
+						&tinfo[cpu].shift,
+						&tinfo[cpu].multi,
+						NULL);
+		if (ret)
+			break;
+	}
+	if (cpu != cpus) {
+		if (!cpu) {
+			perror("tracefs_time_conversion");
+			exit(-1);
+		}
+		printf("Only read %d of %d CPUs", cpu, cpus);
+		cpus = cpu + 1;
+	}
+
+	/* Check if all the shift and mult values are the same */
+	for (cpu = 1; cpu < cpus; cpu++) {
+		if (tinfo[cpu - 1].shift != tinfo[cpu].shift)
+			break;
+		if (tinfo[cpu - 1].multi != tinfo[cpu].multi)
+			break;
+	}
+
+	if (cpu == cpus) {
+		printf("All cpus have:\n");
+		printf(" shift:  %d\n", tinfo[0].shift);
+		printf(" multi:  %d\n", tinfo[0].multi);
+		printf("\n");
+		return;
+	}
+
+	for (cpu = 0; cpu < cpus; cpu++) {
+		printf("CPU: %d\n", cpu);
+		printf(" shift:  %d\n", tinfo[cpu].shift);
+		printf(" multi:  %d\n", tinfo[cpu].multi);
+		printf("\n");
+	}
+}
+
+int main(int argc, char *argv[])
+{
+	show_time_conversion();
+	find_cids();
+	exit(0);
+}
+--
+FILES
+-----
+[verse]
+--
+*tracefs.h*
+	Header file to include in order to have access to the library APIs.
+*-ltracefs*
+	Linker switch to add when building a program that uses the library.
+--
+
+SEE ALSO
+--------
+*libtracefs*(3),
+*libtraceevent*(3),
+*trace-cmd*(1)
+
+AUTHOR
+------
+[verse]
+--
+*Steven Rostedt* <rostedt@goodmis.org>
+*Tzvetomir Stoyanov* <tz.stoyanov@gmail.com>
+--
+REPORTING BUGS
+--------------
+Report bugs to  <linux-trace-devel@vger.kernel.org>
+
+LICENSE
+-------
+libtracefs is Free Software licensed under the GNU LGPL 2.1
+
+RESOURCES
+---------
+https://git.kernel.org/pub/scm/libs/libtrace/libtracefs.git/
+
+COPYING
+-------
+Copyright \(C) 2020 VMware, Inc. Free use of this software is granted under
+the terms of the GNU Public License (GPL).
diff --git a/Documentation/libtracefs-instances-file-manip.txt b/Documentation/libtracefs-instances-file-manip.txt
index 8c04240..bb1b36e 100644
--- a/Documentation/libtracefs-instances-file-manip.txt
+++ b/Documentation/libtracefs-instances-file-manip.txt
@@ -5,7 +5,7 @@ NAME
 ----
 
 tracefs_instance_file_open,
-tracefs_instance_file_write, tracefs_instance_file_append, tracefs_instance_file_clear,
+tracefs_instance_file_write, tracefs_instance_file_write_number, tracefs_instance_file_append, tracefs_instance_file_clear,
 tracefs_instance_file_read, tracefs_instance_file_read_number - Work with files in tracing instances.
 
 SYNOPSIS
@@ -16,6 +16,7 @@ SYNOPSIS
 
 int *tracefs_instance_file_open*(struct tracefs_instance pass:[*]_instance_, const char pass:[*]_file_, int _mode_);
 int *tracefs_instance_file_write*(struct tracefs_instance pass:[*]_instance_, const char pass:[*]_file_, const char pass:[*]_str_);
+int *tracefs_instance_file_write_number*(struct tracefs_instance pass:[*]_instance_, const char pass:[*]_file_, size_t _val_);
 int *tracefs_instance_file_append*(struct tracefs_instance pass:[*]_instance_, const char pass:[*]_file_, const char pass:[*]_str_);
 int *tracefs_instance_file_clear*(struct tracefs_instance pass:[*]_instance_, const char pass:[*]_file_);
 char pass:[*]*tracefs_instance_file_read*(struct tracefs_instance pass:[*]_instance_, const char pass:[*]_file_, int pass:[*]_psize_);
@@ -38,6 +39,10 @@ The *tracefs_instance_file_write()* function writes a string _str_ in a _file_ f
 the given _instance_, without the terminating NULL character. When opening the file, this function
 tries to truncates the size of the file to zero, which clears all previously existing settings.
 
+The *tracefs_instance_file_write_number()* function converts _val_ into a string
+and then writes it to the given file. This is a helper function that does the number
+conversion to string and then calls *tracefs_instance_file_write()*.
+
 The *tracefs_instance_file_append()* function writes a string _str_ in a _file_ from
 the given _instance_, without the terminating NULL character.  This function is similar to
 *tracefs_instance_file_write()*, but the existing content of the is not cleared. Thus the
@@ -61,6 +66,8 @@ closed with *close*(3). In case of an error, -1 is returned.
 The *tracefs_instance_file_write()* function returns the number of written bytes,
 or -1 in case of an error.
 
+The *tracefs_instance_file_write_number()* function returns 0 on success and -1 on error.
+
 The *tracefs_instance_file_append()* function returns the number of written bytes,
 or -1 in case of an error.
 
diff --git a/Documentation/libtracefs-instances-manage.txt b/Documentation/libtracefs-instances-manage.txt
index c03a272..4e5c645 100644
--- a/Documentation/libtracefs-instances-manage.txt
+++ b/Documentation/libtracefs-instances-manage.txt
@@ -4,7 +4,7 @@ libtracefs(3)
 NAME
 ----
 tracefs_instance_create, tracefs_instance_destroy, tracefs_instance_alloc, tracefs_instance_free,
-tracefs_instance_is_new, tracefs_instances - Manage trace instances.
+tracefs_instance_is_new, tracefs_instances, tracefs_instance_clear, tracefs_instance_reset - Manage trace instances.
 
 SYNOPSIS
 --------
@@ -18,6 +18,8 @@ struct tracefs_instance pass:[*]*tracefs_instance_alloc*(const char pass:[*]_tra
 void *tracefs_instance_free*(struct tracefs_instance pass:[*]_instance_);
 bool *tracefs_instance_is_new*(struct tracefs_instance pass:[*]_instance_);
 char pass:[**]*tracefs_instances*(const char pass:[*]_regex_);
+void *tracefs_instance_clear*(struct tracefs_instance pass:[*]_instance_);
+void *tracefs_instance_reset*(struct tracefs_instance pass:[*]_instance_);
 
 --
 
@@ -60,6 +62,11 @@ it will match all instances that exist. The returned list must be freed with
 *tracefs_list_free*(3). Note, if no instances are found an empty list is returned
 and that too needs to be free with *tracefs_list_free*(3).
 
+The *tracefs_instance_clear()* function clears the ring buffer of the given _instance_
+or the top level ring buffer if _instance_ is NULL.
+
+The *tracefs_instance_reset*() function resets the given _instance_ to its default state.
+
 RETURN VALUE
 ------------
 The *tracefs_instance_create()* and *tracefs_instance_alloc()* functions return a pointer to
@@ -80,6 +87,9 @@ The list must be freed with *tracefs_list_free*(3). An empty list is returned if
 no instance exists that matches _regex_, and this needs to be freed with
 *tracefs_list_free*(3) as well. NULL is returned on error.
 
+The *tracefs_instance_clear()* returns 0 if it successfully cleared the ring buffer,
+or -1 on error.
+
 EXAMPLE
 -------
 [source,c]
@@ -106,7 +116,7 @@ struct tracefs_instance *inst = tracefs_instance_alloc(NULL, "bar");
 	}
 
 	...
-
+	tracefs_instance_reset(inst);
 	tracefs_instance_free(inst);
 --
 FILES
diff --git a/Documentation/libtracefs-instances-stat.txt b/Documentation/libtracefs-instances-stat.txt
new file mode 100644
index 0000000..d3bb3c9
--- /dev/null
+++ b/Documentation/libtracefs-instances-stat.txt
@@ -0,0 +1,183 @@
+libtracefs(3)
+=============
+
+NAME
+----
+tracefs_instance_get_stat, tracefs_instance_put_stat, tracefs_buffer_stat_entries, tracefs_buffer_stat_overrun,
+tracefs_buffer_stat_commit_overrun, tracefs_buffer_stat_bytes, tracefs_buffer_stat_event_timestamp,
+tracefs_buffer_stat_timestamp, tracefs_buffer_stat_dropped_events, tracefs_buffer_stat_read_events
+- Handling tracing buffer stats
+
+SYNOPSIS
+--------
+[verse]
+--
+*#include <tracefs.h>*
+
+struct tracefs_buffer_stat pass:[*]*tracefs_instance_get_stat*(struct tracefs_instance pass:[*]_instance_, int _cpu_);
+void *tracefs_instance_put_stat*(struct tracefs_buffer_stat pass:[*]_tstat_);
+ssize_t *tracefs_buffer_stat_entries*(struct tracefs_buffer_stat pass:[*]_tstat_);
+ssize_t *tracefs_buffer_stat_overrun*(struct tracefs_buffer_stat pass:[*]_tstat_);
+ssize_t *tracefs_buffer_stat_commit_overrun*(struct tracefs_buffer_stat pass:[*]_tstat_);
+ssize_t *tracefs_buffer_stat_bytes*(struct tracefs_buffer_stat pass:[*]_tstat_);
+long long *tracefs_buffer_stat_event_timestamp*(struct tracefs_buffer_stat pass:[*]_tstat_);
+long long *tracefs_buffer_stat_timestamp*(struct tracefs_buffer_stat pass:[*]_tstat_);
+ssize_t *tracefs_buffer_stat_dropped_events*(struct tracefs_buffer_stat pass:[*]_tstat_);
+ssize_t *tracefs_buffer_stat_read_events*(struct tracefs_buffer_stat pass:[*]_tstat_);
+--
+
+DESCRIPTION
+-----------
+This set of functions read and parse the tracefs/per_cpu/cpuX/stats file.
+These files hold the statistics of the per CPU ring buffer, such as how
+many events are in the ring buffer, how many have been read and so on.
+
+The *tracefs_instance_get_stat()* function will read and parse a given statistics
+file for a given _instance_ and _cpu_. As the ring buffer is split into per_cpu buffers,
+the information is only associated to the given _cpu_. The returned tracefs_buffer_stat
+pointer can be used with the other *tracefs_buffer_stat* functions and must be freed with
+*tracefs_instance_put_stat()*.
+
+The *tracefs_instance_put_stat()* will free the resources allocated for the given _stat_
+that was created by *tracefs_instance_get_stat()*.
+
+The *tracefs_buffer_stat_entries()* returns the number of events that are currently
+in the ring buffer associated with _tstat_.
+
+The *tracefs_buffer_stat_overrun()* returns the number of events that were lost by
+the ring buffer writer overrunning the reader.
+
+The *tracefs_buffer_stat_commit_overrun()* returns the number of events that were
+lost because the ring buffer was too small and an interrupt interrupted a lower
+context event being recorded and it added more events than the ring buffer could
+hold. Note this is not a common occurrence and when it happens it means that
+something was not set up properly.
+
+The *tracefs_buffer_stat_bytes()* returns the number of bytes that the current events
+take up. Note, it includes the meta data for the events, but does not include the
+meta data for the sub-buffers.
+
+The *tracefs_buffer_stat_event_timestamp()* returns the timestamp of the last event in the
+ring buffer.
+
+The *tracefs_buffer_stat_timestamp()* returns the current timestamp of the ring buffer.
+Note, it is only read when *tracefs_instance_get_stat()* is called. It will have the
+timestamp of the ring buffer when that function was called.
+
+The *tracefs_buffer_stat_dropped_events()* returns the number of events that were
+dropped if overwrite mode is disabled. It will show the events that were lost because
+the writer caught up to the reader and could not write any more events.
+
+The *tracefs_buffer_stat_read_events()* returns the number of events that were consumed
+by a reader.
+
+
+RETURN VALUE
+------------
+The *tracefs_instance_get_stat()* returns a tracefs_buffer_stat structure that can
+be used to retrieve the statistics via the other functions. It must be freed with
+*tracefs_instance_put_stat()*.
+
+The other functions that return different values from the tracefs_buffer_stat structure
+all return the value, or -1 if the value was not found.
+
+
+EXAMPLE
+-------
+[source,c]
+--
+#include <stdlib.h>
+#include <unistd.h>
+#include <tracefs.h>
+
+int main(int argc, char **argv)
+{
+	char *trace;
+	char buf[1000];
+	int ret;
+	int i;
+
+	for (i = 0; i < sizeof(buf) - 1; i++) {
+		buf[i] = '0' + i % 10;
+	}
+	buf[i] = '\0';
+
+	tracefs_instance_clear(NULL);
+
+	for (i = 0; i < 4; i++) {
+		ret = tracefs_printf(NULL, "%s\n", buf);
+		if (ret < 0)
+			perror("write");
+	}
+
+	trace = tracefs_instance_file_read(NULL, "trace", NULL);
+	printf("%s\n", trace);
+	free(trace);
+
+	for (i = 0; i < sysconf(_SC_NPROCESSORS_CONF); i++) {
+		struct tracefs_buffer_stat *tstat;
+		ssize_t entries, eread;
+
+		tstat = tracefs_instance_get_stat(NULL, i);
+		if (!tstat)
+			continue;
+
+		entries = tracefs_buffer_stat_entries(tstat);
+		eread = tracefs_buffer_stat_read_events(tstat);
+		if (!entries && !eread) {
+			tracefs_instance_put_stat(tstat);
+			continue;
+		}
+
+		printf("CPU: %d\n", i);;
+		printf("\tentries: %zd\n", entries);
+		printf("\toverrun: %zd\n", tracefs_buffer_stat_overrun(tstat));
+		printf("\tcommit_overrun: %zd\n", tracefs_buffer_stat_commit_overrun(tstat));
+		printf("\tbytes: %zd\n", tracefs_buffer_stat_bytes(tstat));
+		printf("\tevent_timestamp: %lld\n", tracefs_buffer_stat_event_timestamp(tstat));
+		printf("\ttimestamp: %lld\n", tracefs_buffer_stat_timestamp(tstat));
+		printf("\tdropped_events: %zd\n", tracefs_buffer_stat_dropped_events(tstat));
+		printf("\tread_events: %zd\n", eread);
+
+		tracefs_instance_put_stat(tstat);
+	}
+}
+--
+FILES
+-----
+[verse]
+--
+*tracefs.h*
+	Header file to include in order to have access to the library APIs.
+*-ltracefs*
+	Linker switch to add when building a program that uses the library.
+--
+
+SEE ALSO
+--------
+*libtracefs*(3),
+*libtraceevent*(3),
+*trace-cmd*(1)
+
+AUTHOR
+------
+[verse]
+--
+*Steven Rostedt* <rostedt@goodmis.org>
+--
+REPORTING BUGS
+--------------
+Report bugs to  <linux-trace-devel@vger.kernel.org>
+
+LICENSE
+-------
+libtracefs is Free Software licensed under the GNU LGPL 2.1
+
+RESOURCES
+---------
+https://git.kernel.org/pub/scm/libs/libtrace/libtracefs.git/
+
+COPYING
+-------
+Copyright \(C) 2020 VMware, Inc. Free use of this software is granted under
+the terms of the GNU Public License (GPL).
diff --git a/Documentation/libtracefs-instances-subbuf.txt b/Documentation/libtracefs-instances-subbuf.txt
new file mode 100644
index 0000000..8d5c3e0
--- /dev/null
+++ b/Documentation/libtracefs-instances-subbuf.txt
@@ -0,0 +1,152 @@
+libtracefs(3)
+=============
+
+NAME
+----
+tracefs_instance_get_subbuf_size, tracefs_instance_set_subbuf_size - Helper functions for working with ring buffer sub buffers.
+
+SYNOPSIS
+--------
+[verse]
+--
+*#include <tracefs.h>*
+
+size_t *tracefs_instance_get_subbuf_size*(struct tracefs_instance pass:[*]_instance_);
+int *tracefs_instance_set_subbuf_size*(struct tracefs_instance pass:[*]_instance_, size_t _size_);
+--
+
+DESCRIPTION
+-----------
+Helper functions for working with the sub-buffers of the tracing ring buffer.
+The tracing ring buffer is broken up into *sub-buffers*. An event can not be
+bigger than the data section of the sub-buffer (see *tep_get_sub_buffer_data_size*(3)).
+By default, the ring buffer uses the architectures *page_size* as the default
+size of the sub-buffer, but this can be limiting if there is a need for large
+events, for example, the application wants to write large strings into
+the trace_marker file.
+
+The *tracefs_instance_get_subbuf_size()* returns the current size in kilobytes
+fo the ring buffer sub-buffers.
+
+The *tracefs_instance_set_subbuf_size()* will write the size in kilobytes of
+what the new sub-buffer size should be. Note, that this is only a hint to what
+the minimum sub-buffer size should be. It also does not take into account the
+meta-data that is used by the sub-buffer, so the size written should be no less
+than 16 bytes more than the maximum event size that will be used. The kernel
+will likely make the sub-buffer size larger than specified, as it may need to
+align the size for implementation purposes.
+
+RETURN VALUE
+------------
+The *tracefs_instance_get_subbuf_size()* returns the size of the current
+sub-buffer for the given _instance_ ring buffer or -1 on error.
+
+The *tracefs_instance_set_subbuf_size()* will return 0 if it successfully set
+the _instance_ ring buffer sub-buffer size in kilobytes, or -1 on error.
+
+EXAMPLE
+-------
+[source,c]
+--
+#include <stdlib.h>
+#include <tracefs.h>
+#include <errno.h>
+
+int main(int argc, char **argv)
+{
+	struct tep_handle *tep;
+	ssize_t save_subsize;
+	ssize_t subsize;
+	char *trace;
+	char buf[3000];
+	int meta_size;
+	int ret;
+	int i;
+
+	tep = tep_alloc();
+	ret = tracefs_load_headers(NULL, tep);
+	tep_free(tep);
+
+	if (ret < 0) {
+		perror("reading headers");
+		exit(-1);
+	}
+
+	meta_size = tep_get_sub_buffer_size(tep) - tep_get_sub_buffer_data_size(tep);
+
+	save_subsize = tracefs_instance_get_subbuf_size(NULL);
+	if (save_subsize < 0) {
+		printf("Changing sub-buffer size not available\n");
+		exit(-1);
+	}
+
+	subsize = save_subsize * 1024;
+
+	/* Have at least 4 writes fit on a sub-buffer */
+	if (subsize - meta_size < sizeof(buf) *4 ) {
+		subsize = ((sizeof(buf) * 4 + meta_size) + 1023) / 1024;
+		tracefs_instance_set_subbuf_size(NULL, subsize);
+	}
+
+	for (i = 0; i < sizeof(buf) - 1; i++) {
+		buf[i] = '0' + i % 10;
+	}
+	buf[i] = '\0';
+
+	tracefs_instance_clear(NULL);
+
+	for (i = 0; i < 4; i++) {
+		ret = tracefs_printf(NULL, "%s\n", buf);
+		if (ret < 0)
+			perror("write");
+	}
+
+	trace = tracefs_instance_file_read(NULL, "trace", NULL);
+	printf("%s\n", trace);
+	free(trace);
+
+	printf("Buffer size was: %zd * 1024\n",
+	       tracefs_instance_get_subbuf_size(NULL));
+
+	tracefs_instance_set_subbuf_size(NULL, save_subsize);
+}
+--
+FILES
+-----
+[verse]
+--
+*tracefs.h*
+	Header file to include in order to have access to the library APIs.
+*-ltracefs*
+	Linker switch to add when building a program that uses the library.
+--
+
+SEE ALSO
+--------
+*libtracefs*(3),
+*libtraceevent*(3),
+*trace-cmd*(1)
+
+AUTHOR
+------
+[verse]
+--
+*Steven Rostedt* <rostedt@goodmis.org>
+*Tzvetomir Stoyanov* <tz.stoyanov@gmail.com>
+--
+REPORTING BUGS
+--------------
+Report bugs to  <linux-trace-devel@vger.kernel.org>
+
+LICENSE
+-------
+libtracefs is Free Software licensed under the GNU LGPL 2.1
+
+RESOURCES
+---------
+https://git.kernel.org/pub/scm/libs/libtrace/libtracefs.git/
+
+COPYING
+-------
+Copyright \(C) 2020 VMware, Inc. Free use of this software is granted under
+the terms of the GNU Public License (GPL).
diff --git a/Documentation/libtracefs-instances-utils.txt b/Documentation/libtracefs-instances-utils.txt
index bc8c9a7..d2c4f16 100644
--- a/Documentation/libtracefs-instances-utils.txt
+++ b/Documentation/libtracefs-instances-utils.txt
@@ -4,7 +4,8 @@ libtracefs(3)
 NAME
 ----
 tracefs_instance_get_name, tracefs_instance_get_trace_dir, tracefs_instances_walk, tracefs_instance_exists,
-tracefs_instance_get_buffer_size, tracefs_instance_set_buffer_size - Helper functions for working with tracing instances.
+tracefs_instance_get_buffer_size, tracefs_instance_set_buffer_size, tracefs_instance_get_buffer_percent,
+tracefs_instance_set_buffer_percent - Helper functions for working with tracing instances.
 
 SYNOPSIS
 --------
@@ -18,6 +19,8 @@ int *tracefs_instances_walk*(int (pass:[*]_callback_)(const char pass:[*], void
 bool *tracefs_instance_exists*(const char pass:[*]_name_);
 size_t *tracefs_instance_get_buffer_size*(struct tracefs_instance pass:[*]_instance_, int _cpu_);
 int *tracefs_instance_set_buffer_size*(struct tracefs_instance pass:[*]_instance_, size_t _size_, int _cpu_);
+int *tracefs_instance_get_buffer_percent*(struct tracefs_instance pass:[*]_instance_);
+int *tracefs_instance_set_buffer_percent*(struct tracefs_instance pass:[*]_instance_, int _val_);
 --
 
 DESCRIPTION
@@ -48,6 +51,29 @@ If _cpu_ is negative, then it sets all the per CPU ring buffers to _size_ (note
 the total size is the number of CPUs * _size_). If _cpu_ is specified, then it only
 sets the size of the per CPU ring buffer.
 
+The *tracefs_instance_set_buffer_percent()* sets the buffer percent value of
+the tracing ring buffer for _instance_ or the top level buffer if _instance_ is
+NULL. The buffer percent decides when readers on *tracefs_cpu_read*(3),
+*tracefs_cpu_buffered_read*(3), *tracefs_cpu_write*(3) and *tracefs_cpu_pipe*(3)
+will block when O_NONBLOCK is not set. The value of _val_ must be between 0 and
+100, where:
+
+[verse]
+--
+  0   - block until there's any data in the ring buffer
+  1   - block until 1% of the ring buffer sub-buffers are filled
+  50  - block until 50% of the ring buffer sub-buffers are filled
+  100 - block until the entire ring buffer is filled
+--
+
+Note, any number from 0 to 100 can be used where it is the percentage of the
+ring buffer that must be filled before a blocked reader will be notified that
+there's data to be retrieved.
+
+The *tracefs_instance_get_buffer_percent()* retrieves the current buffer percent
+setting of the tracing ring buffer for _instance_ or the top level buffer
+if _instance_ is NULL.
+
 RETURN VALUE
 ------------
 The *tracefs_instance_get_name()* returns a string or NULL in case of the top
diff --git a/Documentation/libtracefs-iterator.txt b/Documentation/libtracefs-iterator.txt
index b971bd0..b62f66a 100644
--- a/Documentation/libtracefs-iterator.txt
+++ b/Documentation/libtracefs-iterator.txt
@@ -3,7 +3,8 @@ libtracefs(3)
 
 NAME
 ----
-tracefs_iterate_raw_events, tracefs_iterate_stop, tracefs_follow_event, tracefs_follow_missed_events - Iterate over events in the ring buffer
+tracefs_iterate_raw_events, tracefs_iterate_stop, tracefs_follow_event, tracefs_follow_missed_events,
+tracefs_follow_event_clear, tracefs_follow_missed_events_clear, tracefs_iterate_snapshot_events - Iterate over events in the ring buffer
 
 SYNOPSIS
 --------
@@ -28,6 +29,15 @@ int *tracefs_follow_missed_events*(struct tracefs_instance pass:[*]_instance_,
 					  struct tep_record pass:[*],
 					  int, void pass:[*]),
 			  void pass:[*]_callback_data_);
+
+int *tracefs_follow_event_clear*(struct tracefs_instance pass:[*]_instance_,
+			  const char pass:[*]_system_, const char pass:[*]_event_name_);
+int *tracefs_follow_missed_events_clear*(struct tracefs_instance pass:[*]_instance_);
+
+int *tracefs_iterate_snapshot_events*(struct tep_handle pass:[*]_tep_, struct tracefs_instance pass:[*]_instance_,
+				 cpu_set_t pass:[*]_cpus_, int _cpu_size_,
+				 int (pass:[*]_callback_)(struct tep_event pass:[*], struct tep_record pass:[*], int, void pass:[*]),
+				 void pass:[*]_callback_context_);
 --
 
 DESCRIPTION
@@ -49,6 +59,9 @@ record is; The record representing the event; The CPU that the event
 occurred on; and a pointer to user specified _callback_context_. If the _callback_
 returns non-zero, the iteration stops.
 
+The *tracefs_iterate_snapshot_events()* works the same as *tracefs_iterate_raw_events()*
+except that it works on the snapshot buffer.
+
 Use *tracefs_iterate_stop()* to force a executing *tracefs_iterate_raw_events()*
 to halt. This can be called from either a callback that is called by
 the iterator (even though a return of non-zero will stop it), or from another
@@ -68,11 +81,24 @@ record that came after the missed events and _event_ will be of the type of
 event _record_ is. _cpu_ will be set to the CPU that missed the events, and
 _callback_data_ will be the content that was passed in to the function.
 
+The *tracefs_follow_event_clear()* will remove followers from _instance_ that
+match _system_ and _event_name_. If _system_ and _event_name_ are both NULL,
+then it will remove all event followers associated to _instance_. If just _system_
+is NULL, then it will remove all followers that follow events that match _event_name_. If just _event_name_
+is NULL, then it will remove all followers that are attached to events that are
+apart of a system that matches _system_.
+
+The *tracefs_follow_missed_events_clear()* will remove all followers for missed
+events.
+
 RETURN VALUE
 ------------
 The *tracefs_iterate_raw_events()* function returns -1 in case of an error or
 0 otherwise.
 
+Both *tracefs_follow_event_clear()* and *tracefs_follow_missed_events_clear()* return
+0 on success and -1 on error, or if it found no followers that match and should be removed.
+
 EXAMPLE
 -------
 [source,c]
@@ -176,7 +202,17 @@ int main (int argc, char **argv, char **env)
 	tracefs_follow_missed_events(instance, missed_callback, NULL);
 	tracefs_follow_event(tep, instance, "sched", "sched_switch", sched_callback, &this_pid);
 	tracefs_iterate_raw_events(tep, instance, NULL, 0, callback, &my_data);
+
+	/* Note, the clear here is to show how to clear all followers
+	 * in case tracefs_iterate_raw_events() is called again, but
+	 * does not want to include the followers. It's not needed
+	 * here because tracefs_instance_free() will clean them up.
+	 */
+	tracefs_follow_event_clear(instance, NULL, NULL);
+	tracefs_follow_missed_events_clear(instance);
+
 	tracefs_instance_destroy(instance);
+	tracefs_instance_free(instance);
 
 	if (my_data.stopped) {
 		if (counter > MAX_COUNT)
diff --git a/Documentation/libtracefs-kprobes.txt b/Documentation/libtracefs-kprobes.txt
index 593ef9e..199379a 100644
--- a/Documentation/libtracefs-kprobes.txt
+++ b/Documentation/libtracefs-kprobes.txt
@@ -3,8 +3,9 @@ libtracefs(3)
 
 NAME
 ----
-tracefs_kprobe_alloc, tracefs_kretprobe_alloc, tracefs_kprobe_raw, tracefs_kretprobe_raw -
-Allocate, get, and create kprobes
+tracefs_kprobe_alloc, tracefs_kretprobe_alloc, tracefs_kprobe_raw, tracefs_kretprobe_raw,
+tracefs_kprobe_destroy -
+Allocate, get, create, and remove kprobes
 
 SYNOPSIS
 --------
@@ -22,11 +23,15 @@ int *tracefs_kprobe_raw*(const char pass:[*]_system_, const char pass:[*]_event_
 			 const char pass:[*]_addr_, const char pass:[*]_format_);
 int *tracefs_kretprobe_raw*(const char pass:[*]_system_, const char pass:[*]_event_,
 			    const char pass:[*]_addr_, const char pass:[*]_format_);
+int *tracefs_kprobe_destroy*(const char pass:[*]_system_, const char pass:[*]_event_,
+			   const char pass:[*]_addr_, const char pass:[*]_format_, bool _force_);
 --
 
 DESCRIPTION
 -----------
 *tracefs_kprobe_alloc*() allocates a new kprobe context. The kbrobe is not configured in the system.
+The kprobe can be added to the system by passing in the returned descriptor into
+*tracefs_dynevent_create(3)*.
 The new kprobe will be in the _system_ group (or kprobes if _system_ is NULL) and have the name of
 _event_ (or _addr_ if _event_ is NULL). The kprobe will be inserted to _addr_ (function name, with
 or without offset, or a address), and the _format_ will define the format of the kprobe. See the
@@ -49,6 +54,9 @@ document.
 creates a kretprobe instead of a kprobe. The difference is also described
 in the Linux kernel source in the Documentation/trace/kprobetrace.rst file.
 
+*tracefs_kprobe_destroy*() will destroy a specific kprobe or kretprobe created by
+*tracefs_kprobe_raw*() or *tracefs_kretprobe_raw*() with the same parameters.
+
 RETURN VALUE
 ------------
 
@@ -61,6 +69,10 @@ tracefs_dynevent structure, describing the probe. This pointer must be freed by
 *tracefs_dynevent_free*(3). Note, this only allocates a descriptor representing the kprobe. It does
 not modify the running system.
 
+The *tracefs_kprobe_destroy*() returns 0 on success or -1 on error if it was not able to
+successful destory (or find) the kprobe or kretprobe.
+
+
 ERRORS
 ------
 The following errors are for all the above calls:
diff --git a/Documentation/libtracefs-snapshot.txt b/Documentation/libtracefs-snapshot.txt
new file mode 100644
index 0000000..896705c
--- /dev/null
+++ b/Documentation/libtracefs-snapshot.txt
@@ -0,0 +1,182 @@
+libtracefs(3)
+=============
+
+NAME
+----
+tracefs_snapshot_snap, tracefs_snapshot_clear, tracefs_snapshot_free -
+API to create, clear and read snapshots
+
+SYNOPSIS
+--------
+[verse]
+--
+*#include <tracefs.h>*
+
+int *tracefs_snapshot_snap*(struct tracefs_instance pass:[*]instance);
+int *tracefs_snapshot_clear*(struct tracefs_instance pass:[*]instance);
+int *tracefs_snapshot_free*(struct tracefs_instance pass:[*]instance);
+--
+
+DESCRIPTION
+-----------
+The Linux kernel tracing provides a "snapshot" feature. The kernel has two
+ring buffers. One that is written to by the tracing system and another one that
+is the "snapshot" buffer. When a snapshot happens, the two buffers are swapped, and
+the current snapshot buffer becomes the one being written to, and the buffer
+that was being written to becomes the saved snapshot.
+
+Note, the snapshot buffer is allocated the first time it is taken, so it is best
+to take a snapshot at the start before one is needed so that it is allocated
+and a snapshot is ready, then the snapshot will happen immediately.
+
+The *tracefs_snapshot_snap()* will allocate (if not already allocated) the snapshot
+buffer and then take a "snapshot" (swap the main buffer that's being written to with
+the allocated snapshot buffer). It will do this to the given _instance_ buffer or
+the top instance if _instance_ is NULL.
+
+The *tracefs_snapshot_clear()* will erase the content of the snapshot buffer for
+the given _instance_ or the top level instance if _instance_ is NULL.
+
+The *tracefs_snapshot_free()* will free the allocated snapshot for the given _instance_
+or the top level instance if _instance_ is NULL. That is, if another call to
+*tracefs_snapshot_snap()* is done after this, then it will need to allocate
+the snapshot buffer again before it can take a snapshot. This function should
+be used to free up the kernel memory used by hte snapshot buffer when no longer in use.
+
+
+RETURN VALUE
+------------
+The *tracefs_snapshot_snap()*, *tracefs_snapshot_clear()* and the *tracefs_snapshot_free()*
+all return 0 on success and -1 on failure.
+
+EXAMPLE
+-------
+[source,c]
+--
+#include <stdlib.h>
+#include <stdio.h>
+#include <tracefs.h>
+
+static int callback(struct tep_event *event, struct tep_record *record, int cpu, void *data)
+{
+	static struct trace_seq seq;
+	struct tep_handle *tep = event->tep;
+
+	if (!seq.buffer)
+		trace_seq_init(&seq);
+
+	trace_seq_reset(&seq);
+
+	tep_print_event(tep, &seq, record, "[%03d] %s-%d %6.1000d\t%s: %s\n",
+				TEP_PRINT_CPU,
+				TEP_PRINT_COMM,
+				TEP_PRINT_PID,
+				TEP_PRINT_TIME,
+				TEP_PRINT_NAME,
+				TEP_PRINT_INFO);
+	trace_seq_do_printf(&seq);
+	return 0;
+}
+
+int main (int argc, char **argv)
+{
+	struct tracefs_instance *instance;
+	struct tep_handle *tep;
+	char *line = NULL;
+	size_t len = 0;
+	int ret;
+
+	instance = tracefs_instance_create("my_snapshots");
+	if (!instance) {
+		perror("creating instance");
+		exit(-1);
+	}
+
+	tep = tracefs_local_events(NULL);
+	if (!tep) {
+		perror("reading event formats");
+		goto out;
+	}
+
+	/* Make sure the snapshot buffer is allocated */
+	ret = tracefs_snapshot_snap(instance);
+	if (ret < 0)
+		goto out;
+
+	ret = tracefs_event_enable(instance, "sched", NULL);
+	if (ret < 0) {
+		perror("enabling event");
+		goto out;
+	}
+
+	for (;;) {
+		printf("Hit enter without text to take snapshot!\n");
+		printf("Enter any text to display the snapshot\n");
+		printf("Enter 'quit' to exit\n");
+		getline(&line, &len, stdin);
+		ret = tracefs_snapshot_snap(instance);
+		if (ret < 0) {
+			perror("taking snapshot");
+			goto out;
+		}
+		if (!line)
+			break;
+		if (strlen(line) < 2)
+			continue;
+		if (strncmp(line, "quit", 4) == 0)
+			break;
+		tracefs_iterate_snapshot_events(tep, instance, NULL, 0, callback, NULL);
+	}
+
+	free(line);
+
+	tracefs_instance_clear(instance);
+
+ out:
+	tracefs_snapshot_free(instance);
+	tracefs_event_disable(instance, "sched", NULL);
+	tracefs_instance_destroy(instance);
+	tracefs_instance_free(instance);
+
+	exit(0);
+}
+--
+FILES
+-----
+[verse]
+--
+*tracefs.h*
+	Header file to include in order to have access to the library APIs.
+*-ltracefs*
+	Linker switch to add when building a program that uses the library.
+--
+
+SEE ALSO
+--------
+*tracefs_iterate_snapshot_events*(3)
+*libtracefs*(3),
+*libtraceevent*(3),
+*trace-cmd*(1)
+
+AUTHOR
+------
+[verse]
+--
+*Steven Rostedt* <rostedt@goodmis.org>
+--
+REPORTING BUGS
+--------------
+Report bugs to  <linux-trace-devel@vger.kernel.org>
+
+LICENSE
+-------
+libtracefs is Free Software licensed under the GNU LGPL 2.1
+
+RESOURCES
+---------
+https://git.kernel.org/pub/scm/libs/libtrace/libtracefs.git/
+
+COPYING
+-------
+Copyright \(C) 2023 Google, LLC. Free use of this software is granted under
+the terms of the GNU Public License (GPL).
diff --git a/Documentation/libtracefs-sql.txt b/Documentation/libtracefs-sql.txt
index 6d606db..806fbe4 100644
--- a/Documentation/libtracefs-sql.txt
+++ b/Documentation/libtracefs-sql.txt
@@ -127,6 +127,22 @@ The *TIMESTAMP_USECS* will truncate the time down to microseconds as the timesta
 recorded in the tracing buffer has nanosecond resolution. If you do not want that
 truncation, use *TIMESTAMP* instead of *TIMESTAMP_USECS*.
 
+Because it is so common to have:
+
+[source,c]
+--
+   (end.TIMESTAMP_USECS - start.TIMESTAMP_USECS)
+--
+
+The above can be represented with *TIMESTAMP_DELTA_USECS* or if nanoseconds are OK, you can
+use *TIMESTAMP_DELTA*. That is, the previous select can also be represented by:
+
+[source,c]
+--
+select start.pid, TIMESTAMP_DELTA_USECS as lat from sched_waking as start JOIN sched_switch as end ON start.pid = end.next_pid
+--
+
+
 Finally, the *WHERE* clause can be added, that will let you add filters on either or both events.
 
 [source,c]
@@ -162,6 +178,19 @@ select start.pid, (end.TIMESTAMP_USECS - start.TIMESTAMP_USECS) as lat from sche
    WHERE start.prio < 100 || end.prev_prio < 100
 --
 
+If the kernel supports it, you can pass around a stacktrace between events.
+
+[source, c]
+--
+select start.prev_pid as pid, (end.TIMESTAMP_USECS - start.TIMESTAMP_USECS) as delta, start.STACKTRACE as stack
+   FROM sched_switch as start JOIN sched_switch as end ON start.prev_pid = end.next_pid
+   WHERE start.prev_state == 2
+--
+
+The above will record a stacktrace when a task is in the UNINTERRUPTIBLE (blocked) state, and trigger
+the synthetic event when it is scheduled back in, recording the time delta that it was blocked for.
+It will record the stacktrace of where it was when it scheduled out along with the delta.
+
 
 KEYWORDS AS EVENT FIELDS
 ------------------------
diff --git a/Documentation/libtracefs-stream.txt b/Documentation/libtracefs-stream.txt
index 8008be8..7f1ff6a 100644
--- a/Documentation/libtracefs-stream.txt
+++ b/Documentation/libtracefs-stream.txt
@@ -31,8 +31,9 @@ The *tracefs_trace_pipe_stream()* function redirects the stream of trace data to
 file. The "splice" system call is used to moves the data without copying between kernel
 address space and user address space. The _fd_ is the file descriptor of the output file
 and _flags_ is a bit mask of flags to be passed to the open system call of the trace_pipe
-file (see ). If flags contain O_NONBLOCK, then that is also passed to the splice calls
-that may read the file to the output stream file descriptor.
+file (see *open(2)*). If flags contain O_NONBLOCK, then that is also passed to the splice calls
+that may read the file to the output stream file descriptor. Note, O_RDONLY is or'd to
+the _flags_ and only O_NONBLOCK is useful for this parameter.
 
 The *tracefs_trace_pipe_print()* function is similar to *tracefs_trace_pipe_stream()*, but
 the stream of trace data is redirected to stdout.
diff --git a/Documentation/libtracefs-synth2.txt b/Documentation/libtracefs-synth2.txt
index 7e8e6cc..77cdd01 100644
--- a/Documentation/libtracefs-synth2.txt
+++ b/Documentation/libtracefs-synth2.txt
@@ -4,7 +4,7 @@ libtracefs(3)
 NAME
 ----
 tracefs_synth_create, tracefs_synth_destroy, tracefs_synth_complete,
-tracefs_synth_trace, tracefs_synth_snapshot, tracefs_synth_save
+tracefs_synth_trace, tracefs_synth_snapshot, tracefs_synth_save,tracefs_synth_set_instance,
 - Creation of synthetic events
 
 SYNOPSIS
@@ -17,6 +17,7 @@ int *tracefs_synth_create*(struct tracefs_synth pass:[*]_synth_);
 int *tracefs_synth_destroy*(struct tracefs_synth pass:[*]_synth_);
 bool *tracefs_synth_complete*(struct tracefs_synth pass:[*]_synth_);
 
+int *tracefs_synth_set_instance*(struct tracefs_synth pass:[*]_synth_, struct tracefs_instance pass:[*]_instance_);
 int *tracefs_synth_trace*(struct tracefs_synth pass:[*]_synth_,
 			enum tracefs_synth_handler _type_, const char pass:[*]_var_);
 int *tracefs_synth_snapshot*(struct tracefs_synth pass:[*]_synth_,
@@ -45,9 +46,14 @@ as a field for both events to calculate the delta in nanoseconds, or use
 *TRACEFS_TIMESTAMP_USECS* as the compare fields for both events to calculate the
 delta in microseconds. This is used as the example below.
 
-*tracefs_synth_create*() creates the synthetic event in the system. The synthetic events apply
-across all instances. A synthetic event must be created with *tracefs_synth_alloc*(3) before
-it can be created.
+*tracefs_synth_create*() creates the synthetic event in the system. By default,
+the histogram triggers are created in the top trace instance, as any synthetic
+event can be used globally across all instances. In case an application wants
+to keep the histogram triggers out of the top level instance, it can use
+*tracefs_synth_set_instance()* to have the histograms used for creating the
+synthetic event in an instance other than the top level.  A synthetic event
+descriptor must be created with *tracefs_synth_alloc*(3) before this can be
+used to create it on the system.
 
 *tracefs_synth_destroy*() destroys the synthetic event. It will attempt to stop the running of it in
 its instance (top by default), but if its running in another instance this may fail as busy.
@@ -74,6 +80,15 @@ then save the given _save_fields_ list. The fields will be stored in the histogr
 "hist" file of the event that can be retrieved with *tracefs_event_file_read*(3).
 _var_ must be one of the _name_ elements used in *tracefs_synth_add_end_field*(3).
 
+*tracefs_synth_set_instance()* Set the trace instance, where the histogram
+triggers that create the synthetic event will be created. By default, the top
+instance is used. This API must be called before the call to
+*tracefs_synth_create()*, in order to use the new instance when creating the
+event.  Note, that even if the synthetic event is created in an instance, it is
+still visible by all other instances including the top level. That is, other
+instances can enable the created synthetic event and have it traced in the
+buffers that belong to the instance that enabled it.
+
 RETURN VALUE
 ------------
 All functions return zero on success or -1 on error.
diff --git a/Documentation/libtracefs-tracer.txt b/Documentation/libtracefs-tracer.txt
index ea57962..8f90552 100644
--- a/Documentation/libtracefs-tracer.txt
+++ b/Documentation/libtracefs-tracer.txt
@@ -3,7 +3,7 @@ libtracefs(3)
 
 NAME
 ----
-tracefs_tracer_set, tracefs_tracer_clear - Enable or disable a tracer in an instance or the top level
+tracefs_instance_tracers, tracefs_tracer_set, tracefs_tracer_clear - Enable or disable a tracer in an instance or the top level
 
 SYNOPSIS
 --------
@@ -11,6 +11,7 @@ SYNOPSIS
 --
 *#include <tracefs.h>*
 
+char pass:[**] *tracefs_instance_tracers*(struct tracefs_instance pass:[*]_instance_);
 int *tracefs_tracer_set*(struct tracefs_instance pass:[*]_instance_, enum tracefs_tracers _tracer_);
 int *tracefs_tracer_set*(struct tracefs_instance pass:[*]_instance_, enum tracefs_tracers _tracer_, const char pass:[*]_name_);
 int *tracefs_tracer_clear*(struct tracefs_instance pass:[*]_instance_);
@@ -18,6 +19,11 @@ int *tracefs_tracer_clear*(struct tracefs_instance pass:[*]_instance_);
 
 DESCRIPTION
 -----------
+*tracefs_instance_tracers* will return a list of available tracers for a given
+_instance_ (note, an instance may not have the same set of available tracers as
+the top level). If _instance_ is NULL, then the list of available tracers
+returned will be for the top level.
+
 *tracefs_tracer_set* enables a tracer in the given instance, defined by the
 _instance_ parameter. If _instance_ is NULL, then the top level instance is
 changed. If _tracer_ is set to *TRACFES_TRACER_CUSTOM* then a _name_
@@ -119,10 +125,12 @@ int main(int argc, char *argv[])
 {
 	struct tracefs_instance *inst = NULL;
 	enum tracefs_tracers t = TRACEFS_TRACER_NOP;
+	const char *cust = NULL;
 	const char *buf = NULL;
-	const char *cust;
+	char **tracers;
 	int ret;
 	int ch;
+	int i;
 
 	while ((ch = getopt(argc, argv, "nfgiwdc:B:")) > 0) {
 		switch (ch) {
@@ -161,19 +169,27 @@ int main(int argc, char *argv[])
 		ret = tracefs_tracer_set(inst, t);
 
 	if (ret < 0) {
+		if (errno == ENODEV) {
+			if (cust)
+				printf("Tracer '%s' not supported by kernel\n", cust);
+			else
+				printf("Tracer not supported by kernel\n");
+			tracers = tracefs_instance_tracers(inst);
+			printf("Available tracers:");
+			for (i = 0; tracers && tracers[i]; i++)
+				printf(" %s", tracers[i]);
+			tracefs_list_free(tracers);
+			printf("\n");
+		} else
+			perror("Error");
 		if (inst) {
 			tracefs_instance_destroy(inst);
 			tracefs_instance_free(inst);
 		}
-		if (errno == ENODEV)
-			printf("Tracer not supported by kernel\n");
-		else
-			perror("Error");
 		exit(-1);
 	}
 
-	if (inst)
-		tracefs_instance_free(inst);
+	tracefs_instance_free(inst);
 
 	exit(0);
 }
diff --git a/Documentation/libtracefs.txt b/Documentation/libtracefs.txt
index c3f448d..860e2be 100644
--- a/Documentation/libtracefs.txt
+++ b/Documentation/libtracefs.txt
@@ -25,6 +25,8 @@ Trace instances:
 	struct tracefs_instance pass:[*]*tracefs_instance_alloc*(const char pass:[*]_tracing_dir_, const char pass:[*]_name_);
 	void *tracefs_instance_free*(struct tracefs_instance pass:[*]_instance_);
 	char pass:[**]*tracefs_instances*(const char pass:[*]_regex_);
+	void *tracefs_instance_clear*(struct tracefs_instance pass:[*]_instance_);
+	void *tracefs_instance_reset*(struct tracefs_instance pass:[*]_instance_);
 	bool *tracefs_instance_is_new*(struct tracefs_instance pass:[*]_instance_);
 	bool *tracefs_file_exists*(struct tracefs_instance pass:[*]_instance_, char pass:[*]_name_);
 	bool *tracefs_dir_exists*(struct tracefs_instance pass:[*]_instance_, char pass:[*]_name_);
@@ -32,6 +34,7 @@ Trace instances:
 	char pass:[*]*tracefs_instance_get_dir*(struct tracefs_instance pass:[*]_instance_);
 	int *tracefs_instance_file_open*(struct tracefs_instance pass:[*]_instance_, const char pass:[*]_file_, int _mode_);
 	int *tracefs_instance_file_write*(struct tracefs_instance pass:[*]_instance_, const char pass:[*]_file_, const char pass:[*]_str_);
+	int *tracefs_instance_file_write_number*(struct tracefs_instance pass:[*]_instance_, const char pass:[*]_file_, size_t _val_);
 	int *tracefs_instance_file_append*(struct tracefs_instance pass:[*]_instance_, const char pass:[*]_file_, const char pass:[*]_str_);
 	int *tracefs_instance_file_clear*(struct tracefs_instance pass:[*]_instance_, const char pass:[*]_file_);
 	char pass:[*]*tracefs_instance_file_read*(struct tracefs_instance pass:[*]_instance_, const char pass:[*]_file_, int pass:[*]_psize_);
@@ -48,6 +51,8 @@ Trace instances:
 	char pass:[*]*tracefs_instance_get_affinity_raw*(struct tracefs_instance pass:[*]_instance_);
 	size_t *tracefs_instance_get_buffer_size*(struct tracefs_instance pass:[*]_instance_, int _cpu_);
 	int *tracefs_instance_set_buffer_size*(struct tracefs_instance pass:[*]_instance_, size_t _size_, int _cpu_);
+	int *tracefs_instance_get_buffer_percent*(struct tracefs_instance pass:[*]_instance_);
+	int *tracefs_instance_set_buffer_percent*(struct tracefs_instance pass:[*]_instance_, int _val_);
 
 Trace events:
 	char pass:[*]pass:[*]*tracefs_event_systems*(const char pass:[*]_tracing_dir_);
@@ -71,10 +76,14 @@ Trace events:
 						  struct tep_record pass:[*],
 						  int, void pass:[*]),
 				  void pass:[*]_callback_data_);
+	int *tracefs_follow_event_clear*(struct tracefs_instance pass:[*]_instance_,
+			  const char pass:[*]_system_, const char pass:[*]_event_name_);
+	int *tracefs_follow_missed_events_clear*(struct tracefs_instance pass:[*]_instance_);
 	struct tep_handle pass:[*]*tracefs_local_events*(const char pass:[*]_tracing_dir_);
 	struct tep_handle pass:[*]*tracefs_local_events_system*(const char pass:[*]_tracing_dir_, const char pass:[*] const pass:[*]_sys_names_);
 	int *tracefs_fill_local_events*(const char pass:[*]_tracing_dir_, struct tep_handle pass:[*]_tep_, int pass:[*]_parsing_failures_);
 	int *tracefs_load_cmdlines*(const char pass:[*]_tracing_dir_, struct tep_handle pass:[*]_tep_);
+	int *tracefs_load_headers*(const char pass:[*]_tracing_dir_, struct tep_handle pass:[*]_tep_);
 	char pass:[*]*tracefs_event_get_file*(struct tracefs_instance pass:[*]_instance_, const char pass:[*]_system_, const char pass:[*]_event_,
 			     const char pass:[*]_file_);
 	char pass:[*]*tracefs_event_file_read*(struct tracefs_instance pass:[*]_instance_, const char pass:[*]_system_, const char pass:[*]_event_,
@@ -86,6 +95,18 @@ Trace events:
 	int *tracefs_event_file_clear*(struct tracefs_instance pass:[*]_instance_, const char pass:[*]_system_, const char pass:[*]_event_,
 			     const char pass:[*]_file_);
 	bool *tracefs_event_file_exists*(struct tracefs_instance pass:[*]_instance_, const char pass:[*]_system_, const char pass:[*]_event_,
+			       const char pass:[*]_file_);
+
+Snapshot buffer:
+	int *tracefs_snapshot_snap*(struct tracefs_instance pass:[*]instance);
+	int *tracefs_snapshot_clear*(struct tracefs_instance pass:[*]instance);
+	int *tracefs_snapshot_free*(struct tracefs_instance pass:[*]instance);
+	int *tracefs_iterate_snapshot_events*(struct tep_handle pass:[*]_tep_, struct tracefs_instance pass:[*]_instance_,
+				 cpu_set_t pass:[*]_cpus_, int _cpu_size_,
+				 int (pass:[*]_callback_)(struct tep_event pass:[*], struct tep_record pass:[*], int, void pass:[*]),
+				 void pass:[*]_callback_context_);
+	struct tracefs_cpu pass:[*]*tracefs_cpu_snapshot_open*(struct tracefs_instance pass:[*]_instance_,
+					     int _cpu_, bool _nonblock_);
 
 Event filters:
 	int *tracefs_filter_string_append*(struct tep_event pass:[*]_event_, char pass:[**]_filter_,
@@ -100,6 +121,14 @@ Function filters:
 	int *tracefs_function_notrace*(struct tracefs_instance pass:[*]_instance_, const char pass:[*]_filter_, const char pass:[*]_module_, int _flags_);
 	int *tracefs_filter_functions*(const char pass:[*]_filter_, const char pass:[*]_module_, char pass:[*]pass:[*]pass:[*]_list_);
 
+PID filters:
+	int *tracefs_filter_pid_function*(struct tracefs_instance pass:[*]_instance,_ int _pid_,
+				bool _reset_, bool _notrace_);
+	int *tracefs_filter_pid_function_clear*(struct tracefs_instance pass:[*]_instance_, bool _notrace_);
+	int *tracefs_filter_pid_events*(struct tracefs_instance pass:[*]_instance_, int _pid_,
+				bool _reset_, bool _notrace_);
+	int *tracefs_filter_pid_events_clear*(struct tracefs_instance pass:[*]_instance_, bool _notrace_);
+
 Trace helper functions:
 	void *tracefs_list_free*(char pass:[*]pass:[*]_list_);
 	char pass:[**]*tracefs_list_add*(char **_list_, const char *_string_);
@@ -117,6 +146,14 @@ Trace stream:
 	ssize_t *tracefs_trace_pipe_print*(struct tracefs_instance pass:[*]_instance_, int _flags_);
 	void *tracefs_trace_pipe_stop*(struct tracefs_instance pass:[*]_instance_);
 
+Memory mapping the ring buffer:
+	bool *tracefs_cpu_is_mapped*(struct tracefs_cpu pass:[*]tcpu);
+	bool *tracefs_mapped_is_supported*(void);
+	int *tracefs_cpu_map*(struct tracefs_cpu pass:[*]tcpu);
+	void *tracefs_cpu_unmap*(struct tracefs_cpu pass:[*]tcpu);
+	struct tracefs_cpu pass:[*]*tracefs_cpu_open_mapped*(struct tracefs_instance pass:[*]instance,
+						int cpu, bool nonblock);
+
 Trace options:
 	const struct tracefs_options_mask pass:[*]*tracefs_options_get_supported*(struct tracefs_instance pass:[*]_instance_);
 	bool *tracefs_option_is_supported*(struct tracefs_instance pass:[*]_instance_, enum tracefs_option_id _id_);
@@ -130,6 +167,7 @@ Trace options:
 
 Ftrace tracers:
 	char pass:[*]pass:[*]*tracefs_tracers*(const char pass:[*]_tracing_dir_);
+	char pass:[**] *tracefs_instance_tracers*(struct tracefs_instance pass:[*]_instance_);
 	bool *tracefs_tracer_available*(const char pass:[*]_tracing_dir_, const char pass:[*]_tracer_);
 	int *tracefs_tracer_set*(struct tracefs_instance pass:[*]_instance_, enum tracefs_tracers _tracer_);
 	int *tracefs_tracer_set*(struct tracefs_instance pass:[*]_instance_, enum tracefs_tracers _tracer_, const char pass:[*]_name_);
@@ -147,6 +185,18 @@ Writing data in the trace buffer:
 Control library logs:
 	int *tracefs_set_loglevel*(enum tep_loglevel _level_);
 
+Read the ring buffer statistics:
+	struct tracefs_buffer_stat pass:[*]*tracefs_instance_get_stat*(struct tracefs_instance pass:[*]_instance_, int _cpu_);
+	void *tracefs_instance_put_stat*(struct tracefs_buffer_stat pass:[*]_tstat_);
+	ssize_t *tracefs_buffer_stat_entries*(struct tracefs_buffer_stat pass:[*]_tstat_);
+	ssize_t *tracefs_buffer_stat_overrun*(struct tracefs_buffer_stat pass:[*]_tstat_);
+	ssize_t *tracefs_buffer_stat_commit_overrun*(struct tracefs_buffer_stat pass:[*]_tstat_);
+	ssize_t *tracefs_buffer_stat_bytes*(struct tracefs_buffer_stat pass:[*]_tstat_);
+	long long *tracefs_buffer_stat_event_timestamp*(struct tracefs_buffer_stat pass:[*]_tstat_);
+	long long *tracefs_buffer_stat_timestamp*(struct tracefs_buffer_stat pass:[*]_tstat_);
+	ssize_t *tracefs_buffer_stat_dropped_events*(struct tracefs_buffer_stat pass:[*]_tstat_);
+	ssize_t *tracefs_buffer_stat_read_events*(struct tracefs_buffer_stat pass:[*]_tstat_);
+
 Dynamic event generic APIs:
 	struct *tracefs_dynevent*;
 	enum *tracefs_dynevent_type*;
@@ -172,6 +222,8 @@ Uprobes, Kprobes and Kretprobes:
 		     const char pass:[*]_file_, unsigned long long _offset_, const char pass:[*]_fetchargs_)
 	*tracefs_uretprobe_alloc*(const char pass:[*]_system_, const char pass:[*]_event_,
 		     const char pass:[*]_file_, unsigned long long _offset_, const char pass:[*]_fetchargs_);
+	int *tracefs_kprobe_destroy*(const char pass:[*]_system_, const char pass:[*]_event_,
+			   const char pass:[*]_addr_, const char pass:[*]_format_, bool _force_);
 
 Synthetic events:
 	struct tracefs_synth pass:[*]*tracefs_sql*(struct tep_handle pass:[*]_tep_, const char pass:[*]_name_,
@@ -213,6 +265,7 @@ Synthetic events:
 	void *tracefs_synth_free*(struct tracefs_synth pass:[*]_synth_);
 	int *tracefs_synth_create*(struct tracefs_synth pass:[*]_synth_);
 	int *tracefs_synth_destroy*(struct tracefs_synth pass:[*]_synth_);
+	int *tracefs_synth_set_instance*(struct tracefs_synth pass:[*]_synth_, struct tracefs_instance pass:[*]_instance_);
 	int *tracefs_synth_echo_cmd*(struct trace_seq pass:[*]_seq_, struct tracefs_synth pass:[*]_synth_);
 	bool *tracefs_synth_complete*(struct tracefs_synth pass:[*]_synth_);
 	struct tracefs_hist pass:[*]*tracefs_synth_get_start_hist*(struct tracefs_synth pass:[*]_synth_);
@@ -297,7 +350,18 @@ Recording of trace_pipe_raw files:
 	int *tracefs_cpu_flush*(struct tracefs_cpu pass:[*]_tcpu_, void pass:[*]_buffer_);
 	int *tracefs_cpu_flush_write*(struct tracefs_cpu pass:[*]_tcpu_, int _wfd_);
 	int *tracefs_cpu_pipe*(struct tracefs_cpu pass:[*]_tcpu_, int _wfd_, bool _nonblock_);
+	struct kbuffer pass:[*]*tracefs_cpu_read_buf*(struct tracefs_cpu pass:[*]_tcpu_, bool _nonblock_);
+	struct kbuffer pass:[*]*tracefs_cpu_buffered_read_buf*(struct tracefs_cpu pass:[*]_tcpu_, bool _nonblock_);
+	struct kbuffer pass:[*]*tracefs_cpu_flush_buf*(struct tracefs_cpu pass:[*]_tcpu_);
+
+Helper functions for modifying the ring buffer sub-buffers:
+	size_t *tracefs_instance_get_subbuf_size*(struct tracefs_instance pass:[*]_instance_);
+	int *tracefs_instance_set_subbuf_size*(struct tracefs_instance pass:[*]_instance_, size_t _size_);
 
+Helper functions for guest tracing:
+	char pass:[*]*tracefs_find_cid_pid*(int _cid_);
+	char pass:[*]*tracefs_instance_find_cid_pid*(struct tracefs_instance pass:[*]_instance_, int _cid_);
+	int *tracefs_time_conversion*(int _cpu_, int pass:[*]_shift_, int pass:[*]_multi_, long long pass:[*]offset);
 --
 
 DESCRIPTION
diff --git a/Documentation/meson.build b/Documentation/meson.build
new file mode 100644
index 0000000..efb78b6
--- /dev/null
+++ b/Documentation/meson.build
@@ -0,0 +1,197 @@
+# SPDX-License-Identifier: LGPL-2.1
+#
+# Copyright (c) 2023 Daniel Wagner, SUSE LLC
+
+# input text file: man page section
+
+sources = {
+    'libtracefs-sqlhist.txt.1': '1',
+    'libtracefs-cpu-open.txt': '3',
+    'libtracefs-cpu.txt': '3',
+    'libtracefs-dynevents.txt': '3',
+    'libtracefs-eprobes.txt': '3',
+    'libtracefs-error.txt': '3',
+    'libtracefs-events-file.txt': '3',
+    'libtracefs-events-tep.txt': '3',
+    'libtracefs-events.txt': '3',
+    'libtracefs-files.txt': '3',
+    'libtracefs-filter.txt': '3',
+    'libtracefs-function-filter.txt': '3',
+    'libtracefs-hist-cont.txt': '3',
+    'libtracefs-hist-mod.txt': '3',
+    'libtracefs-hist.txt': '3',
+    'libtracefs-instances-affinity.txt': '3',
+    'libtracefs-instances-file-manip.txt': '3',
+    'libtracefs-instances-files.txt': '3',
+    'libtracefs-instances-manage.txt': '3',
+    'libtracefs-instances-utils.txt': '3',
+    'libtracefs-iterator.txt': '3',
+    'libtracefs-kprobes.txt': '3',
+    'libtracefs-log.txt': '3',
+    'libtracefs-marker_raw.txt': '3',
+    'libtracefs-marker.txt': '3',
+    'libtracefs-option-get.txt': '3',
+    'libtracefs-option-misc.txt': '3',
+    'libtracefs-options.txt': '3',
+    'libtracefs-sql.txt': '3',
+    'libtracefs-stream.txt': '3',
+    'libtracefs-synth2.txt': '3',
+    'libtracefs-synth-info.txt': '3',
+    'libtracefs-synth.txt': '3',
+    'libtracefs-traceon.txt': '3',
+    'libtracefs-tracer.txt': '3',
+    'libtracefs.txt': '3',
+    'libtracefs-uprobes.txt': '3',
+    'libtracefs-utils.txt': '3',
+}
+
+conf_dir = meson.current_source_dir() + '/'
+top_source_dir = meson.current_source_dir() + '/../'
+
+##
+# For asciidoc ...
+#   -7.1.2,     no extra settings are needed.
+#    8.0-,      set ASCIIDOC8.
+#
+
+#
+# For docbook-xsl ...
+#   -1.68.1,         set ASCIIDOC_NO_ROFF? (based on changelog from 1.73.0)
+#    1.69.0,         no extra settings are needed?
+#    1.69.1-1.71.0,  set DOCBOOK_SUPPRESS_SP?
+#    1.71.1,         no extra settings are needed?
+#    1.72.0,         set DOCBOOK_XSL_172.
+#    1.73.0-,        set ASCIIDOC_NO_ROFF
+#
+
+#
+# If you had been using DOCBOOK_XSL_172 in an attempt to get rid
+# of 'the ".ft C" problem' in your generated manpages, and you
+# instead ended up with weird characters around callouts, try
+# using ASCIIDOC_NO_ROFF instead (it works fine with ASCIIDOC8).
+#
+
+if get_option('asciidoctor')
+    asciidoc = find_program('asciidoctor')
+    asciidoc_extra  = ['-a', 'compat-mode']
+    asciidoc_extra += ['-I.']
+    asciidoc_extra += ['-r', 'asciidoctor-extensions']
+    asciidoc_extra += ['-a', 'mansource=libtraceevent']
+    asciidoc_extra += ['-a', 'manmanual="libtraceevent Manual"']
+    asciidoc_html = 'xhtml5'
+else
+    asciidoc = find_program('asciidoc')
+    asciidoc_extra  = ['--unsafe']
+    asciidoc_extra += ['-f', conf_dir + 'asciidoc.conf']
+    asciidoc_html = 'xhtml11'
+
+    r = run_command(asciidoc, '--version', check: true)
+    v = r.stdout().strip()
+    if v.version_compare('>=8.0')
+        asciidoc_extra += ['-a', 'asciidoc7compatible']
+    endif
+endif
+
+manpage_xsl = conf_dir + 'manpage-normal.xsl'
+
+if get_option('docbook-xls-172')
+    asciidoc_extra += ['-a', 'libtraceevent-asciidoc-no-roff']
+    manpage_xsl = conf_dir + 'manpage-1.72.xsl'
+elif get_option('asciidoc-no-roff')
+    # docbook-xsl after 1.72 needs the regular XSL, but will not
+    # pass-thru raw roff codes from asciidoc.conf, so turn them off.
+    asciidoc_extra += ['-a', 'libtraceevent-asciidoc-no-roff']
+endif
+
+xmlto = find_program('xmlto')
+xmlto_extra = []
+
+if get_option('man-bold-literal')
+    xmlto_extra += ['-m ', conf_dir + 'manpage-bold-literal.xsl']
+endif
+
+if get_option('docbook-suppress-sp')
+    xmlto_extra += ['-m ',  conf_dir + 'manpage-suppress-sp.xsl']
+endif
+
+check_doc = custom_target(
+    'check-doc',
+    output: 'dummy',
+    command : [
+        top_source_dir + 'check-manpages.sh',
+        meson.current_source_dir()])
+
+gen = generator(
+    asciidoc,
+    output: '@BASENAME@.xml',
+    arguments: [
+        '-b', 'docbook',
+        '-d', 'manpage',
+        '-a', 'libtraceevent_version=' + meson.project_version(),
+        '-o', '@OUTPUT@']
+        + asciidoc_extra
+        +  ['@INPUT@'])
+
+man = []
+html = []
+foreach txt, section : sources
+    # build man page(s)
+    xml = gen.process(txt)
+    man += custom_target(
+        txt.underscorify() + '_man',
+        input: xml,
+        output: '@BASENAME@.' + section,
+        depends: check_doc,
+        command: [
+            xmlto,
+            '-m', manpage_xsl,
+            'man',
+            '-o', '@OUTPUT@']
+            + xmlto_extra
+            + ['@INPUT@'])
+
+    # build html pages
+    html += custom_target(
+        txt.underscorify() + '_html',
+        input: txt,
+        output: '@BASENAME@.html',
+        depends: check_doc,
+        command: [
+            asciidoc,
+            '-b', asciidoc_html,
+            '-d', 'manpage',
+            '-a', 'libtraceevent_version=' + meson.project_version(),
+            '-o', '@OUTPUT@']
+            + asciidoc_extra
+            + ['@INPUT@'])
+endforeach
+
+# Install path workaround because:
+#
+# - xmlto might generate more than one file and we would to tell meson
+#   about those output files. We could figure out which files are generated
+#   (see sed match in check-manpages.sh).
+#
+# - The man page generation puts all the generated files under sub dirs
+#   and it's not obvious how to tell Meson it should not do this without
+#   causing the install step to fail (confusion where the generated files
+#   are stored)
+#
+# - The documentation build is not part of the 'build' target. The user
+#   has explicitly to trigger the doc build. Hence the documentation is
+#   not added to the 'install' target.
+#
+# Thus just use a plain old shell script to move the generated files to the
+# right location.
+
+conf = configuration_data()
+conf.set('SRCDIR', meson.current_build_dir())
+conf.set('MANDIR', mandir)
+conf.set('HTMLDIR', htmldir)
+configure_file(
+    input: 'install-docs.sh.in',
+    output: 'install-docs.sh',
+    configuration: conf)
+
+meson.add_install_script(
+    join_paths(meson.current_build_dir(), 'install-docs.sh'))
diff --git a/METADATA b/METADATA
index 33cda28..835310d 100644
--- a/METADATA
+++ b/METADATA
@@ -1,19 +1,19 @@
 # This project was upgraded with external_updater.
-# Usage: tools/external_updater/updater.sh update libtracefs
-# For more info, check https://cs.android.com/android/platform/superproject/+/master:tools/external_updater/README.md
+# Usage: tools/external_updater/updater.sh update external/libtracefs
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
 name: "libtracefs"
 description: "libtracefs is a library that provides APIs to access to the Linux kernel tracefs file system"
 third_party {
-  url {
-    type: GIT
-    value: "https://git.kernel.org/pub/scm/libs/libtrace/libtracefs.git"
-  }
-  version: "libtracefs-1.6.4"
   license_type: RESTRICTED
   last_upgrade_date {
-    year: 2023
+    year: 2025
     month: 1
-    day: 18
+    day: 30
+  }
+  identifier {
+    type: "Git"
+    value: "https://git.kernel.org/pub/scm/libs/libtrace/libtracefs.git"
+    version: "libtracefs-1.8.1"
   }
 }
diff --git a/Makefile b/Makefile
index 61ed976..bd5c76b 100644
--- a/Makefile
+++ b/Makefile
@@ -1,8 +1,8 @@
 # SPDX-License-Identifier: LGPL-2.1
 # libtracefs version
 TFS_VERSION = 1
-TFS_PATCHLEVEL = 6
-TFS_EXTRAVERSION = 4
+TFS_PATCHLEVEL = 8
+TFS_EXTRAVERSION = 1
 TRACEFS_VERSION = $(TFS_VERSION).$(TFS_PATCHLEVEL).$(TFS_EXTRAVERSION)
 
 export TFS_VERSION
@@ -10,7 +10,8 @@ export TFS_PATCHLEVEL
 export TFS_EXTRAVERSION
 export TRACEFS_VERSION
 
-LIBTRACEEVENT_MIN_VERSION = 1.3
+# Note, samples and utests need 1.8.1
+LIBTRACEEVENT_MIN_VERSION = 1.8
 
 # taken from trace-cmd
 MAKEFLAGS += --no-print-directory
@@ -73,12 +74,25 @@ else
  endif
 endif
 
+ifndef NO_VSOCK
+VSOCK_DEFINED := $(shell if (echo "$(pound)include <linux/vm_sockets.h>" | $(CC) -E - >/dev/null 2>&1) ; then echo 1; else echo 0 ; fi)
+else
+VSOCK_DEFINED := 0
+endif
+
+ifndef NO_PERF
+PERF_DEFINED := $(shell if (echo "$(pound)include <linux/perf_event.h>" | $(CC) -E - >/dev/null 2>&1) ; then echo 1; else echo 0 ; fi)
+else
+PREF_DEFINED := 0
+endif
+
 etcdir ?= /etc
 etcdir_SQ = '$(subst ','\'',$(etcdir))'
 
 export man_dir man_dir_SQ html_install html_install_SQ INSTALL
 export img_install img_install_SQ
 export DESTDIR DESTDIR_SQ
+export VSOCK_DEFINED PERF_DEFINED
 
 pound := \#
 
@@ -151,6 +165,12 @@ INCLUDES += -I$(src)/include/tracefs
 include $(src)/scripts/features.mk
 
 # Set compile option CFLAGS if not set elsewhere
+ifdef EXTRA_CFLAGS
+  CFLAGS ?= $(EXTRA_CFLAGS)
+else
+  CFLAGS ?= -g -Wall
+endif
+
 CFLAGS ?= -g -Wall
 CPPFLAGS ?=
 LDFLAGS ?=
@@ -158,15 +178,15 @@ LDFLAGS ?=
 CUNIT_INSTALLED := $(shell if (printf "$(pound)include <CUnit/Basic.h>\n void main(){CU_initialize_registry();}" | $(CC) -x c - -lcunit -o /dev/null >/dev/null 2>&1) ; then echo 1; else echo 0 ; fi)
 export CUNIT_INSTALLED
 
-export CFLAGS
-export INCLUDES
-
 # Append required CFLAGS
 override CFLAGS += -D_GNU_SOURCE $(LIBTRACEEVENT_INCLUDES) $(INCLUDES)
 
 # Make sure 32 bit stat() works on large file systems
 override CFLAGS += -D_FILE_OFFSET_BITS=64
 
+export CFLAGS
+export INCLUDES
+
 all: all_cmd
 
 LIB_TARGET  = libtracefs.a libtracefs.so.$(TRACEFS_VERSION)
@@ -243,7 +263,7 @@ $(EMACS_TAGS): force
 
 $(CSCOPE_TAGS): force
 	$(RM) $(obj)/cscope*
-	$(call find_tag_files) | cscope -b -q
+	$(call find_tag_files) | xargs cscope -b -q
 
 tags: $(VIM_TAGS)
 TAGS: $(EMACS_TAGS)
@@ -380,7 +400,7 @@ sqlhist: samples/sqlhist
 samples: libtracefs.a force
 	$(Q)$(call descend,$(src)/samples,all)
 
-clean:
+clean: clean_meson
 	$(Q)$(call descend_clean,utest)
 	$(Q)$(call descend_clean,src)
 	$(Q)$(call descend_clean,samples)
@@ -390,6 +410,19 @@ clean:
 	  $(VERSION_FILE) \
 	  $(BUILD_PREFIX))
 
+meson:
+	$(MAKE) -f Makefile.meson
+
+meson_install:
+	$(MAKE) -f Makefile.meson install
+
+meson_docs:
+	$(MAKE) -f Makefile.meson docs
+
+PHONY += clean_meson
+clean_meson:
+	$(Q)$(MAKE) -f Makefile.meson $@
+
 .PHONY: clean
 
 # libtracefs.a and libtracefs.so would concurrently enter the same directory -
diff --git a/Makefile.meson b/Makefile.meson
new file mode 100644
index 0000000..71d6bf3
--- /dev/null
+++ b/Makefile.meson
@@ -0,0 +1,40 @@
+# SPDX-License-Identifier: GPL-2.0
+
+undefine CFLAGS
+
+# Makefiles suck: This macro sets a default value of $(2) for the
+# variable named by $(1), unless the variable has been set by
+# environment or command line. This is necessary for CC and AR
+# because make sets default values, so the simpler ?= approach
+# won't work as expected.
+define allow-override
+  $(if $(or $(findstring environment,$(origin $(1))),\
+            $(findstring command line,$(origin $(1)))),,\
+    $(eval $(1) = $(2)))
+endef
+
+$(call allow-override,MESON,meson)
+$(call allow-override,MESON_BUILD_DIR,build)
+
+
+all: compile
+
+PHONY += compile
+compile: $(MESON_BUILD_DIR) force
+	$(MESON) compile -C $(MESON_BUILD_DIR)
+
+$(MESON_BUILD_DIR):
+	$(MESON) setup --prefix=$(prefix) $(MESON_BUILD_DIR)
+
+install: compile
+	$(MESON) install -C $(MESON_BUILD_DIR)
+
+docs: $(MESON_BUILD_DIR)
+	$(MESON) compile -C build docs
+
+PHONY += clean_meson
+clean_meson:
+	$(Q)$(RM) -rf $(MESON_BUILD_DIR)
+
+PHONY += force
+force:
diff --git a/OWNERS b/OWNERS
index 7e72f72..918c418 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,2 +1,3 @@
 kaleshsingh@google.com
 namhyung@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/include/meson.build b/include/meson.build
new file mode 100644
index 0000000..52db432
--- /dev/null
+++ b/include/meson.build
@@ -0,0 +1,11 @@
+# SPDX-License-Identifier: LGPL-2.1
+#
+# Copyright (c) 2023 Daniel Wagner, SUSE LLC
+
+headers = [
+   'tracefs.h',
+]
+
+foreach h : headers
+    install_headers(h, subdir : 'libtracefs')
+endforeach
diff --git a/include/tracefs-local.h b/include/tracefs-local.h
index 2007d26..ffc9d33 100644
--- a/include/tracefs-local.h
+++ b/include/tracefs-local.h
@@ -6,6 +6,7 @@
 #ifndef _TRACE_FS_LOCAL_H
 #define _TRACE_FS_LOCAL_H
 
+#include <tracefs.h>
 #include <pthread.h>
 
 #define __hidden __attribute__((visibility ("hidden")))
@@ -51,6 +52,19 @@ struct tracefs_instance {
 	bool				iterate_keep_going;
 };
 
+struct tracefs_buffer_stat {
+	ssize_t				entries;
+	ssize_t				overrun;
+	ssize_t				commit_overrun;
+	ssize_t				bytes;
+	long long			oldest_ts;
+	long long			now_ts;
+	ssize_t				dropped_events;
+	ssize_t				read_events;
+};
+
+extern const struct tep_format_field common_stacktrace;
+
 extern pthread_mutex_t toplevel_lock;
 
 static inline pthread_mutex_t *trace_get_lock(struct tracefs_instance *instance)
@@ -64,6 +78,7 @@ int trace_get_instance(struct tracefs_instance *instance);
 /* Can be overridden */
 void tracefs_warning(const char *fmt, ...);
 
+char *strstrip(char *str);
 int str_read_file(const char *file, char **buffer, bool warn);
 char *trace_append_file(const char *dir, const char *name);
 char *trace_find_tracing_dir(bool debugfs);
@@ -102,6 +117,11 @@ int trace_append_filter(char **filter, unsigned int *state,
 			enum tracefs_compare compare,
 			 const char *val);
 
+void *trace_mmap(int fd, struct kbuffer *kbuf);
+void trace_unmap(void *mapping);
+int trace_mmap_load_subbuf(void *mapping, struct kbuffer *kbuf);
+int trace_mmap_read(void *mapping, void *buffer);
+
 struct tracefs_synth *synth_init_from(struct tep_handle *tep,
 				      const char *start_system,
 				      const char *start_event);
diff --git a/include/tracefs.h b/include/tracefs.h
index 3547b5a..b6e0f6b 100644
--- a/include/tracefs.h
+++ b/include/tracefs.h
@@ -9,6 +9,7 @@
 #include <fcntl.h>
 #include <sched.h>
 #include <event-parse.h>
+#include <kbuffer.h>
 
 char *tracefs_get_tracing_file(const char *name);
 void tracefs_put_tracing_file(char *name);
@@ -23,6 +24,8 @@ int tracefs_tracing_dir_is_mounted(bool mount, const char **path);
 struct tracefs_instance;
 
 void tracefs_instance_free(struct tracefs_instance *instance);
+void tracefs_instance_reset(struct tracefs_instance *instance);
+int tracefs_instance_clear(struct tracefs_instance *instance);
 struct tracefs_instance *tracefs_instance_create(const char *name);
 struct tracefs_instance *tracefs_instance_alloc(const char *tracing_dir,
 						const char *name);
@@ -35,6 +38,8 @@ tracefs_instance_get_file(struct tracefs_instance *instance, const char *file);
 char *tracefs_instance_get_dir(struct tracefs_instance *instance);
 int tracefs_instance_file_write(struct tracefs_instance *instance,
 				const char *file, const char *str);
+int tracefs_instance_file_write_number(struct tracefs_instance *instance,
+				       const char *file, size_t val);
 int tracefs_instance_file_append(struct tracefs_instance *instance,
 				 const char *file, const char *str);
 int tracefs_instance_file_clear(struct tracefs_instance *instance,
@@ -58,8 +63,26 @@ int tracefs_instance_get_affinity_set(struct tracefs_instance *instance,
 				      cpu_set_t *set, size_t set_size);
 ssize_t tracefs_instance_get_buffer_size(struct tracefs_instance *instance, int cpu);
 int tracefs_instance_set_buffer_size(struct tracefs_instance *instance, size_t size, int cpu);
+ssize_t tracefs_instance_get_subbuf_size(struct tracefs_instance *instance);
+int tracefs_instance_set_subbuf_size(struct tracefs_instance *instance, size_t size);
 char **tracefs_instances(const char *regex);
 
+int tracefs_instance_get_buffer_percent(struct tracefs_instance *instance);
+int tracefs_instance_set_buffer_percent(struct tracefs_instance *instance, int val);
+
+struct tracefs_buffer_stat;
+
+struct tracefs_buffer_stat *tracefs_instance_get_stat(struct tracefs_instance *instance, int cpu);
+void tracefs_instance_put_stat(struct tracefs_buffer_stat *tstat);
+ssize_t tracefs_buffer_stat_entries(struct tracefs_buffer_stat *tstat);
+ssize_t tracefs_buffer_stat_overrun(struct tracefs_buffer_stat *tstat);
+ssize_t tracefs_buffer_stat_commit_overrun(struct tracefs_buffer_stat *tstat);
+ssize_t tracefs_buffer_stat_bytes(struct tracefs_buffer_stat *tstat);
+long long tracefs_buffer_stat_event_timestamp(struct tracefs_buffer_stat *tstat);
+long long tracefs_buffer_stat_timestamp(struct tracefs_buffer_stat *tstat);
+ssize_t tracefs_buffer_stat_dropped_events(struct tracefs_buffer_stat *tstat);
+ssize_t tracefs_buffer_stat_read_events(struct tracefs_buffer_stat *tstat);
+
 bool tracefs_instance_exists(const char *name);
 bool tracefs_file_exists(struct tracefs_instance *instance, const char *name);
 bool tracefs_dir_exists(struct tracefs_instance *instance, const char *name);
@@ -137,6 +160,10 @@ int tracefs_follow_missed_events(struct tracefs_instance *instance,
 						 struct tep_record *,
 						 int, void *),
 				 void *callback_data);
+int tracefs_follow_event_clear(struct tracefs_instance *instance,
+			  const char *system, const char *event_name);
+int tracefs_follow_missed_events_clear(struct tracefs_instance *instance);
+
 
 char *tracefs_event_get_file(struct tracefs_instance *instance,
 			     const char *system, const char *event,
@@ -158,6 +185,7 @@ bool tracefs_event_file_exists(struct tracefs_instance *instance,
 			       const char *file);
 
 char **tracefs_tracers(const char *tracing_dir);
+char **tracefs_instance_tracers(struct tracefs_instance *instance);
 
 struct tep_handle *tracefs_local_events(const char *tracing_dir);
 struct tep_handle *tracefs_local_events_system(const char *tracing_dir,
@@ -167,6 +195,8 @@ int tracefs_fill_local_events(const char *tracing_dir,
 
 int tracefs_load_cmdlines(const char *tracing_dir, struct tep_handle *tep);
 
+int tracefs_load_headers(const char *tracing_dir, struct tep_handle *tep);
+
 char *tracefs_get_clock(struct tracefs_instance *instance);
 
 enum tracefs_option_id {
@@ -239,6 +269,13 @@ enum {
 	TRACEFS_FL_FUTURE	= (1 << 2),
 };
 
+int tracefs_filter_pid_function(struct tracefs_instance *instance, int pid,
+				bool reset, bool notrace);
+int tracefs_filter_pid_function_clear(struct tracefs_instance *instance, bool notrace);
+int tracefs_filter_pid_events(struct tracefs_instance *instance, int pid,
+			     bool reset, bool notrace);
+int tracefs_filter_pid_events_clear(struct tracefs_instance *instance, bool notrace);
+
 int tracefs_function_filter(struct tracefs_instance *instance, const char *filter,
 			    const char *module, unsigned int flags);
 int tracefs_function_notrace(struct tracefs_instance *instance, const char *filter,
@@ -323,6 +360,8 @@ int tracefs_kprobe_raw(const char *system, const char *event,
 		       const char *addr, const char *format);
 int tracefs_kretprobe_raw(const char *system, const char *event,
 			  const char *addr, const char *format);
+int tracefs_kprobe_destroy(const char *system, const char *event,
+			   const char *addr, const char *format, bool force);
 
 enum tracefs_hist_key_type {
 	TRACEFS_HIST_KEY_NORMAL = 0,
@@ -334,6 +373,7 @@ enum tracefs_hist_key_type {
 	TRACEFS_HIST_KEY_LOG,
 	TRACEFS_HIST_KEY_USECS,
 	TRACEFS_HIST_KEY_BUCKETS,
+	TRACEFS_HIST_KEY_STACKTRACE,
 	TRACEFS_HIST_KEY_MAX
 };
 
@@ -448,7 +488,7 @@ int tracefs_hist_command(struct tracefs_instance *instance,
 static inline int tracefs_hist_start(struct tracefs_instance *instance,
 				     struct tracefs_hist *hist)
 {
-	return tracefs_hist_command(instance, hist, 0);
+	return tracefs_hist_command(instance, hist, TRACEFS_HIST_CMD_START);
 }
 
 /**
@@ -553,6 +593,8 @@ int tracefs_event_verify_filter(struct tep_event *event, const char *filter,
 #define TRACEFS_TIMESTAMP "common_timestamp"
 #define TRACEFS_TIMESTAMP_USECS "common_timestamp.usecs"
 
+#define TRACEFS_STACKTRACE "common_stacktrace"
+
 enum tracefs_synth_handler {
 	TRACEFS_SYNTH_HANDLE_NONE	= 0,
 	TRACEFS_SYNTH_HANDLE_MATCH,
@@ -607,6 +649,7 @@ struct tracefs_hist *tracefs_synth_get_start_hist(struct tracefs_synth *synth);
 int tracefs_synth_create(struct tracefs_synth *synth);
 int tracefs_synth_destroy(struct tracefs_synth *synth);
 void tracefs_synth_free(struct tracefs_synth *synth);
+int tracefs_synth_set_instance(struct tracefs_synth *synth, struct tracefs_instance *instance);
 int tracefs_synth_echo_cmd(struct trace_seq *seq, struct tracefs_synth *synth);
 int tracefs_synth_raw_fmt(struct trace_seq *seq, struct tracefs_synth *synth);
 const char *tracefs_synth_show_event(struct tracefs_synth *synth);
@@ -627,11 +670,42 @@ void tracefs_cpu_close(struct tracefs_cpu *tcpu);
 void tracefs_cpu_free_fd(struct tracefs_cpu *tcpu);
 int tracefs_cpu_read_size(struct tracefs_cpu *tcpu);
 int tracefs_cpu_read(struct tracefs_cpu *tcpu, void *buffer, bool nonblock);
+struct kbuffer *tracefs_cpu_read_buf(struct tracefs_cpu *tcpu, bool nonblock);
 int tracefs_cpu_buffered_read(struct tracefs_cpu *tcpu, void *buffer, bool nonblock);
+struct kbuffer *tracefs_cpu_buffered_read_buf(struct tracefs_cpu *tcpu, bool nonblock);
 int tracefs_cpu_write(struct tracefs_cpu *tcpu, int wfd, bool nonblock);
 int tracefs_cpu_stop(struct tracefs_cpu *tcpu);
 int tracefs_cpu_flush(struct tracefs_cpu *tcpu, void *buffer);
+struct kbuffer *tracefs_cpu_flush_buf(struct tracefs_cpu *tcpu);
 int tracefs_cpu_flush_write(struct tracefs_cpu *tcpu, int wfd);
 int tracefs_cpu_pipe(struct tracefs_cpu *tcpu, int wfd, bool nonblock);
 
+struct tracefs_cpu *
+tracefs_cpu_snapshot_open(struct tracefs_instance *instance, int cpu, bool nonblock);
+int tracefs_iterate_snapshot_events(struct tep_handle *tep,
+				    struct tracefs_instance *instance,
+				    cpu_set_t *cpus, int cpu_size,
+				    int (*callback)(struct tep_event *,
+						    struct tep_record *,
+						    int, void *),
+				    void *callback_context);
+int tracefs_snapshot_snap(struct tracefs_instance *instance);
+int tracefs_snapshot_clear(struct tracefs_instance *instance);
+int tracefs_snapshot_free(struct tracefs_instance *instance);
+
+/* Memory mapping of ring buffer */
+bool tracefs_cpu_is_mapped(struct tracefs_cpu *tcpu);
+bool tracefs_mapped_is_supported(void);
+int tracefs_cpu_map(struct tracefs_cpu *tcpu);
+void tracefs_cpu_unmap(struct tracefs_cpu *tcpu);
+struct tracefs_cpu *tracefs_cpu_open_mapped(struct tracefs_instance *instance,
+					    int cpu, bool nonblock);
+
+/* Mapping vsocket cids to pids using tracing */
+int tracefs_instance_find_cid_pid(struct tracefs_instance *instance, int cid);
+int tracefs_find_cid_pid(int cid);
+
+/* More guest helpers */
+int tracefs_time_conversion(int cpu, int *shift, int *mult, long long *offset);
+
 #endif /* _TRACE_FS_H */
diff --git a/meson.build b/meson.build
new file mode 100644
index 0000000..2258ca0
--- /dev/null
+++ b/meson.build
@@ -0,0 +1,53 @@
+# SPDX-License-Identifier: LGPL-2.1
+#
+# Copyright (c) 2023 Daniel Wagner, SUSE LLC
+
+project(
+    'libtracefs', ['c'],
+    meson_version: '>= 0.50.0',
+    license: 'LGPL-2.1',
+    version: '1.8.1',
+    default_options: [
+        'c_std=gnu99',
+        'buildtype=debug',
+        'default_library=both',
+        'prefix=/usr/local',
+        'warning_level=1'])
+
+library_version = meson.project_version()
+
+libtraceevent_dep = dependency('libtraceevent', version: '>= 1.8.1', required: true)
+threads_dep = dependency('threads', required: true)
+cunit_dep = dependency('cunit', required : false)
+
+prefixdir = get_option('prefix')
+bindir = join_paths(prefixdir, get_option('bindir'))
+mandir = join_paths(prefixdir, get_option('mandir'))
+htmldir = join_paths(prefixdir, get_option('htmldir'))
+
+add_project_arguments(
+    [
+        '-D_GNU_SOURCE',
+    ],
+    language : 'c')
+
+incdir = include_directories(['include'])
+
+subdir('src')
+subdir('include')
+if get_option('utest') and cunit_dep.found()
+    subdir('utest')
+endif
+if get_option('samples')
+subdir('samples')
+endif
+
+if get_option('doc')
+subdir('Documentation')
+
+custom_target(
+    'docs',
+    output: 'docs',
+    depends: [html, man],
+    command: ['echo'])
+endif
diff --git a/meson_options.txt b/meson_options.txt
new file mode 100644
index 0000000..a48efea
--- /dev/null
+++ b/meson_options.txt
@@ -0,0 +1,22 @@
+# SPDX-License-Identifier: LGPL-2.1
+#
+# Copyright (c) 2023 Daniel Wagner, SUSE LLC
+
+option('htmldir', type : 'string', value : 'share/doc/libtracefs-doc',
+       description : 'directory for HTML documentation')
+option('asciidoctor', type : 'boolean', value: false,
+       description : 'use asciidoctor instead of asciidoc')
+option('docbook-xls-172', type : 'boolean', value : false,
+       description : 'enable docbook XLS 172 workaround')
+option('asciidoc-no-roff', type : 'boolean', value : false,
+       description : 'enable no roff workaround')
+option('man-bold-literal', type : 'boolean', value : false,
+       description : 'enable bold literals')
+option('docbook-suppress-sp', type : 'boolean', value : false,
+       description : 'docbook suppress sp')
+option('doc', type : 'boolean', value: true,
+       description : 'produce documentation')
+option('samples', type : 'boolean', value: true,
+       description : 'build samples')
+option('utest', type : 'boolean', value: true,
+       description : 'build utest')
diff --git a/samples/Makefile b/samples/Makefile
index 743bddb..7b68ae7 100644
--- a/samples/Makefile
+++ b/samples/Makefile
@@ -22,6 +22,11 @@ EXAMPLES += tracer
 EXAMPLES += stream
 EXAMPLES += instances-affinity
 EXAMPLES += cpu
+EXAMPLES += guest
+EXAMPLES += cpu-buf
+EXAMPLES += instances-stat
+EXAMPLES += instances-subbuf
+EXAMPLES += cpu-map
 
 TARGETS :=
 TARGETS += sqlhist
@@ -62,6 +67,10 @@ $(EXAMPLES): $(patsubst %,$(sdir)/%,$(TARGETS))
 #
 # $(bdir)/XX.o: $(bdir)/XX.c
 #	$(CC) -g -Wall $(CFLAGS) -c -o $@ $^ -I../include/ $(LIBTRACEEVENT_INCLUDES)
+$(bdir)/cpu-map.o: $(bdir)/cpu-map.c
+	$(CC) -g -Wall $(CFLAGS) -c -o $@ $^ -I../include/ $(LIBTRACEEVENT_INCLUDES)
+$(bdir)/kprobes.o: $(bdir)/kprobes.c
+	$(CC) -g -Wall $(CFLAGS) -c -o $@ $^ -I../include/ $(LIBTRACEEVENT_INCLUDES)
 
 $(bdir)/%.o: $(bdir)/%.c
 	$(call do_sample_obj,$@,$^)
diff --git a/samples/cpu-map.c b/samples/cpu-map.c
new file mode 100644
index 0000000..b42742d
--- /dev/null
+++ b/samples/cpu-map.c
@@ -0,0 +1,90 @@
+#include <stdlib.h>
+#include <ctype.h>
+#include <tracefs.h>
+
+static void read_subbuf(struct tep_handle *tep, struct kbuffer *kbuf)
+{
+	static struct trace_seq seq;
+	struct tep_record record;
+	int missed_events;
+
+	if (seq.buffer)
+		trace_seq_reset(&seq);
+	else
+		trace_seq_init(&seq);
+
+	while ((record.data = kbuffer_read_event(kbuf, &record.ts))) {
+		record.size = kbuffer_event_size(kbuf);
+		missed_events = kbuffer_missed_events(kbuf);
+		if (missed_events) {
+			printf("[MISSED EVENTS");
+			if (missed_events > 0)
+				printf(": %d]\n", missed_events);
+			else
+				printf("]\n");
+		}
+		kbuffer_next_event(kbuf, NULL);
+		tep_print_event(tep, &seq, &record,
+				"%s-%d %6.1000d\t%s: %s\n",
+				TEP_PRINT_COMM,
+				TEP_PRINT_PID,
+				TEP_PRINT_TIME,
+				TEP_PRINT_NAME,
+				TEP_PRINT_INFO);
+		trace_seq_do_printf(&seq);
+		trace_seq_reset(&seq);
+	}
+}
+
+int main (int argc, char **argv)
+{
+	struct tracefs_cpu *tcpu;
+	struct tep_handle *tep;
+	struct kbuffer *kbuf;
+	bool mapped;
+	int cpu;
+
+	if (argc < 2 || !isdigit(argv[1][0])) {
+		printf("usage: %s cpu\n\n", argv[0]);
+		exit(-1);
+	}
+
+	cpu = atoi(argv[1]);
+
+	tep = tracefs_local_events(NULL);
+	if (!tep) {
+		perror("Reading trace event formats");
+		exit(-1);
+	}
+
+	tcpu = tracefs_cpu_open_mapped(NULL, cpu, 0);
+	if (!tcpu) {
+		perror("Open CPU 0 file");
+		exit(-1);
+	}
+
+	/*
+	 * If this kernel supports mapping, use normal read,
+	 * otherwise use the piped buffer read, although if
+	 * the mapping succeeded, tracefs_cpu_buffered_read_buf()
+	 * acts the same as tracefs_cpu_read_buf(). But this is just
+	 * an example on how to use tracefs_cpu_is_mapped().
+	 */
+	mapped = tracefs_cpu_is_mapped(tcpu);
+	if (!mapped)
+		printf("Was not able to map, falling back to buffered read\n");
+	while ((kbuf = mapped ? tracefs_cpu_read_buf(tcpu, true) :
+			tracefs_cpu_buffered_read_buf(tcpu, true))) {
+		read_subbuf(tep, kbuf);
+	}
+
+	kbuf = tracefs_cpu_flush_buf(tcpu);
+	if (kbuf)
+		read_subbuf(tep, kbuf);
+
+	tracefs_cpu_close(tcpu);
+	tep_free(tep);
+
+	return 0;
+}
+
diff --git a/samples/extract-example.sh b/samples/extract-example.sh
new file mode 100644
index 0000000..c5c0f70
--- /dev/null
+++ b/samples/extract-example.sh
@@ -0,0 +1,3 @@
+#!/bin/bash
+
+cat $1 | sed -ne '/^EXAMPLE/,/FILES/ { /EXAMPLE/,+2d ; /^FILES/d ;  /^--/d ; p}' > $2
diff --git a/samples/meson.build b/samples/meson.build
new file mode 100644
index 0000000..112b122
--- /dev/null
+++ b/samples/meson.build
@@ -0,0 +1,45 @@
+# SPDX-License-Identifier: LGPL-2.1
+#
+# Copyright (c) 2023 Daniel Wagner, SUSE LLC
+
+examples = [
+    'dynevents',
+    'kprobes',
+    'eprobes',
+    'uprobes',
+    'synth',
+    'error',
+    'filter',
+    'function-filter',
+    'hist',
+    'hist-cont',
+    'tracer',
+    'stream',
+    'instances-affinity',
+    'cpu',
+]
+
+extract_examples = find_program('extract-example.sh')
+gen = generator(
+   extract_examples,
+   output: '@BASENAME@.c',
+   arguments: ['@INPUT@', '@OUTPUT@'])
+
+foreach ex : examples
+    src = gen.process(meson.current_source_dir() + '/../Documentation/libtracefs-@0@.txt'.format(ex))
+    executable(
+        ex.underscorify(),
+        src,
+        dependencies: [libtracefs_dep, libtraceevent_dep, threads_dep],
+        include_directories: [incdir])
+endforeach
+
+# sqlhist is unique and stands on its own
+src = gen.process(meson.current_source_dir() + '/../Documentation/libtracefs-sql.txt')
+executable(
+   'sqlhist',
+   src,
+   dependencies: [libtracefs_dep, libtraceevent_dep, threads_dep],
+   include_directories: [incdir],
+   install: true,
+   install_dir: bindir)
diff --git a/src/Makefile b/src/Makefile
index e2965bc..be81059 100644
--- a/src/Makefile
+++ b/src/Makefile
@@ -10,11 +10,19 @@ OBJS += tracefs-tools.o
 OBJS += tracefs-marker.o
 OBJS += tracefs-kprobes.o
 OBJS += tracefs-hist.o
+OBJS += tracefs-stats.o
 OBJS += tracefs-filter.o
 OBJS += tracefs-dynevents.o
 OBJS += tracefs-eprobes.o
 OBJS += tracefs-uprobes.o
 OBJS += tracefs-record.o
+OBJS += tracefs-mmap.o
+ifeq ($(VSOCK_DEFINED), 1)
+OBJS += tracefs-vsock.o
+endif
+ifeq ($(PERF_DEFINED), 1)
+OBJS += tracefs-perf.o
+endif
 
 # Order matters for the the three below
 OBJS += sqlhist-lex.o
diff --git a/src/meson.build b/src/meson.build
new file mode 100644
index 0000000..31fd9ed
--- /dev/null
+++ b/src/meson.build
@@ -0,0 +1,65 @@
+# SPDX-License-Identifier: LGPL-2.1
+#
+# Copyright (c) 2023 Daniel Wagner, SUSE LLC
+
+sources= [
+   'tracefs-dynevents.c',
+   'tracefs-eprobes.c',
+   'tracefs-events.c',
+   'tracefs-filter.c',
+   'tracefs-hist.c',
+   'tracefs-instance.c',
+   'tracefs-kprobes.c',
+   'tracefs-marker.c',
+   'tracefs-mmap.c',
+   'tracefs-record.c',
+   'tracefs-sqlhist.c',
+   'tracefs-tools.c',
+   'tracefs-uprobes.c',
+   'tracefs-utils.c',
+   'tracefs-mmap.c',
+]
+
+flex = find_program('flex', required: true)
+bison = find_program('bison', required: true)
+
+lgen = generator(flex,
+output : '@PLAINNAME@.yy.c',
+arguments : ['-o', '@OUTPUT@', '@INPUT@'])
+
+pgen = generator(bison,
+output : ['@BASENAME@.tab.c', '@BASENAME@.tab.h'],
+arguments : ['@INPUT@', '--defines=@OUTPUT1@', '--output=@OUTPUT0@'])
+
+lfiles = lgen.process('sqlhist.l')
+pfiles = pgen.process('sqlhist.y')
+
+libtracefs = library(
+    'tracefs',
+    sources, lfiles, pfiles,
+    version: library_version,
+    dependencies: [libtraceevent_dep, threads_dep],
+    include_directories: [incdir],
+    install: true)
+
+libtracefs_static = static_library(
+    'tracefs_static',
+    sources, lfiles, pfiles,
+    dependencies: [libtraceevent_dep, threads_dep],
+    include_directories: [incdir],
+    install: false)
+
+pkg = import('pkgconfig')
+pkg.generate(
+    libtracefs,
+    libraries: [libtraceevent_dep],
+    subdirs: 'libtracefs',
+    filebase: meson.project_name(),
+    name: meson.project_name(),
+    version: meson.project_version(),
+    description: 'Manage trace fs',
+    url: 'https://git.kernel.org/pub/scm/libs/libtrace/libtracefs.git/')
+
+libtracefs_dep = declare_dependency(
+    include_directories: ['.'],
+    link_with: libtracefs)
diff --git a/src/tracefs-dynevents.c b/src/tracefs-dynevents.c
index 7a3c45c..85c1fcd 100644
--- a/src/tracefs-dynevents.c
+++ b/src/tracefs-dynevents.c
@@ -589,6 +589,7 @@ tracefs_dynevent_get_all(unsigned int types, const char *system)
 	return all_events;
 
 error:
+	free(events);
 	if (all_events) {
 		for (i = 0; i < all; i++)
 			free(all_events[i]);
diff --git a/src/tracefs-events.c b/src/tracefs-events.c
index c2adf41..83069aa 100644
--- a/src/tracefs-events.c
+++ b/src/tracefs-events.c
@@ -31,8 +31,6 @@ struct cpu_iterate {
 	struct tep_record record;
 	struct tep_event *event;
 	struct kbuffer *kbuf;
-	void *page;
-	int psize;
 	int cpu;
 };
 
@@ -63,46 +61,24 @@ static int read_kbuf_record(struct cpu_iterate *cpu)
 
 int read_next_page(struct tep_handle *tep, struct cpu_iterate *cpu)
 {
-	enum kbuffer_long_size long_size;
-	enum kbuffer_endian endian;
-	int r;
+	struct kbuffer *kbuf;
 
 	if (!cpu->tcpu)
 		return -1;
 
-	r = tracefs_cpu_buffered_read(cpu->tcpu, cpu->page, true);
+	kbuf = tracefs_cpu_buffered_read_buf(cpu->tcpu, true);
 	/*
-	 * tracefs_cpu_buffered_read() only reads in full subbuffer size,
+	 * tracefs_cpu_buffered_read_buf() only reads in full subbuffer size,
 	 * but this wants partial buffers as well. If the function returns
-	 * empty (-1 for EAGAIN), try tracefs_cpu_read() next, as that can
+	 * empty (-1 for EAGAIN), try tracefs_cpu_flush_buf() next, as that can
 	 * read partially filled buffers too, but isn't as efficient.
 	 */
-	if (r <= 0)
-		r = tracefs_cpu_read(cpu->tcpu, cpu->page, true);
-	if (r <= 0)
+	if (!kbuf)
+		kbuf = tracefs_cpu_flush_buf(cpu->tcpu);
+	if (!kbuf)
 		return -1;
 
-	if (!cpu->kbuf) {
-		if (tep_is_file_bigendian(tep))
-			endian = KBUFFER_ENDIAN_BIG;
-		else
-			endian = KBUFFER_ENDIAN_LITTLE;
-
-		if (tep_get_header_page_size(tep) == 8)
-			long_size = KBUFFER_LSIZE_8;
-		else
-			long_size = KBUFFER_LSIZE_4;
-
-		cpu->kbuf = kbuffer_alloc(long_size, endian);
-		if (!cpu->kbuf)
-			return -1;
-	}
-
-	kbuffer_load_subbuffer(cpu->kbuf, cpu->page);
-	if (kbuffer_subbuffer_size(cpu->kbuf) > r) {
-		tracefs_warning("%s: page_size > %d", __func__, r);
-		return -1;
-	}
+	cpu->kbuf = kbuf;
 
 	return 0;
 }
@@ -280,7 +256,8 @@ static int read_cpu_pages(struct tep_handle *tep, struct tracefs_instance *insta
 }
 
 static int open_cpu_files(struct tracefs_instance *instance, cpu_set_t *cpus,
-			  int cpu_size, struct cpu_iterate **all_cpus, int *count)
+			  int cpu_size, struct cpu_iterate **all_cpus, int *count,
+			  bool snapshot)
 {
 	struct tracefs_cpu *tcpu;
 	struct cpu_iterate *tmp;
@@ -294,10 +271,16 @@ static int open_cpu_files(struct tracefs_instance *instance, cpu_set_t *cpus,
 	for (cpu = 0; cpu < nr_cpus; cpu++) {
 		if (cpus && !CPU_ISSET_S(cpu, cpu_size, cpus))
 			continue;
-		tcpu = tracefs_cpu_open(instance, cpu, true);
+		if (snapshot)
+			tcpu = tracefs_cpu_snapshot_open(instance, cpu, true);
+		else
+			tcpu = tracefs_cpu_open_mapped(instance, cpu, true);
+		if (!tcpu)
+			goto error;
+
 		tmp = realloc(*all_cpus, (i + 1) * sizeof(*tmp));
 		if (!tmp) {
-			i--;
+			tracefs_cpu_close(tcpu);
 			goto error;
 		}
 
@@ -305,24 +288,16 @@ static int open_cpu_files(struct tracefs_instance *instance, cpu_set_t *cpus,
 
 		memset(tmp + i, 0, sizeof(*tmp));
 
-		if (!tcpu)
-			goto error;
-
 		tmp[i].tcpu = tcpu;
 		tmp[i].cpu = cpu;
-		tmp[i].psize = tracefs_cpu_read_size(tcpu);
-		tmp[i].page =  malloc(tmp[i].psize);
-
-		if (!tmp[i++].page)
-			goto error;
+		i++;
 	}
 	*count = i;
 	return 0;
  error:
 	tmp = *all_cpus;
-	for (; i >= 0; i--) {
+	for (i--; i >= 0; i--) {
 		tracefs_cpu_close(tmp[i].tcpu);
-		free(tmp[i].page);
 	}
 	free(tmp);
 	*all_cpus = NULL;
@@ -392,32 +367,118 @@ int tracefs_follow_event(struct tep_handle *tep, struct tracefs_instance *instan
 	return 0;
 }
 
-static bool top_iterate_keep_going;
+/**
+ * tracefs_follow_event_clear - Remove callbacks for specific events for iterators
+ * @instance: The instance to follow
+ * @system: The system of the event to remove (NULL for all)
+ * @event_name: The name of the event to remove (NULL for all)
+ *
+ * This removes all callbacks from an instance that matches a specific
+ * event. If @event_name is NULL, then it removes all followers that match
+ * @system. If @system is NULL, then it removes all followers that match
+ * @event_name. If both @system and @event_name are NULL then it removes all
+ * followers for all events.
+ *
+ * Returns 0 on success and -1 on error (which includes no followers found)
+ */
+int tracefs_follow_event_clear(struct tracefs_instance *instance,
+			       const char *system, const char *event_name)
+{
+	struct follow_event **followers;
+	struct follow_event *follower;
+	int *nr_followers;
+	int nr;
+	int i, n;
 
-/*
- * tracefs_iterate_raw_events - Iterate through events in trace_pipe_raw,
- *				per CPU trace buffers
- * @tep: a handle to the trace event parser context
- * @instance: ftrace instance, can be NULL for the top instance
- * @cpus: Iterate only through the buffers of CPUs, set in the mask.
- *	  If NULL, iterate through all CPUs.
- * @cpu_size: size of @cpus set
- * @callback: A user function, called for each record from the file
- * @callback_context: A custom context, passed to the user callback function
+	if (instance) {
+		followers = &instance->followers;
+		nr_followers = &instance->nr_followers;
+	} else {
+		followers = &root_followers;
+		nr_followers = &nr_root_followers;
+	}
+
+	if (!*nr_followers)
+		return -1;
+
+	/* If both system and event_name are NULL just remove all */
+	if (!system && !event_name) {
+		free(*followers);
+		*followers = NULL;
+		*nr_followers = 0;
+		return 0;
+	}
+
+	nr = *nr_followers;
+	follower = *followers;
+
+	for (i = 0, n = 0; i < nr; i++) {
+		if (event_name && strcmp(event_name, follower[n].event->name) != 0) {
+			n++;
+			continue;
+		}
+		if (system && strcmp(system, follower[n].event->system) != 0) {
+			n++;
+			continue;
+		}
+		/* If there are no more after this, continue to increment i */
+		if (i == nr - 1)
+			continue;
+		/* Remove this follower */
+		memmove(&follower[n], &follower[n + 1],
+			sizeof(*follower) * (nr - (n + 1)));
+	}
+
+	/* Did we find anything? */
+	if (n == i)
+		return -1;
+
+	/* NULL out the rest */
+	memset(&follower[n], 0, (sizeof(*follower)) * (nr - n));
+	*nr_followers = n;
+
+	return 0;
+}
+
+/**
+ * tracefs_follow_missed_events_clear - Remove callbacks for missed events
+ * @instance: The instance to remove missed callback followers
  *
- * If the @callback returns non-zero, the iteration stops - in that case all
- * records from the current page will be lost from future reads
- * The events are iterated in sorted order, oldest first.
+ * This removes all callbacks from an instance that are for missed events.
  *
- * Returns -1 in case of an error, or 0 otherwise
+ * Returns 0 on success and -1 on error (which includes no followers found)
  */
-int tracefs_iterate_raw_events(struct tep_handle *tep,
-				struct tracefs_instance *instance,
-				cpu_set_t *cpus, int cpu_size,
-				int (*callback)(struct tep_event *,
-						struct tep_record *,
+int tracefs_follow_missed_events_clear(struct tracefs_instance *instance)
+{
+	struct follow_event **followers;
+	int *nr_followers;
+
+	if (instance) {
+		followers = &instance->missed_followers;
+		nr_followers = &instance->nr_missed_followers;
+	} else {
+		followers = &root_missed_followers;
+		nr_followers = &nr_root_missed_followers;
+	}
+
+	if (!*nr_followers)
+		return -1;
+
+	free(*followers);
+	*followers = NULL;
+	*nr_followers = 0;
+	return 0;
+}
+
+static bool top_iterate_keep_going;
+
+static int iterate_events(struct tep_handle *tep,
+			  struct tracefs_instance *instance,
+			  cpu_set_t *cpus, int cpu_size,
+			  int (*callback)(struct tep_event *,
+					  struct tep_record *,
 						int, void *),
-				void *callback_context)
+			  void *callback_context, bool snapshot)
 {
 	bool *keep_going = instance ? &instance->iterate_keep_going :
 				      &top_iterate_keep_going;
@@ -439,7 +500,7 @@ int tracefs_iterate_raw_events(struct tep_handle *tep,
 	if (!callback && !followers)
 		return -1;
 
-	ret = open_cpu_files(instance, cpus, cpu_size, &all_cpus, &count);
+	ret = open_cpu_files(instance, cpus, cpu_size, &all_cpus, &count, snapshot);
 	if (ret < 0)
 		goto out;
 	ret = read_cpu_pages(tep, instance, all_cpus, count,
@@ -449,9 +510,7 @@ int tracefs_iterate_raw_events(struct tep_handle *tep,
 out:
 	if (all_cpus) {
 		for (i = 0; i < count; i++) {
-			kbuffer_free(all_cpus[i].kbuf);
 			tracefs_cpu_close(all_cpus[i].tcpu);
-			free(all_cpus[i].page);
 		}
 		free(all_cpus);
 	}
@@ -459,6 +518,64 @@ out:
 	return ret;
 }
 
+/*
+ * tracefs_iterate_raw_events - Iterate through events in trace_pipe_raw,
+ *				per CPU trace buffers
+ * @tep: a handle to the trace event parser context
+ * @instance: ftrace instance, can be NULL for the top instance
+ * @cpus: Iterate only through the buffers of CPUs, set in the mask.
+ *	  If NULL, iterate through all CPUs.
+ * @cpu_size: size of @cpus set
+ * @callback: A user function, called for each record from the file
+ * @callback_context: A custom context, passed to the user callback function
+ *
+ * If the @callback returns non-zero, the iteration stops - in that case all
+ * records from the current page will be lost from future reads
+ * The events are iterated in sorted order, oldest first.
+ *
+ * Returns -1 in case of an error, or 0 otherwise
+ */
+int tracefs_iterate_raw_events(struct tep_handle *tep,
+				struct tracefs_instance *instance,
+				cpu_set_t *cpus, int cpu_size,
+				int (*callback)(struct tep_event *,
+						struct tep_record *,
+						int, void *),
+				void *callback_context)
+{
+	return iterate_events(tep, instance, cpus, cpu_size, callback,
+			      callback_context, false);
+}
+
+/*
+ * tracefs_iterate_snapshot_events - Iterate through events in snapshot_raw,
+ *				per CPU trace buffers
+ * @tep: a handle to the trace event parser context
+ * @instance: ftrace instance, can be NULL for the top instance
+ * @cpus: Iterate only through the buffers of CPUs, set in the mask.
+ *	  If NULL, iterate through all CPUs.
+ * @cpu_size: size of @cpus set
+ * @callback: A user function, called for each record from the file
+ * @callback_context: A custom context, passed to the user callback function
+ *
+ * If the @callback returns non-zero, the iteration stops - in that case all
+ * records from the current page will be lost from future reads
+ * The events are iterated in sorted order, oldest first.
+ *
+ * Returns -1 in case of an error, or 0 otherwise
+ */
+int tracefs_iterate_snapshot_events(struct tep_handle *tep,
+				    struct tracefs_instance *instance,
+				    cpu_set_t *cpus, int cpu_size,
+				    int (*callback)(struct tep_event *,
+						    struct tep_record *,
+						    int, void *),
+				    void *callback_context)
+{
+	return iterate_events(tep, instance, cpus, cpu_size, callback,
+			      callback_context, true);
+}
+
 /**
  * tracefs_iterate_stop - stop the iteration over the raw events.
  * @instance: ftrace instance, can be NULL for top tracing instance.
@@ -737,12 +854,12 @@ char **tracefs_event_systems(const char *tracing_dir)
 		enable = trace_append_file(sys, "enable");
 
 		ret = stat(enable, &st);
+		free(enable);
+		free(sys);
 		if (ret >= 0) {
 			if (add_list_string(&systems, name) < 0)
-				goto out_free;
+				break;
 		}
-		free(enable);
-		free(sys);
 	}
 
 	closedir(dir);
@@ -802,11 +919,10 @@ char **tracefs_system_events(const char *tracing_dir, const char *system)
 			free(event);
 			continue;
 		}
+		free(event);
 
 		if (add_list_string(&events, name) < 0)
-			goto out_free;
-
-		free(event);
+			break;
 	}
 
 	closedir(dir);
@@ -817,14 +933,7 @@ char **tracefs_system_events(const char *tracing_dir, const char *system)
 	return events;
 }
 
-/**
- * tracefs_tracers - returns an array of available tracers
- * @tracing_dir: The directory that contains the tracing directory
- *
- * Returns an allocate list of plugins. The array ends with NULL
- * Both the plugin names and array must be freed with tracefs_list_free()
- */
-char **tracefs_tracers(const char *tracing_dir)
+static char **list_tracers(const char *tracing_dir)
 {
 	char *available_tracers;
 	struct stat st;
@@ -882,6 +991,35 @@ char **tracefs_tracers(const char *tracing_dir)
 	return plugins;
 }
 
+/**
+ * tracefs_tracers - returns an array of available tracers
+ * @tracing_dir: The directory that contains the tracing directory
+ *
+ * Returns an allocate list of plugins. The array ends with NULL
+ * Both the plugin names and array must be freed with tracefs_list_free()
+ */
+char **tracefs_tracers(const char *tracing_dir)
+{
+	return list_tracers(tracing_dir);
+}
+
+/**
+ * tracefs_instance_tracers - returns an array of available tracers for an instance
+ * @instance: ftrace instance, can be NULL for the top instance
+ *
+ * Returns an allocate list of plugins. The array ends with NULL
+ * Both the plugin names and array must be freed with tracefs_list_free()
+ */
+char **tracefs_instance_tracers(struct tracefs_instance *instance)
+{
+	const char *tracing_dir = NULL;
+
+	if (instance)
+		tracing_dir = instance->trace_dir;
+
+	return list_tracers(tracing_dir);
+}
+
 static int load_events(struct tep_handle *tep,
 		       const char *tracing_dir, const char *system, bool check)
 {
@@ -1091,6 +1229,28 @@ int tracefs_load_cmdlines(const char *tracing_dir, struct tep_handle *tep)
 	return load_saved_cmdlines(tracing_dir, tep, true);
 }
 
+/**
+ * tracefs_load_headers - load just the headers into a tep handle
+ * @tracing_dir: The directory to load from (NULL to figure it out)
+ * @tep: The tep handle to load the headers into.
+ *
+ * Updates the @tep handle with the event and sub-buffer header
+ * information.
+ *
+ * Returns 0 on success and -1 on error.
+ */
+int tracefs_load_headers(const char *tracing_dir, struct tep_handle *tep)
+{
+	int ret;
+
+	if (!tracing_dir)
+		tracing_dir = tracefs_tracing_dir();
+
+	ret = read_header(tep, tracing_dir);
+
+	return ret < 0 ? -1 : 0;
+}
+
 static int fill_local_events_system(const char *tracing_dir,
 				    struct tep_handle *tep,
 				    const char * const *sys_names,
diff --git a/src/tracefs-filter.c b/src/tracefs-filter.c
index a3dd77b..1b1c60e 100644
--- a/src/tracefs-filter.c
+++ b/src/tracefs-filter.c
@@ -41,6 +41,13 @@ static const struct tep_format_field common_comm = {
 	.size			= 16,
 };
 
+const struct tep_format_field common_stacktrace __hidden = {
+	.type			= "unsigned long[]",
+	.name			= "stacktrace",
+	.size			= 4,
+	.flags			= TEP_FIELD_IS_ARRAY | TEP_FIELD_IS_DYNAMIC,
+};
+
 /*
  * This also must be able to accept fields that are OK via the histograms,
  * such as common_timestamp.
@@ -56,6 +63,9 @@ static const struct tep_format_field *get_event_field(struct tep_event *event,
 	if (!strcmp(field_name, TRACEFS_TIMESTAMP_USECS))
 		return &common_timestamp_usecs;
 
+	if (!strcmp(field_name, TRACEFS_STACKTRACE))
+		return &common_stacktrace;
+
 	field = tep_find_any_field(event, field_name);
 	if (!field && (!strcmp(field_name, "COMM") || !strcmp(field_name, "comm")))
 		return &common_comm;
@@ -240,12 +250,12 @@ static int append_filter(char **filter, unsigned int *state,
 	case TRACEFS_COMPARE_NE: tmp = append_string(tmp, NULL, " != "); break;
 	case TRACEFS_COMPARE_RE:
 		if (!is_string)
-			goto inval;
+			goto free;
 		tmp = append_string(tmp, NULL, "~");
 		break;
 	default:
 		if (is_string)
-			goto inval;
+			goto free;
 	}
 
 	switch (compare) {
@@ -267,6 +277,8 @@ static int append_filter(char **filter, unsigned int *state,
 	*state = S_COMPARE;
 
 	return 0;
+free:
+	free(tmp);
 inval:
 	errno = EINVAL;
 	return -1;
@@ -791,6 +803,138 @@ int tracefs_event_filter_clear(struct tracefs_instance *instance,
 					"filter", "0");
 }
 
+static int write_pid_file(struct tracefs_instance *instance, const char *file,
+		      int pid, bool reset)
+{
+	char buf[64];
+	int ret;
+
+	sprintf(buf, "%d", pid);
+
+	if (reset)
+		ret = tracefs_instance_file_write(instance, file, buf);
+	else
+		ret = tracefs_instance_file_append(instance, file, buf);
+
+	return ret < 0 ? -1 : 0;
+}
+
+/**
+ * tracefs_filter_pid_function - set function tracing to filter the pid
+ * @instance: The instance to set the filter to
+ * @pid: The pid to filter on
+ * @reset: If set, it will clear out all other pids being filtered
+ * @notrace: If set, it will filter all but this pid
+ *
+ * Set the function tracing to trace or avoid tracing a given @pid.
+ * If @notrace is set, then it will avoid tracing the @pid.
+ * If @reset is set, it will clear the filter as well.
+ *
+ * Note, @reset only resets what pids will be traced, or what pids will
+ *   not be traced. That is, if both @reset and @notrace is set, then
+ *   it will not affect pids that are being traced. It will only clear
+ *   the pids that are not being traced. To do both, The
+ *   tracefs_filter_pid_function_clear() needs to be called with the
+ *   inverse of @notrace.
+ *
+ * Returns -1 on error, 0 on success.
+ */
+int tracefs_filter_pid_function(struct tracefs_instance *instance, int pid,
+				bool reset, bool notrace)
+{
+	const char *file;
+
+	if (notrace)
+		file = "set_ftrace_notrace_pid";
+	else
+		file = "set_ftrace_pid";
+
+	return write_pid_file(instance, file, pid, reset);
+}
+
+/**
+ * tracefs_filter_pid_function_clear - reset pid function filtering
+ * @instance: The instance to reset function filtering
+ * @notrace: If set, it will filter reset the pids that are not to be traced
+ *
+ * This will clear the function filtering on pids. If @notrace is set,
+ * it will clear the filtering on what pids should not be traced.
+ *
+ * Returns -1 on error, 0 on success.
+ */
+int tracefs_filter_pid_function_clear(struct tracefs_instance *instance, bool notrace)
+{
+	const char *file;
+	int ret;
+
+	if (notrace)
+		file = "set_ftrace_notrace_pid";
+	else
+		file = "set_ftrace_pid";
+
+	ret = tracefs_instance_file_write(instance, file, "");
+
+	return ret < 0 ? -1 : 0;
+}
+
+/**
+ * tracefs_filter_pid_events - set event filtering to a specific pid
+ * @instance: The instance to set the filter to
+ * @pid: The pid to filter on
+ * @reset: If set, it will clear out all other pids being filtered
+ * @notrace: If set, it will filter all but this pid
+ *
+ * Set the event filtering to trace or avoid tracing a given @pid.
+ * If @notrace is set, then it will avoid tracing the @pid.
+ * If @reset is set, it will clear the filter as well.
+ *
+ * Note, @reset only resets what pids will be traced, or what pids will
+ *   not be traced. That is, if both @reset and @notrace is set, then
+ *   it will not affect pids that are being traced. It will only clear
+ *   the pids that are not being traced. To do both, The
+ *   tracefs_filter_pid_events_clear() needs to be called with the
+ *   inverse of @notrace.
+ *
+ * Returns -1 on error, 0 on success.
+ */
+int tracefs_filter_pid_events(struct tracefs_instance *instance, int pid,
+			     bool reset, bool notrace)
+{
+	const char *file;
+
+	if (notrace)
+		file = "set_event_notrace_pid";
+	else
+		file = "set_event_pid";
+
+	return write_pid_file(instance, file, pid, reset);
+}
+
+/**
+ * tracefs_filter_pid_events_clear - reset pid events filtering
+ * @instance: The instance to reset function filtering
+ * @notrace: If set, it will filter reset the pids that are not to be traced
+ *
+ * This will clear the function filtering on pids. If @notrace is set,
+ * it will clear the filtering on what pids should not be traced.
+ *
+ * Returns -1 on error, 0 on success.
+ */
+int tracefs_filter_pid_events_clear(struct tracefs_instance *instance, bool notrace)
+{
+	const char *file;
+	int ret;
+
+	if (notrace)
+		file = "set_event_notrace_pid";
+	else
+		file = "set_event_pid";
+
+	ret = tracefs_instance_file_write(instance, file, "");
+
+	return ret < 0 ? -1 : 0;
+}
+
 /** Deprecated **/
 int tracefs_event_append_filter(struct tep_event *event, char **filter,
 				enum tracefs_filter type,
diff --git a/src/tracefs-hist.c b/src/tracefs-hist.c
index fb6231e..4f4971e 100644
--- a/src/tracefs-hist.c
+++ b/src/tracefs-hist.c
@@ -13,6 +13,7 @@
 #include <errno.h>
 #include <fcntl.h>
 #include <limits.h>
+#include <ctype.h>
 #include <sys/time.h>
 #include <sys/types.h>
 
@@ -416,6 +417,9 @@ int tracefs_hist_add_key_cnt(struct tracefs_hist *hist, const char *key,
 	case TRACEFS_HIST_KEY_BUCKETS:
 		ret = asprintf(&key_type, "%s.buckets=%d", key, cnt);
 		break;
+	case TRACEFS_HIST_KEY_STACKTRACE:
+		ret = asprintf(&key_type, "%s.stacktrace", key);
+		break;
 	case TRACEFS_HIST_KEY_MAX:
 		/* error */
 		break;
@@ -500,14 +504,23 @@ add_sort_key(struct tracefs_hist *hist, const char *sort_key, char **list)
 {
 	char **key_list = hist->keys;
 	char **val_list = hist->values;
+	char *dot;
+	int len;
 	int i;
 
 	if (strcmp(sort_key, TRACEFS_HIST_HITCOUNT) == 0)
 		goto out;
 
+	len = strlen(sort_key);
+
 	for (i = 0; key_list[i]; i++) {
 		if (strcmp(key_list[i], sort_key) == 0)
 			break;
+		dot = strchr(key_list[i], '.');
+		if (!dot || dot - key_list[i] != len)
+			continue;
+		if (strncmp(key_list[i], sort_key, len) == 0)
+			break;
 	}
 
 	if (!key_list[i] && val_list) {
@@ -583,8 +596,10 @@ int tracefs_hist_set_sort_key(struct tracefs_hist *hist,
 		if (!sort_key)
 			break;
 		tmp = add_sort_key(hist, sort_key, list);
-		if (!tmp)
+		if (!tmp) {
+			va_end(ap);
 			goto fail;
+		}
 		list = tmp;
 	}
 	va_end(ap);
@@ -736,6 +751,7 @@ struct name_hash {
  * @start_parens: Current parenthesis level for start event
  * @end_parens: Current parenthesis level for end event
  * @new_format: onmatch().trace(synth_event,..) or onmatch().synth_event(...)
+ * @created: Set if tracefs_synth_create() was called on this; cleared on destroy()
  */
 struct tracefs_synth {
 	struct tracefs_instance *instance;
@@ -766,6 +782,7 @@ struct tracefs_synth {
 	char			arg_name[16];
 	int			arg_cnt;
 	bool			new_format;
+	bool			created;
 };
 
  /*
@@ -915,7 +932,8 @@ static char *add_synth_field(const struct tep_format_field *field,
 	bool sign;
 
 	if (field->flags & TEP_FIELD_IS_ARRAY) {
-		str = strdup("char");
+		str = strdup(field->type);
+		str = strtok(str, "[");
 		str = append_string(str, " ", name);
 		str = append_string(str, NULL, "[");
 
@@ -967,6 +985,9 @@ static char *add_synth_field(const struct tep_format_field *field,
 		return NULL;
 	}
 
+	if (field == &common_stacktrace)
+		type = field->type;
+
 	str = strdup(type);
 	str = append_string(str, " ", name);
 	return append_string(str, NULL, ";");
@@ -1555,7 +1576,7 @@ int tracefs_synth_add_end_field(struct tracefs_synth *synth,
 	const struct tep_format_field *field;
 	const char *hname = NULL;
 	char *tmp_var = NULL;
-	int ret;
+	int ret = -1;
 
 	if (!synth || !end_field) {
 		errno = EINVAL;
@@ -1573,15 +1594,15 @@ int tracefs_synth_add_end_field(struct tracefs_synth *synth,
 		tmp_var = new_arg(synth);
 
 	if (!trace_verify_event_field(synth->end_event, end_field, &field))
-		return -1;
+		goto out;
 
 	ret = add_var(&synth->end_vars, name ? hname : tmp_var, end_field, false);
 	if (ret)
 		goto out;
 
 	ret = add_synth_fields(synth, field, name, hname ? : tmp_var);
-	free(tmp_var);
  out:
+	free(tmp_var);
 	return ret;
 }
 
@@ -1669,27 +1690,81 @@ int tracefs_synth_append_end_filter(struct tracefs_synth *synth,
 				   type, field, compare, val);
 }
 
-static int test_max_var(struct tracefs_synth *synth, const char *var)
+static bool var_match(const char *match, const char *var, int match_len, int len)
+{
+	char copy[match_len + 1];
+	char *p, *e;
+
+	strncpy(copy, match, match_len + 1);
+	copy[match_len] = '\0';
+
+	p = copy;
+
+	if (*p == '$')
+		p++;
+
+	if (strncmp(p, var, len) == 0)
+		return true;
+
+	/* Check if this was hashed __<var>_<number>_<number> */
+	if (p[0] != '_' || p[1] != '_')
+		return false;
+
+	p += 2;
+
+	e = copy + match_len - 1;
+	if (!isdigit(*e))
+		return false;
+	while (isdigit(*e) && e > p)
+		e--;
+	if (e == p || *e != '_')
+		return false;
+
+	e--;
+	if (!isdigit(*e))
+		return false;
+	while (isdigit(*e) && e > p)
+		e--;
+	if (e == p || *e != '_')
+		return false;
+
+	if (e - p != len)
+		return false;
+
+	*e = '\0';
+
+	return strncmp(p, var, len) == 0;
+}
+
+static char *test_max_var(struct tracefs_synth *synth, const char *var)
 {
 	char **vars = synth->end_vars;
+	char *ret;
 	char *p;
 	int len;
 	int i;
 
 	len = strlen(var);
+	if (var[0] == '$') {
+		var++;
+		len--;
+	}
 
 	/* Make sure the var is defined for the end event */
 	for (i = 0; vars[i]; i++) {
 		p = strchr(vars[i], '=');
 		if (!p)
 			continue;
-		if (p - vars[i] != len)
-			continue;
-		if (!strncmp(var, vars[i], len))
-			return 0;
+
+		if (var_match(vars[i], var, p - vars[i], len)) {
+			i = asprintf(&ret, "%.*s", (int)(p - vars[i]), vars[i]);
+			if (i < 0)
+				return NULL;
+			return ret;
+		}
 	}
 	errno = ENODEV;
-	return -1;
+	return NULL;
 }
 
 static struct action *create_action(enum tracefs_synth_handler type,
@@ -1697,14 +1772,16 @@ static struct action *create_action(enum tracefs_synth_handler type,
 				    const char *var)
 {
 	struct action *action;
+	char *newvar = NULL;
 	int ret;
 
 	switch (type) {
 	case TRACEFS_SYNTH_HANDLE_MAX:
 	case TRACEFS_SYNTH_HANDLE_CHANGE:
-		ret = test_max_var(synth, var);
-		if (ret < 0)
+		newvar = test_max_var(synth, var);
+		if (!newvar)
 			return NULL;
+		var = newvar;
 		break;
 	default:
 		break;
@@ -1712,15 +1789,18 @@ static struct action *create_action(enum tracefs_synth_handler type,
 
 	action = calloc(1, sizeof(*action));
 	if (!action)
-		return NULL;
+		goto out;
 
 	if (var) {
 		ret = asprintf(&action->handle_field, "$%s", var);
-		if (!action->handle_field) {
+		if (ret < 0) {
 			free(action);
+			free(newvar);
 			return NULL;
 		}
 	}
+ out:
+	free(newvar);
 	return action;
 }
 
@@ -1820,8 +1900,6 @@ int tracefs_synth_save(struct tracefs_synth *synth,
 
 	action->type = ACTION_SAVE;
 	action->handler = type;
-	*synth->next_action = action;
-	synth->next_action = &action->next;
 
 	save = strdup(".save(");
 	if (!save)
@@ -2178,6 +2256,25 @@ tracefs_synth_get_start_hist(struct tracefs_synth *synth)
 	return hist;
 }
 
+/**
+ * tracefs_synth_set_instance - Set the ftrace instance of the synthetic events
+ * @synth: The tracefs_synth descriptor
+ * @instance: ftrace instance
+ *
+ * Set the ftrace instance, in which the synthetic event will be created. By default,
+ * the top instance is used. This API must be called before the call to tracefs_synth_create(),
+ * in order to use the new instance when creating the event.
+ *
+ * Returns 0 on success and -1 on error.
+ */
+int tracefs_synth_set_instance(struct tracefs_synth *synth, struct tracefs_instance *instance)
+{
+	if (!synth || synth->created)
+		return -1;
+	synth->instance = instance;
+	return 0;
+}
+
 /**
  * tracefs_synth_create - creates the synthetic event on the system
  * @synth: The tracefs_synth descriptor
@@ -2236,6 +2333,8 @@ int tracefs_synth_create(struct tracefs_synth *synth)
 	if (ret < 0)
 		goto remove_start_hist;
 
+	synth->created = true;
+
 	return 0;
 
  remove_start_hist:
@@ -2299,6 +2398,9 @@ int tracefs_synth_destroy(struct tracefs_synth *synth)
 
 	ret = tracefs_dynevent_destroy(synth->dyn_event, true);
 
+	if (!ret)
+		synth->created = false;
+
 	return ret ? -1 : 0;
 }
 
diff --git a/src/tracefs-instance.c b/src/tracefs-instance.c
index 57f5c7f..dd7decd 100644
--- a/src/tracefs-instance.c
+++ b/src/tracefs-instance.c
@@ -123,6 +123,8 @@ __hidden void trace_put_instance(struct tracefs_instance *instance)
 		close(instance->ftrace_marker_raw_fd);
 
 	free(instance->trace_dir);
+	free(instance->followers);
+	free(instance->missed_followers);
 	free(instance->name);
 	pthread_mutex_destroy(&instance->lock);
 	free(instance);
@@ -215,6 +217,7 @@ struct tracefs_instance *tracefs_instance_create(const char *name)
 	return inst;
 
 error:
+	tracefs_put_tracing_file(path);
 	tracefs_instance_free(inst);
 	return NULL;
 }
@@ -400,6 +403,18 @@ ssize_t tracefs_instance_get_buffer_size(struct tracefs_instance *instance, int
 	return size;
 }
 
+/**
+ * tracefs_instance_set_buffer_size - modify the ring buffer size
+ * @instance: The instance to modify (NULL for the top level)
+ * @size: The size in kilobytes to to set the size to
+ * @cpu: the CPU to set it to (-1 for all CPUs)
+ *
+ * Sets the size of the ring buffer per CPU buffers. If @cpu is negative,
+ * then it sets the ring buffer size for all the per CPU buffers, otherwise
+ * it only sets the per CPU buffer specified by @cpu.
+ *
+ * Returns 0 on success and -1 on error.
+ */
 int tracefs_instance_set_buffer_size(struct tracefs_instance *instance, size_t size, int cpu)
 {
 	char *path;
@@ -427,6 +442,43 @@ int tracefs_instance_set_buffer_size(struct tracefs_instance *instance, size_t s
 	return ret < 0 ? -1 : 0;
 }
 
+/**
+ * tracefs_instance_get_subbuf_size - return the sub-buffer size of the ring buffer
+ * @instance: The instance to get the buffer size from
+ *
+ * Returns the sub-buffer size in kilobytes.
+ * Returns -1 on error.
+ */
+ssize_t tracefs_instance_get_subbuf_size(struct tracefs_instance *instance)
+{
+	long long size;
+	int ret;
+
+	ret = tracefs_instance_file_read_number(instance, "buffer_subbuf_size_kb", &size);
+	if (ret < 0)
+		return ret;
+
+	return size;
+}
+
+/**
+ * tracefs_instance_set_buffer_size - modify the ring buffer sub-buffer size
+ * @instance: The instance to modify (NULL for the top level)
+ * @size: The size in kilobytes to to set the sub-buffer size to
+ *
+ * Sets the sub-buffer size in kilobytes for the given ring buffer.
+ *
+ * Returns 0 on success and -1 on error.
+ */
+int tracefs_instance_set_subbuf_size(struct tracefs_instance *instance, size_t size)
+{
+	int ret;
+
+	ret = tracefs_instance_file_write_number(instance, "buffer_subbuf_size_kb", size);
+
+	return ret < 0 ? -1 : 0;
+}
+
 /**
  * tracefs_instance_get_trace_dir - return the top trace directory, where the instance is confuigred
  * @instance: ftrace instance
@@ -491,6 +543,27 @@ int tracefs_instance_file_write(struct tracefs_instance *instance,
 	return instance_file_write(instance, file, str, O_WRONLY | O_TRUNC);
 }
 
+/**
+ * tracefs_instance_file_write_number - Write integer from a trace file.
+ * @instance: ftrace instance, can be NULL for the top instance
+ * @file: name of the file
+ * @res: The integer to write to @file
+ *
+ * Returns 0 if the write succeeds, -1 on error.
+ */
+int tracefs_instance_file_write_number(struct tracefs_instance *instance,
+				       const char *file, size_t val)
+{
+	char buf[64];
+	int ret;
+
+	snprintf(buf, 64, "%zd\n", val);
+
+	ret = tracefs_instance_file_write(instance, file, buf);
+
+	return ret > 1 ? 0 : -1;
+}
+
 /**
  * tracefs_instance_file_append - Append to a trace file of specific instance.
  * @instance: ftrace instance, can be NULL for the top instance.
@@ -1239,3 +1312,253 @@ char *tracefs_instance_get_affinity(struct tracefs_instance *instance)
 
 	return set;
 }
+
+static int clear_trigger(const char *file)
+{
+	char trigger[BUFSIZ];
+	char *save = NULL;
+	char *line;
+	char *buf;
+	int size;
+	int len;
+	int ret;
+
+	size = str_read_file(file, &buf, true);
+	if (size < 1)
+		return 0;
+
+	trigger[0] = '!';
+
+	for (line = strtok_r(buf, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
+		if (line[0] == '#')
+			continue;
+		len = strlen(line);
+		if (len > BUFSIZ - 2)
+			len = BUFSIZ - 2;
+		strncpy(trigger + 1, line, len);
+		trigger[len + 1] = '\0';
+		/* We don't want any filters or extra on the line */
+		strtok(trigger, " ");
+		write_file(file, trigger, O_WRONLY);
+	}
+
+	free(buf);
+
+	/*
+	 * Some triggers have an order in removing them.
+	 * They will not be removed if done in the wrong order.
+	 */
+	size = str_read_file(file, &buf, true);
+	if (size < 1)
+		return 0;
+
+	ret = 0;
+	for (line = strtok(buf, "\n"); line; line = strtok(NULL, "\n")) {
+		if (line[0] == '#')
+			continue;
+		ret = 1;
+		break;
+	}
+	free(buf);
+	return ret;
+}
+
+static void disable_func_stack_trace_instance(struct tracefs_instance *instance)
+{
+	char *content;
+	char *cond;
+	int size;
+
+	content = tracefs_instance_file_read(instance, "current_tracer", &size);
+	if (!content)
+		return;
+	cond = strstrip(content);
+	if (memcmp(cond, "function", size - (cond - content)) != 0)
+		goto out;
+
+	tracefs_option_disable(instance, TRACEFS_OPTION_FUNC_STACKTRACE);
+ out:
+	free(content);
+}
+
+static void reset_cpu_mask(struct tracefs_instance *instance)
+{
+	int cpus = sysconf(_SC_NPROCESSORS_CONF);
+	int fullwords = (cpus - 1) / 32;
+	int bits = (cpus - 1) % 32 + 1;
+	int len = (fullwords + 1) * 9;
+	char buf[len + 1];
+
+	buf[0] = '\0';
+	sprintf(buf, "%x", (unsigned int)((1ULL << bits) - 1));
+	while (fullwords-- > 0)
+		strcat(buf, ",ffffffff");
+
+	tracefs_instance_file_write(instance, "tracing_cpumask", buf);
+}
+
+static void clear_func_filter(struct tracefs_instance *instance, const char *file)
+{
+	char filter[BUFSIZ];
+	char *line;
+	char *buf;
+	char *p;
+	int len;
+
+	buf = tracefs_instance_file_read(instance, file, NULL);
+	if (!buf)
+		return;
+
+	/* Now remove filters */
+	filter[0] = '!';
+
+	/*
+	 * To delete a filter, we need to write a '!filter'
+	 * to the file for each filter.
+	 */
+	for (line = strtok(buf, "\n"); line; line = strtok(NULL, "\n")) {
+		if (line[0] == '#')
+			continue;
+		len = strlen(line);
+		if (len > BUFSIZ - 2)
+			len = BUFSIZ - 2;
+
+		strncpy(filter + 1, line, len);
+		filter[len + 1] = '\0';
+		/*
+		 * To remove "unlimited" filters, we must remove
+		 * the ":unlimited" from what we write.
+		 */
+		p = strstr(filter, ":unlimited");
+		if (p) {
+			*p = '\0';
+			len = p - filter;
+		}
+		/*
+		 * The write to this file expects white space
+		 * at the end :-p
+		 */
+		filter[len] = '\n';
+		filter[len+1] = '\0';
+		tracefs_instance_file_append(instance, file, filter);
+	}
+	free(buf);
+}
+
+static void clear_func_filters(struct tracefs_instance *instance)
+{
+	int i;
+	const char * const files[] = { "set_ftrace_filter",
+				       "set_ftrace_notrace",
+				       "set_graph_function",
+				       "set_graph_notrace",
+				       "stack_trace_filter",
+				       NULL };
+
+	for (i = 0; files[i]; i++)
+		clear_func_filter(instance, files[i]);
+}
+
+/**
+ * tracefs_instance_clear - clear the trace buffer
+ * @instance: The instance to clear the trace for.
+ *
+ * Returns 0 on succes, -1 on error
+ */
+int tracefs_instance_clear(struct tracefs_instance *instance)
+{
+	return tracefs_instance_file_clear(instance, "trace");
+}
+
+/**
+ * tracefs_instance_reset - Reset a ftrace instance to its default state
+ * @instance - a ftrace instance to be reseted
+ *
+ * The main logic and the helper functions are copied from
+ * trace-cmd/tracecmd/trace-record.c, trace_reset()
+ */
+void tracefs_instance_reset(struct tracefs_instance *instance)
+{
+	int has_trigger = -1;
+	char **systems;
+	struct stat st;
+	char **file_list = NULL;
+	int list_size = 0;
+	char **events;
+	char *file;
+	int i, j;
+	int ret;
+
+	tracefs_trace_off(instance);
+	disable_func_stack_trace_instance(instance);
+	tracefs_tracer_clear(instance);
+	tracefs_instance_file_write(instance, "events/enable", "0");
+	tracefs_instance_file_write(instance, "set_ftrace_pid", "");
+	tracefs_instance_file_write(instance, "max_graph_depth", "0");
+	tracefs_instance_file_clear(instance, "trace");
+
+	systems = tracefs_event_systems(NULL);
+	if (systems) {
+		for (i = 0; systems[i]; i++) {
+			events = tracefs_system_events(NULL, systems[i]);
+			if (!events)
+				continue;
+			for (j = 0; events[j]; j++) {
+				file = tracefs_event_get_file(instance, systems[i],
+							      events[j], "filter");
+				write_file(file, "0", O_WRONLY | O_TRUNC);
+				tracefs_put_tracing_file(file);
+
+				file = tracefs_event_get_file(instance, systems[i],
+							      events[j], "trigger");
+				if (has_trigger < 0) {
+					/* Check if the kernel is configured with triggers */
+					if (stat(file, &st) < 0)
+						has_trigger = 0;
+					else
+						has_trigger = 1;
+				}
+				if (has_trigger) {
+					ret = clear_trigger(file);
+					if (ret) {
+						char **list;
+						list = tracefs_list_add(file_list, file);
+						if (list)
+							file_list = list;
+					}
+				}
+				tracefs_put_tracing_file(file);
+			}
+			tracefs_list_free(events);
+		}
+		tracefs_list_free(systems);
+	}
+
+	while (file_list && list_size != tracefs_list_size(file_list)) {
+		char **list = file_list;
+
+		list_size = tracefs_list_size(file_list);
+		file_list = NULL;
+		for (i = 0; list[i]; i++) {
+			file = list[i];
+			ret = clear_trigger(file);
+			if (ret) {
+				char **tlist;
+				tlist = tracefs_list_add(file_list, list[i]);
+				if (tlist)
+					file_list = tlist;
+			}
+		}
+		tracefs_list_free(list);
+	}
+	tracefs_list_free(file_list);
+
+	tracefs_instance_file_write(instance, "synthetic_events", " ");
+	tracefs_instance_file_write(instance, "error_log", " ");
+	tracefs_instance_file_write(instance, "trace_clock", "local");
+	tracefs_instance_file_write(instance, "set_event_pid", "");
+	reset_cpu_mask(instance);
+	clear_func_filters(instance);
+	tracefs_instance_file_write(instance, "tracing_max_latency", "0");
+	tracefs_trace_on(instance);
+}
diff --git a/src/tracefs-kprobes.c b/src/tracefs-kprobes.c
index a8c0163..5c50b21 100644
--- a/src/tracefs-kprobes.c
+++ b/src/tracefs-kprobes.c
@@ -196,3 +196,33 @@ int tracefs_kretprobe_raw(const char *system, const char *event,
 {
 	return kprobe_raw(TRACEFS_DYNEVENT_KRETPROBE, system, event, addr, format);
 }
+
+/**
+ * tracefs_kprobe_destroy - Remove an individual kprobe or kretprobe
+ * @system: The system of the kprobe to remove (could be NULL)
+ * @event: The event of the kprobe or kretprobe to remove
+ * @addr: The address used to create the kprobe
+ * @format: The format used to create the kprobe
+ * @force: If true, try to disable the kprobe/kretprobe first
+ *
+ * This removes the kprobe or kretprobe that was created by
+ * tracefs_kprobe_raw() or tracefs_kretprobe_raw().
+ *
+ * Returns 0 on success and -1 otherwise.
+ */
+int tracefs_kprobe_destroy(const char *system, const char *event,
+			   const char *addr, const char *format, bool force)
+{
+	struct tracefs_dynevent *kp;
+	int ret;
+
+	kp = tracefs_kprobe_alloc(system, event, addr, format);
+	if (!kp)
+		return -1;
+
+	ret = tracefs_dynevent_destroy(kp, force);
+
+	tracefs_dynevent_free(kp);
+
+	return ret;
+}
diff --git a/src/tracefs-mmap.c b/src/tracefs-mmap.c
new file mode 100644
index 0000000..44d1597
--- /dev/null
+++ b/src/tracefs-mmap.c
@@ -0,0 +1,248 @@
+// SPDX-License-Identifier: LGPL-2.1
+/*
+ * Copyright (C) 2023 Google Inc, Steven Rostedt <rostedt@goodmis.org>
+ */
+#include <stdlib.h>
+#include <unistd.h>
+#include <sys/mman.h>
+#include <sys/ioctl.h>
+#include <asm/types.h>
+#include "tracefs-local.h"
+
+/**
+ * struct trace_buffer_meta - Ring-buffer Meta-page description
+ * @meta_page_size:	Size of this meta-page.
+ * @meta_struct_len:	Size of this structure.
+ * @subbuf_size:	Size of each sub-buffer.
+ * @nr_subbufs:		Number of subbfs in the ring-buffer, including the reader.
+ * @reader.lost_events:	Number of events lost at the time of the reader swap.
+ * @reader.id:		subbuf ID of the current reader. ID range [0 : @nr_subbufs - 1]
+ * @reader.read:	Number of bytes read on the reader subbuf.
+ * @flags:		Placeholder for now, 0 until new features are supported.
+ * @entries:		Number of entries in the ring-buffer.
+ * @overrun:		Number of entries lost in the ring-buffer.
+ * @read:		Number of entries that have been read.
+ * @Reserved1:		Internal use only.
+ * @Reserved2:		Internal use only.
+ */
+struct trace_buffer_meta {
+	__u32		meta_page_size;
+	__u32		meta_struct_len;
+
+	__u32		subbuf_size;
+	__u32		nr_subbufs;
+
+	struct {
+		__u64	lost_events;
+		__u32	id;
+		__u32	read;
+	} reader;
+
+	__u64	flags;
+
+	__u64	entries;
+	__u64	overrun;
+	__u64	read;
+
+	__u64	Reserved1;
+	__u64	Reserved2;
+};
+
+#define TRACE_MMAP_IOCTL_GET_READER		_IO('R', 0x20)
+
+struct trace_mmap {
+	struct trace_buffer_meta	*map;
+	struct kbuffer			*kbuf;
+	void				*data;
+	int				*data_pages;
+	int				fd;
+	int				last_idx;
+	int				last_read;
+	int				meta_len;
+	int				data_len;
+};
+
+/**
+ * trace_mmap - try to mmap the ring buffer
+ * @fd: The file descriptor to the trace_pipe_raw file
+ * @kbuf: The kbuffer to load the subbuffer to
+ *
+ * Will try to mmap the ring buffer if it is supported, and
+ * if not, will return NULL, otherwise it returns a descriptor
+ * to handle the mapping.
+ */
+__hidden void *trace_mmap(int fd, struct kbuffer *kbuf)
+{
+	struct trace_mmap *tmap;
+	int page_size;
+	void *meta;
+	void *data;
+
+	page_size = getpagesize();
+	meta = mmap(NULL, page_size, PROT_READ, MAP_SHARED, fd, 0);
+	if (meta == MAP_FAILED)
+		return NULL;
+
+	tmap = calloc(1, sizeof(*tmap));
+	if (!tmap) {
+		munmap(meta, page_size);
+		return NULL;
+	}
+
+	tmap->kbuf = kbuffer_dup(kbuf);
+	if (!tmap->kbuf) {
+		munmap(meta, page_size);
+		free(tmap);
+	}
+	kbuf = tmap->kbuf;
+
+	tmap->fd = fd;
+
+	tmap->map = meta;
+	tmap->meta_len = tmap->map->meta_page_size;
+
+	if (tmap->meta_len > page_size) {
+		munmap(meta, page_size);
+		meta = mmap(NULL, tmap->meta_len, PROT_READ, MAP_SHARED, fd, 0);
+		if (meta == MAP_FAILED) {
+			kbuffer_free(kbuf);
+			free(tmap);
+			return NULL;
+		}
+		tmap->map = meta;
+	}
+
+	tmap->data_pages = meta + tmap->meta_len;
+
+	tmap->data_len = tmap->map->subbuf_size * tmap->map->nr_subbufs;
+
+	tmap->data = mmap(NULL, tmap->data_len, PROT_READ, MAP_SHARED,
+			  fd, tmap->meta_len);
+	if (tmap->data == MAP_FAILED) {
+		munmap(meta, tmap->meta_len);
+		kbuffer_free(kbuf);
+		free(tmap);
+		return NULL;
+	}
+
+	tmap->last_idx = tmap->map->reader.id;
+
+	data = tmap->data + tmap->map->subbuf_size * tmap->last_idx;
+	kbuffer_load_subbuffer(kbuf, data);
+
+	/*
+	 * The page could have left over data on it that was already
+	 * consumed. Move the "read" forward in that case.
+	 */
+	if (tmap->map->reader.read) {
+		int size = kbuffer_start_of_data(kbuf) + tmap->map->reader.read;
+		char tmpbuf[size];
+		kbuffer_read_buffer(kbuf, tmpbuf, size);
+	}
+
+	return tmap;
+}
+
+__hidden void trace_unmap(void *mapping)
+{
+	struct trace_mmap *tmap = mapping;
+
+	if (!tmap)
+		return;
+
+	munmap(tmap->data, tmap->data_len);
+	munmap(tmap->map, tmap->meta_len);
+	kbuffer_free(tmap->kbuf);
+	free(tmap);
+}
+
+static int get_reader(struct trace_mmap *tmap)
+{
+	return ioctl(tmap->fd, TRACE_MMAP_IOCTL_GET_READER);
+}
+
+__hidden int trace_mmap_load_subbuf(void *mapping, struct kbuffer *kbuf)
+{
+	struct trace_mmap *tmap = mapping;
+	void *data;
+	int id;
+
+	if (!tmap)
+		return -1;
+
+	id = tmap->map->reader.id;
+	data = tmap->data + tmap->map->subbuf_size * id;
+
+	/*
+	 * If kbuf doesn't point to the current sub-buffer
+	 * just load it and return.
+	 */
+	if (data != kbuffer_subbuffer(kbuf)) {
+		kbuffer_load_subbuffer(kbuf, data);
+		/* Move the read pointer forward if need be */
+		if (kbuffer_curr_index(tmap->kbuf)) {
+			int size = kbuffer_curr_offset(tmap->kbuf);
+			char tmpbuf[size];
+			kbuffer_read_buffer(kbuf, tmpbuf, size);
+		}
+		return 1;
+	}
+
+	/*
+	 * Perhaps the reader page had a write that added
+	 * more data.
+	 */
+	kbuffer_refresh(kbuf);
+
+	/* Are there still events to read? */
+	if (kbuffer_curr_size(kbuf)) {
+		/* If current is greater than what was read, refresh */
+		if (kbuffer_curr_offset(kbuf) + kbuffer_curr_size(kbuf) >
+		    tmap->map->reader.read) {
+			if (get_reader(tmap) < 0)
+				return -1;
+		}
+		return 1;
+	}
+
+	/* See if a new page is ready? */
+	if (get_reader(tmap) < 0)
+		return -1;
+	id = tmap->map->reader.id;
+	data = tmap->data + tmap->map->subbuf_size * id;
+
+	/*
+	 * If the sub-buffer hasn't changed, then there's no more
+	 * events to read.
+	 */
+	if (data == kbuffer_subbuffer(kbuf))
+		return 0;
+
+	kbuffer_load_subbuffer(kbuf, data);
+	return 1;
+}
+
+__hidden int trace_mmap_read(void *mapping, void *buffer)
+{
+	struct trace_mmap *tmap = mapping;
+	struct kbuffer *kbuf;
+	int ret;
+
+	if (!tmap)
+		return -1;
+
+	kbuf = tmap->kbuf;
+
+	ret = trace_mmap_load_subbuf(mapping, kbuf);
+	/* Return for error or no more events */
+	if (ret <= 0)
+		return ret;
+
+	/* Update the buffer */
+	ret = kbuffer_read_buffer(kbuf, buffer, tmap->map->subbuf_size);
+	if (ret <= 0)
+		return ret;
+
+	/* This needs to include the size of the meta data too */
+	return ret + kbuffer_start_of_data(kbuf);
+}
diff --git a/src/tracefs-perf.c b/src/tracefs-perf.c
new file mode 100644
index 0000000..62c1508
--- /dev/null
+++ b/src/tracefs-perf.c
@@ -0,0 +1,94 @@
+#include <unistd.h>
+#include <sys/syscall.h>
+#include <sys/mman.h>
+#include <signal.h>
+#include <linux/perf_event.h>
+
+#include <tracefs.h>
+
+static void perf_init_pe(struct perf_event_attr *pe)
+{
+	memset(pe, 0, sizeof(struct perf_event_attr));
+	pe->type = PERF_TYPE_SOFTWARE;
+	pe->sample_type = PERF_SAMPLE_CPU;
+	pe->size = sizeof(struct perf_event_attr);
+	pe->config = PERF_COUNT_HW_CPU_CYCLES;
+	pe->disabled = 1;
+	pe->exclude_kernel = 1;
+	pe->freq = 1;
+	pe->sample_freq = 1000;
+	pe->inherit = 1;
+	pe->mmap = 1;
+	pe->comm = 1;
+	pe->task = 1;
+	pe->precise_ip = 1;
+	pe->sample_id_all = 1;
+	pe->read_format = PERF_FORMAT_ID |
+			PERF_FORMAT_TOTAL_TIME_ENABLED|
+			PERF_FORMAT_TOTAL_TIME_RUNNING;
+
+}
+
+static long perf_event_open(struct perf_event_attr *event, pid_t pid,
+			    int cpu, int group_fd, unsigned long flags)
+{
+	return syscall(__NR_perf_event_open, event, pid, cpu, group_fd, flags);
+}
+
+#define MAP_SIZE (9 * getpagesize())
+
+static struct perf_event_mmap_page *perf_mmap(int fd)
+{
+	struct perf_event_mmap_page *perf_mmap;
+
+	/* associate a buffer with the file */
+	perf_mmap = mmap(NULL, MAP_SIZE,
+			PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
+	if (perf_mmap == MAP_FAILED)
+		return NULL;
+
+	return perf_mmap;
+}
+
+static int perf_read_maps(int cpu, int *shift, int *mult, long long *offset)
+{
+	struct perf_event_attr perf_attr;
+	struct perf_event_mmap_page *mpage;
+	int fd;
+
+	/* We succeed if theres' nothing to do! */
+	if (!shift && !mult && !offset)
+		return 0;
+
+	perf_init_pe(&perf_attr);
+	fd = perf_event_open(&perf_attr, getpid(), cpu, -1, 0);
+	if (fd < 0)
+		return -1;
+
+	mpage = perf_mmap(fd);
+	if (!mpage) {
+		close(fd);
+		return -1;
+	}
+
+	if (shift)
+		*shift = mpage->time_shift;
+	if (mult)
+		*mult = mpage->time_mult;
+	if (offset)
+		*offset = mpage->time_offset;
+	munmap(mpage, MAP_SIZE);
+	return 0;
+}
+
+/**
+ * tracefs_time_conversion - Find how the kernel converts the raw counters
+ * @cpu: The CPU to check for
+ * @shift: If non-NULL it will be set to the shift value
+ * @mult: If non-NULL it will be set to the multiplier value
+ * @offset: If non-NULL it will be set to the offset
+ */
+int tracefs_time_conversion(int cpu, int *shift, int *mult, long long *offset)
+{
+	return perf_read_maps(cpu, shift, mult, offset);
+}
diff --git a/src/tracefs-record.c b/src/tracefs-record.c
index b078c86..932e8b4 100644
--- a/src/tracefs-record.c
+++ b/src/tracefs-record.c
@@ -34,6 +34,9 @@ struct tracefs_cpu {
 	int		subbuf_size;
 	int		buffered;
 	int		splice_read_flags;
+	struct kbuffer	*kbuf;
+	void		*buffer;
+	void		*mapping;
 };
 
 /**
@@ -90,34 +93,22 @@ tracefs_cpu_alloc_fd(int fd, int subbuf_size, bool nonblock)
 	return NULL;
 }
 
-/**
- * tracefs_cpu_open - open an instance raw trace file
- * @instance: the instance (NULL for toplevel) of the cpu raw file to open
- * @cpu: The CPU that the raw trace file is associated with
- * @nonblock: If true, the file will be opened in O_NONBLOCK mode
- *
- * Return a descriptor that can read the tracefs trace_pipe_raw file
- * for a give @cpu in a given @instance.
- *
- * Returns NULL on error.
- */
-struct tracefs_cpu *
-tracefs_cpu_open(struct tracefs_instance *instance, int cpu, bool nonblock)
+static struct tracefs_cpu *cpu_open(struct tracefs_instance *instance,
+				    const char *path_fmt, int cpu, bool nonblock)
 {
 	struct tracefs_cpu *tcpu;
 	struct tep_handle *tep;
+	struct kbuffer *kbuf;
 	char path[128];
-	char *buf;
 	int mode = O_RDONLY;
 	int subbuf_size;
-	int len;
 	int ret;
 	int fd;
 
 	if (nonblock)
 		mode |= O_NONBLOCK;
 
-	sprintf(path, "per_cpu/cpu%d/trace_pipe_raw", cpu);
+	sprintf(path, path_fmt, cpu);
 
 	fd = tracefs_instance_file_open(instance, path, mode);
 	if (fd < 0)
@@ -128,16 +119,16 @@ tracefs_cpu_open(struct tracefs_instance *instance, int cpu, bool nonblock)
 		goto fail;
 
 	/* Get the size of the page */
-	buf = tracefs_instance_file_read(NULL, "events/header_page", &len);
-	if (!buf)
-		goto fail;
-
-	ret = tep_parse_header_page(tep, buf, len, sizeof(long));
-	free(buf);
+	ret = tracefs_load_headers(NULL, tep);
 	if (ret < 0)
 		goto fail;
 
 	subbuf_size = tep_get_sub_buffer_size(tep);
+
+	kbuf = tep_kbuffer(tep);
+	if (!kbuf)
+		goto fail;
+
 	tep_free(tep);
 	tep = NULL;
 
@@ -145,6 +136,8 @@ tracefs_cpu_open(struct tracefs_instance *instance, int cpu, bool nonblock)
 	if (!tcpu)
 		goto fail;
 
+	tcpu->kbuf = kbuf;
+
 	return tcpu;
  fail:
 	tep_free(tep);
@@ -152,6 +145,116 @@ tracefs_cpu_open(struct tracefs_instance *instance, int cpu, bool nonblock)
 	return NULL;
 }
 
+/**
+ * tracefs_cpu_open - open an instance raw trace file
+ * @instance: the instance (NULL for toplevel) of the cpu raw file to open
+ * @cpu: The CPU that the raw trace file is associated with
+ * @nonblock: If true, the file will be opened in O_NONBLOCK mode
+ *
+ * Return a descriptor that can read the tracefs trace_pipe_raw file
+ * for a give @cpu in a given @instance.
+ *
+ * Returns NULL on error.
+ */
+struct tracefs_cpu *
+tracefs_cpu_open(struct tracefs_instance *instance, int cpu, bool nonblock)
+{
+	return cpu_open(instance, "per_cpu/cpu%d/trace_pipe_raw", cpu, nonblock);
+}
+
+/**
+ * tracefs_cpu_snapshot_open - open an instance snapshot raw trace file
+ * @instance: the instance (NULL for toplevel) of the cpu raw file to open
+ * @cpu: The CPU that the raw trace file is associated with
+ * @nonblock: If true, the file will be opened in O_NONBLOCK mode
+ *
+ * Return a descriptor that can read the tracefs snapshot_raw file
+ * for a give @cpu in a given @instance.
+ *
+ * In nonblock mode, it will block if the snapshot is empty and wake up
+ * when there's a new snapshot.
+ *
+ * Returns NULL on error.
+ */
+struct tracefs_cpu *
+tracefs_cpu_snapshot_open(struct tracefs_instance *instance, int cpu, bool nonblock)
+{
+	return cpu_open(instance, "per_cpu/cpu%d/snapshot_raw", cpu, nonblock);
+}
+
+/**
+ * tracefs_snapshot_snap - takes a snapshot (allocates if necessary)
+ * @instance: The instance to take a snapshot on
+ *
+ * Takes a snapshot of the current ring buffer.
+ *
+ * Returns 0 on success, -1 on error.
+ */
+int tracefs_snapshot_snap(struct tracefs_instance *instance)
+{
+	int ret;
+
+	ret = tracefs_instance_file_write(instance, "snapshot", "1");
+	return ret < 0 ? -1 : 0;
+}
+
+/**
+ * tracefs_snapshot_clear - clears the snapshot
+ * @instance: The instance to clear the snapshot
+ *
+ * Clears the snapshot buffer for the @instance.
+ *
+ * Returns 0 on success, -1 on error.
+ */
+int tracefs_snapshot_clear(struct tracefs_instance *instance)
+{
+	int ret;
+
+	ret = tracefs_instance_file_write(instance, "snapshot", "2");
+	return ret < 0 ? -1 : 0;
+}
+
+/**
+ * tracefs_snapshot_free - frees the snapshot
+ * @instance: The instance to free the snapshot
+ *
+ * Frees the snapshot for the given @instance.
+ *
+ * Returns 0 on success, -1 on error.
+ */
+int tracefs_snapshot_free(struct tracefs_instance *instance)
+{
+	int ret;
+
+	ret = tracefs_instance_file_write(instance, "snapshot", "0");
+	return ret < 0 ? -1 : 0;
+}
+
+/**
+ * tracefs_cpu_open_mapped - open an instance raw trace file and map it
+ * @instance: the instance (NULL for toplevel) of the cpu raw file to open
+ * @cpu: The CPU that the raw trace file is associated with
+ * @nonblock: If true, the file will be opened in O_NONBLOCK mode
+ *
+ * Return a descriptor that can read the tracefs trace_pipe_raw file
+ * for a give @cpu in a given @instance.
+ *
+ * Returns NULL on error.
+ */
+struct tracefs_cpu *
+tracefs_cpu_open_mapped(struct tracefs_instance *instance, int cpu, bool nonblock)
+{
+	struct tracefs_cpu *tcpu;
+
+	tcpu = tracefs_cpu_open(instance, cpu, nonblock);
+	if (!tcpu)
+		return NULL;
+
+	tracefs_cpu_map(tcpu);
+
+	return tcpu;
+}
+
 static void close_fd(int fd)
 {
 	if (fd < 0)
@@ -173,6 +276,8 @@ void tracefs_cpu_free_fd(struct tracefs_cpu *tcpu)
 	close_fd(tcpu->splice_pipe[0]);
 	close_fd(tcpu->splice_pipe[1]);
 
+	trace_unmap(tcpu->mapping);
+	kbuffer_free(tcpu->kbuf);
 	free(tcpu);
 }
 
@@ -207,6 +312,47 @@ int tracefs_cpu_read_size(struct tracefs_cpu *tcpu)
 	return tcpu->subbuf_size;
 }
 
+bool tracefs_cpu_is_mapped(struct tracefs_cpu *tcpu)
+{
+	return tcpu->mapping != NULL;
+}
+
+/**
+ * tracefs_mapped_is_supported - find out if memory mapping is supported
+ *
+ * Return true if the ring buffer can be memory mapped, or false on
+ * error or it cannot be.
+ */
+bool tracefs_mapped_is_supported(void)
+{
+	struct tracefs_cpu *tcpu;
+	bool ret;
+
+	tcpu = tracefs_cpu_open_mapped(NULL, 0, false);
+	if (!tcpu)
+		return false;
+	ret = tracefs_cpu_is_mapped(tcpu);
+	tracefs_cpu_close(tcpu);
+	return ret;
+}
+
+int tracefs_cpu_map(struct tracefs_cpu *tcpu)
+{
+	if (tcpu->mapping)
+		return 0;
+
+	tcpu->mapping = trace_mmap(tcpu->fd, tcpu->kbuf);
+	return tcpu->mapping ? 0 : -1;
+}
+
+void tracefs_cpu_unmap(struct tracefs_cpu *tcpu)
+{
+	if (!tcpu->mapping)
+		return;
+
+	trace_unmap(tcpu->mapping);
+}
+
 static void set_nonblock(struct tracefs_cpu *tcpu)
 {
 	long flags;
@@ -275,6 +421,25 @@ static int wait_on_input(struct tracefs_cpu *tcpu, bool nonblock)
 	return FD_ISSET(tcpu->fd, &rfds);
 }
 
+/* If nonblock is set, set errno to EAGAIN on no data */
+static int mmap_read(struct tracefs_cpu *tcpu, void *buffer, bool nonblock)
+{
+	void *mapping = tcpu->mapping;
+	int ret;
+
+	ret = trace_mmap_read(mapping, buffer);
+	if (ret <= 0) {
+		if (!ret && nonblock)
+			errno = EAGAIN;
+		return ret;
+	}
+
+	/* Write full sub-buffer size, but zero out empty space */
+	if (ret < tcpu->subbuf_size)
+		memset(buffer + ret, 0, tcpu->subbuf_size - ret);
+	return tcpu->subbuf_size;
+}
+
 /**
  * tracefs_cpu_read - read from the raw trace file
  * @tcpu: The descriptor representing the raw trace file
@@ -305,6 +470,9 @@ int tracefs_cpu_read(struct tracefs_cpu *tcpu, void *buffer, bool nonblock)
 	if (ret <= 0)
 		return ret;
 
+	if (tcpu->mapping)
+		return mmap_read(tcpu, buffer, nonblock);
+
 	ret = read(tcpu->fd, buffer, tcpu->subbuf_size);
 
 	/* It's OK if there's no data to read */
@@ -317,8 +485,62 @@ int tracefs_cpu_read(struct tracefs_cpu *tcpu, void *buffer, bool nonblock)
 	return ret;
 }
 
+static bool get_buffer(struct tracefs_cpu *tcpu)
+{
+	if (!tcpu->buffer) {
+		tcpu->buffer = malloc(tcpu->subbuf_size);
+		if (!tcpu->buffer)
+			return false;
+	}
+	return true;
+}
+
+/**
+ * tracefs_cpu_read_buf - read from the raw trace file and return kbuffer
+ * @tcpu: The descriptor representing the raw trace file
+ * @nonblock: Hint to not block on the read if there's no data.
+ *
+ * Reads the trace_pipe_raw files associated to @tcpu and returns a kbuffer
+ * associated with the read that can be used to parse events.
+ *
+ * If @nonblock is set, and there's no data available, it will return
+ * immediately. Otherwise depending on how @tcpu was opened, it will
+ * block. If @tcpu was opened with nonblock set, then this @nonblock
+ * will make no difference.
+ *
+ * Returns a kbuffer associated to the next sub-buffer or NULL on error
+ * or no data to read with nonblock set (EAGAIN will be set).
+ *
+ * The kbuffer returned should not be freed!
+ */
+struct kbuffer *tracefs_cpu_read_buf(struct tracefs_cpu *tcpu, bool nonblock)
+{
+	int ret;
+
+	/* If mapping is enabled, just use it directly */
+	if (tcpu->mapping) {
+		ret = wait_on_input(tcpu, nonblock);
+		if (ret <= 0)
+			return NULL;
+
+		ret = trace_mmap_load_subbuf(tcpu->mapping, tcpu->kbuf);
+		return ret > 0 ? tcpu->kbuf : NULL;
+	}
+
+	if (!get_buffer(tcpu))
+		return NULL;
+
+	ret = tracefs_cpu_read(tcpu, tcpu->buffer, nonblock);
+	if (ret <= 0)
+		return NULL;
+
+	kbuffer_load_subbuffer(tcpu->kbuf, tcpu->buffer);
+	return tcpu->kbuf;
+}
+
 static int init_splice(struct tracefs_cpu *tcpu)
 {
+	char *buf;
 	int ret;
 
 	if (tcpu->splice_pipe[0] >= 0)
@@ -328,6 +550,12 @@ static int init_splice(struct tracefs_cpu *tcpu)
 	if (ret < 0)
 		return ret;
 
+	if (str_read_file("/proc/sys/fs/pipe-max-size", &buf, false)) {
+		int size = atoi(buf);
+		fcntl(tcpu->splice_pipe[0], F_SETPIPE_SZ, &size);
+		free(buf);
+	}
+
 	ret = fcntl(tcpu->splice_pipe[0], F_GETPIPE_SZ, &tcpu->pipe_size);
 	/*
 	 * F_GETPIPE_SZ was introduced in 2.6.35, ftrace was introduced
@@ -381,6 +609,9 @@ int tracefs_cpu_buffered_read(struct tracefs_cpu *tcpu, void *buffer, bool nonbl
 	if (ret <= 0)
 		return ret;
 
+	if (tcpu->mapping)
+		return mmap_read(tcpu, buffer, nonblock);
+
 	if (tcpu->flags & TC_NONBLOCK)
 		mode |= SPLICE_F_NONBLOCK;
 
@@ -402,6 +633,52 @@ int tracefs_cpu_buffered_read(struct tracefs_cpu *tcpu, void *buffer, bool nonbl
 	return ret;
 }
 
+/**
+ * tracefs_cpu_buffered_read_buf - Read the raw trace data buffering through a pipe
+ * @tcpu: The descriptor representing the raw trace file
+ * @nonblock: Hint to not block on the read if there's no data.
+ *
+ * This is basically the same as tracefs_cpu_read() except that it uses
+ * a pipe through splice to buffer reads. This will batch reads keeping
+ * the reading from the ring buffer less intrusive to the system, as
+ * just reading all the time can cause quite a disturbance.
+ *
+ * Note, one difference between this and tracefs_cpu_read() is that it
+ * will read only in sub buffer pages. If the ring buffer has not filled
+ * a page, then it will not return anything, even with @nonblock set.
+ * Calls to tracefs_cpu_flush() should be done to read the rest of
+ * the file at the end of the trace.
+ *
+ * Returns a kbuffer associated to the next sub-buffer or NULL on error
+ * or no data to read with nonblock set (EAGAIN will be set).
+ *
+ * The kbuffer returned should not be freed!
+ */
+struct kbuffer *tracefs_cpu_buffered_read_buf(struct tracefs_cpu *tcpu, bool nonblock)
+{
+	int ret;
+
+	/* If mapping is enabled, just use it directly */
+	if (tcpu->mapping) {
+		ret = wait_on_input(tcpu, nonblock);
+		if (ret <= 0)
+			return NULL;
+
+		ret = trace_mmap_load_subbuf(tcpu->mapping, tcpu->kbuf);
+		return ret > 0 ? tcpu->kbuf : NULL;
+	}
+
+	if (!get_buffer(tcpu))
+		return NULL;
+
+	ret = tracefs_cpu_buffered_read(tcpu, tcpu->buffer, nonblock);
+	if (ret <= 0)
+		return NULL;
+
+	kbuffer_load_subbuffer(tcpu->kbuf, tcpu->buffer);
+	return tcpu->kbuf;
+}
+
 /**
  * tracefs_cpu_stop - Stop a blocked read of the raw tracing file
  * @tcpu: The descriptor representing the raw trace file
@@ -464,6 +741,9 @@ int tracefs_cpu_flush(struct tracefs_cpu *tcpu, void *buffer)
 	if (tcpu->buffered < 0)
 		tcpu->buffered = 0;
 
+	if (tcpu->mapping)
+		return mmap_read(tcpu, buffer, false);
+
 	if (tcpu->buffered) {
 		ret = read(tcpu->splice_pipe[0], buffer, tcpu->subbuf_size);
 		if (ret > 0)
@@ -485,6 +765,39 @@ int tracefs_cpu_flush(struct tracefs_cpu *tcpu, void *buffer)
 	return ret;
 }
 
+/**
+ * tracefs_cpu_flush_buf - Finish out and read the rest of the raw tracing file
+ * @tcpu: The descriptor representing the raw trace file
+ *
+ * Reads the trace_pipe_raw file associated by the @tcpu and puts it
+ * into @buffer, which must be the size of the sub buffer which is retrieved.
+ * by tracefs_cpu_read_size(). This should be called at the end of tracing
+ * to get the rest of the data.
+ *
+ * This will set the file descriptor for reading to non-blocking mode.
+ */
+struct kbuffer *tracefs_cpu_flush_buf(struct tracefs_cpu *tcpu)
+{
+	int ret;
+
+	if (!get_buffer(tcpu))
+		return NULL;
+
+	if (tcpu->mapping) {
+		/* Make sure that reading is now non blocking */
+		set_nonblock(tcpu);
+		ret = trace_mmap_load_subbuf(tcpu->mapping, tcpu->kbuf);
+		return ret > 0 ? tcpu->kbuf : NULL;
+	}
+
+	ret = tracefs_cpu_flush(tcpu, tcpu->buffer);
+	if (ret <= 0)
+		return NULL;
+
+	kbuffer_load_subbuffer(tcpu->kbuf, tcpu->buffer);
+	return tcpu->kbuf;
+}
+
 /**
  * tracefs_cpu_flush_write - Finish out and read the rest of the raw tracing file
  * @tcpu: The descriptor representing the raw trace file
@@ -533,6 +846,20 @@ int tracefs_cpu_write(struct tracefs_cpu *tcpu, int wfd, bool nonblock)
 	int tot;
 	int ret;
 
+	if (tcpu->mapping) {
+		int r = tracefs_cpu_read(tcpu, buffer, nonblock);
+		if (r < 0)
+			return r;
+		do {
+			ret = write(wfd, buffer, r);
+			if (ret < 0)
+				return ret;
+			r -= ret;
+			tot_write += ret;
+		} while (r > 0);
+		return tot_write;
+	}
+
 	ret = wait_on_input(tcpu, nonblock);
 	if (ret <= 0)
 		return ret;
@@ -598,6 +925,9 @@ int tracefs_cpu_pipe(struct tracefs_cpu *tcpu, int wfd, bool nonblock)
 	int mode = SPLICE_F_MOVE;
 	int ret;
 
+	if (tcpu->mapping)
+		return tracefs_cpu_write(tcpu, wfd, nonblock);
+
 	ret = wait_on_input(tcpu, nonblock);
 	if (ret <= 0)
 		return ret;
diff --git a/src/tracefs-sqlhist.c b/src/tracefs-sqlhist.c
index 3f571b7..08bd0fa 100644
--- a/src/tracefs-sqlhist.c
+++ b/src/tracefs-sqlhist.c
@@ -39,6 +39,13 @@ enum field_type {
 #define for_each_field(expr, field, table) \
 	for (expr = (table)->fields; expr; expr = (field)->next)
 
+#define TIMESTAMP_COMPARE "TIMESTAMP_DELTA"
+#define TIMESTAMP_USECS_COMPARE "TIMESTAMP_DELTA_USECS"
+#define EVENT_START	"__START_EVENT__"
+#define EVENT_END	"__END_EVENT__"
+#define TIMESTAMP_NSECS "TIMESTAMP"
+#define TIMESTAMP_USECS "TIMESTAMP_USECS"
+
 struct field {
 	struct expr		*next;	/* private link list */
 	const char		*system;
@@ -114,7 +121,7 @@ __hidden int my_yyinput(void *extra, char *buf, int max)
 	struct sqlhist_bison *sb = extra;
 
 	if (!sb || !sb->buffer)
-		return -1;
+		return 0;
 
 	if (sb->buffer_idx + max > sb->buffer_size)
 		max = sb->buffer_size - sb->buffer_idx;
@@ -374,6 +381,44 @@ __hidden void *add_field(struct sqlhist_bison *sb,
 	struct sql_table *table = sb->table;
 	struct expr *expr;
 	struct field *field;
+	bool nsecs;
+
+	/* Check if this is a TIMESTAMP compare */
+	if ((nsecs = (strcmp(field_name, TIMESTAMP_COMPARE) == 0)) ||
+	    strcmp(field_name, TIMESTAMP_USECS_COMPARE) == 0) {
+		const char *field_nameA;
+		const char *field_nameB;
+		struct expr *exprA;
+		struct expr *exprB;
+		struct field *fieldA;
+		struct field *fieldB;
+
+		if (nsecs) {
+			field_nameA = EVENT_END "." TIMESTAMP_NSECS;
+			field_nameB = EVENT_START "." TIMESTAMP_NSECS;
+		} else {
+			field_nameA = EVENT_END "." TIMESTAMP_USECS;
+			field_nameB = EVENT_START "." TIMESTAMP_USECS;
+		}
+
+		exprA = find_field(sb, field_nameA, NULL);
+		if (!exprA) {
+			create_field(fieldA, &exprA);
+			fieldA->next = table->fields;
+			table->fields = exprA;
+			fieldA->raw = field_nameA;
+		}
+
+		exprB = find_field(sb, field_nameB, NULL);
+		if (!exprB) {
+			create_field(fieldB, &exprB);
+			fieldB->next = table->fields;
+			table->fields = exprB;
+			fieldB->raw = field_nameB;
+		}
+
+		return add_compare(sb, exprA, exprB, COMPARE_SUB);
+	}
 
 	expr = find_field(sb, field_name, label);
 	if (expr)
@@ -566,7 +611,8 @@ static int test_field_exists(struct tep_handle *tep,
 		return -1;
 
 	if (!strcmp(field_name, TRACEFS_TIMESTAMP) ||
-	    !strcmp(field->field, TRACEFS_TIMESTAMP_USECS))
+	    !strcmp(field->field, TRACEFS_TIMESTAMP_USECS) ||
+	    !strcmp(field->field, TRACEFS_STACKTRACE))
 		tfield = (void *)1L;
 	else
 		tfield = tep_find_any_field(field->event, field_name);
@@ -596,17 +642,25 @@ static int update_vars(struct tep_handle *tep,
 	enum field_type ftype = FIELD_NONE;
 	struct tep_event *event;
 	struct field *field;
+	const char *extra_label = NULL;
 	const char *label;
 	const char *raw = event_field->raw;
 	const char *event_name;
 	const char *system;
 	const char *p;
 	int label_len = 0, event_len, system_len;
+	int extra_label_len = 0;
 
-	if (expr == table->to)
+	if (expr == table->to) {
 		ftype = FIELD_TO;
-	else if (expr == table->from)
+		extra_label = EVENT_END;
+	} else if (expr == table->from) {
 		ftype = FIELD_FROM;
+		extra_label = EVENT_START;
+	}
+
+	if (extra_label)
+		extra_label_len = strlen(extra_label);
 
 	p = strchr(raw, '.');
 	if (p) {
@@ -672,6 +726,13 @@ static int update_vars(struct tep_handle *tep,
 			goto found;
 		}
 
+		len = extra_label_len;
+		if (extra_label && !strncmp(raw, extra_label, len) &&
+		    raw[len] == '.') {
+			/* Label matches and takes precedence */
+			goto found;
+		}
+
 		if (!strncmp(raw, system, system_len) &&
 		    raw[system_len] == '.') {
 			raw += system_len + 1;
@@ -695,6 +756,8 @@ static int update_vars(struct tep_handle *tep,
 			field->field = store_str(sb, TRACEFS_TIMESTAMP);
 		if (!strcmp(field->field, "TIMESTAMP_USECS"))
 			field->field = store_str(sb, TRACEFS_TIMESTAMP_USECS);
+		if (!strcmp(field->field, "STACKTRACE"))
+			field->field = store_str(sb, TRACEFS_STACKTRACE);
 		if (test_field_exists(tep, sb, expr))
 			return -1;
 	}
@@ -747,9 +810,9 @@ static int update_fields(struct tep_handle *tep,
 			if (!p)
 				return -1;
 			field_name = store_str(sb, p);
+			free((char *)p);
 			if (!field_name)
 				return -1;
-			free((char *)p);
 		}
 
 		tfield = tep_find_any_field(event, field_name);
@@ -1046,7 +1109,7 @@ static int build_filter(struct tep_handle *tep, struct sqlhist_bison *sb,
 			     const char *val);
 	struct filter *filter = &expr->filter;
 	enum tracefs_compare cmp;
-	const char *val;
+	const char *val = NULL;
 	int and_or = TRACEFS_FILTER_AND;
 	char num[64];
 	int ret;
diff --git a/src/tracefs-stats.c b/src/tracefs-stats.c
new file mode 100644
index 0000000..d43235b
--- /dev/null
+++ b/src/tracefs-stats.c
@@ -0,0 +1,162 @@
+// SPDX-License-Identifier: LGPL-2.1
+/*
+ * Copyright (C) 2023 Google LLC, Steven Rostedt <rostedt@goodmis.org>
+ */
+#include <stdlib.h>
+#include <ctype.h>
+#include "tracefs.h"
+#include "tracefs-local.h"
+
+static long long convert_ts(char *value)
+{
+	long long ts;
+	char *saveptr;
+	char *secs;
+	char *usecs;
+
+	secs = strtok_r(value, ".", &saveptr);
+	if (!secs)
+		return -1LL;
+
+	ts = strtoll(secs, NULL, 0);
+
+	usecs = strtok_r(NULL, ".", &saveptr);
+	if (!usecs)
+		return ts;
+
+	/* Could be in nanoseconds */
+	if (strlen(usecs) > 6)
+		ts *= 1000000000LL;
+	else
+		ts *= 1000000LL;
+
+	ts += strtoull(usecs, NULL, 0);
+
+	return ts;
+}
+
+struct tracefs_buffer_stat *
+tracefs_instance_get_stat(struct tracefs_instance *instance, int cpu)
+{
+	struct tracefs_buffer_stat *tstat;
+	char *saveptr;
+	char *value;
+	char *field;
+	char *path;
+	char *line;
+	char *next;
+	char *buf;
+	int len;
+	int ret;
+
+	ret = asprintf(&path, "per_cpu/cpu%d/stats", cpu);
+	if (ret < 0)
+		return NULL;
+
+	buf = tracefs_instance_file_read(instance, path, &len);
+	free(path);
+
+	if (!buf)
+		return NULL;
+
+	tstat = malloc(sizeof(*tstat));
+	if (!tstat) {
+		free(buf);
+		return NULL;
+	}
+
+	/* Set everything to -1 */
+	memset(tstat, -1, sizeof(*tstat));
+
+	next = buf;
+	while ((line = strtok_r(next, "\n", &saveptr))) {
+		char *save2;
+
+		next = NULL;
+
+		field = strtok_r(line, ":", &save2);
+		if (!field)
+			break;
+
+		value = strtok_r(NULL, ":", &save2);
+		if (!value)
+			break;
+
+		while (isspace(*value))
+			value++;
+
+		if (strcmp(field, "entries") == 0) {
+			tstat->entries = strtoull(value, NULL, 0);
+
+		} else if (strcmp(field, "overrun") == 0) {
+			tstat->overrun = strtoull(value, NULL, 0);
+
+		} else if (strcmp(field, "commit overrun") == 0) {
+			tstat->commit_overrun = strtoull(value, NULL, 0);
+
+		} else if (strcmp(field, "bytes") == 0) {
+			tstat->bytes = strtoull(value, NULL, 0);
+
+		} else if (strcmp(field, "oldest event ts") == 0) {
+			tstat->oldest_ts = convert_ts(value);
+
+		} else if (strcmp(field, "now ts") == 0) {
+			tstat->now_ts = convert_ts(value);
+
+		} else if (strcmp(field, "dropped events") == 0) {
+			tstat->dropped_events = strtoull(value, NULL, 0);
+
+		} else if (strcmp(field, "read events") == 0) {
+			tstat->read_events = strtoull(value, NULL, 0);
+		}
+	}
+	free(buf);
+
+	return tstat;
+}
+
+void tracefs_instance_put_stat(struct tracefs_buffer_stat *tstat)
+{
+	free(tstat);
+}
+
+ssize_t tracefs_buffer_stat_entries(struct tracefs_buffer_stat *tstat)
+{
+	return tstat->entries;
+}
+
+ssize_t tracefs_buffer_stat_overrun(struct tracefs_buffer_stat *tstat)
+{
+	return tstat->overrun;
+}
+
+ssize_t tracefs_buffer_stat_commit_overrun(struct tracefs_buffer_stat *tstat)
+{
+	return tstat->commit_overrun;
+}
+
+ssize_t tracefs_buffer_stat_bytes(struct tracefs_buffer_stat *tstat)
+{
+	return tstat->bytes;
+}
+
+long long tracefs_buffer_stat_event_timestamp(struct tracefs_buffer_stat *tstat)
+{
+	return tstat->oldest_ts;
+}
+
+long long tracefs_buffer_stat_timestamp(struct tracefs_buffer_stat *tstat)
+{
+	return tstat->now_ts;
+}
+
+ssize_t tracefs_buffer_stat_dropped_events(struct tracefs_buffer_stat *tstat)
+{
+	return tstat->dropped_events;
+}
+
+ssize_t tracefs_buffer_stat_read_events(struct tracefs_buffer_stat *tstat)
+{
+	return tstat->read_events;
+}
+
diff --git a/src/tracefs-tools.c b/src/tracefs-tools.c
index 8e7b46d..74cfe91 100644
--- a/src/tracefs-tools.c
+++ b/src/tracefs-tools.c
@@ -559,8 +559,10 @@ static int add_func_str(struct func_list ***next_func_ptr, const char *func)
 		if (!func_list)
 			return -1;
 		func_list->func = strdup(func);
-		if (!func_list->func)
+		if (!func_list->func) {
+			free(func_list);
 			return -1;
+		}
 		*next_func = func_list;
 		return 0;
 	}
diff --git a/src/tracefs-utils.c b/src/tracefs-utils.c
index 9acf2ad..50a7c74 100644
--- a/src/tracefs-utils.c
+++ b/src/tracefs-utils.c
@@ -248,7 +248,7 @@ static int test_dir(const char *dir, const char *file)
  */
 const char *tracefs_tracing_dir(void)
 {
-	static const char *tracing_dir;
+	static char *tracing_dir;
 
 	/* Do not check custom_tracing_dir */
 	if (custom_tracing_dir)
@@ -257,6 +257,7 @@ const char *tracefs_tracing_dir(void)
 	if (tracing_dir && test_dir(tracing_dir, "trace"))
 		return tracing_dir;
 
+	free(tracing_dir);
 	tracing_dir = find_tracing_dir(false, true);
 	return tracing_dir;
 }
@@ -319,6 +320,26 @@ void tracefs_put_tracing_file(char *name)
 	free(name);
 }
 
+/* The function is copied from trace-cmd */
+__hidden char *strstrip(char *str)
+{
+	char *s;
+
+	if (!str)
+		return NULL;
+
+	s = str + strlen(str) - 1;
+	while (s >= str && isspace(*s))
+		s--;
+	s++;
+	*s = '\0';
+
+	for (s = str; *s && isspace(*s); s++)
+		;
+
+	return s;
+}
+
 __hidden int str_read_file(const char *file, char **buffer, bool warn)
 {
 	char stbuf[BUFSIZ];
@@ -622,3 +643,30 @@ bool tracefs_tracer_available(const char *tracing_dir, const char *tracer)
 	tracefs_list_free(tracers);
 	return ret;
 }
+
+/**
+ * tracefs_instance_get_buffer_percent - get the instance buffer percent
+ * @instance: The instance to get from (NULL for toplevel)
+ *
+ * Returns the buffer percent setting of the given instance.
+ *  (-1 if not found).
+ */
+int tracefs_instance_get_buffer_percent(struct tracefs_instance *instance)
+{
+	long long val;
+	int ret;
+
+	ret = tracefs_instance_file_read_number(instance, "buffer_percent", &val);
+	return !ret ? (int)val : ret;
+}
+
+/**
+ * tracefs_instance_set_buffer_percent - set the instance buffer percent
+ * @instance: The instance to set (NULL for toplevel)
+ *
+ * Returns zero on success or -1 on error
+ */
+int tracefs_instance_set_buffer_percent(struct tracefs_instance *instance, int val)
+{
+	return tracefs_instance_file_write_number(instance, "buffer_percent", val);
+}
diff --git a/src/tracefs-vsock.c b/src/tracefs-vsock.c
new file mode 100644
index 0000000..9171321
--- /dev/null
+++ b/src/tracefs-vsock.c
@@ -0,0 +1,276 @@
+#include <stdlib.h>
+#include <unistd.h>
+#include <ctype.h>
+#include <sys/socket.h>
+#include <linux/vm_sockets.h>
+
+#include <tracefs.h>
+
+static int open_vsock(unsigned int cid, unsigned int port)
+{
+	struct sockaddr_vm addr = {
+		.svm_family = AF_VSOCK,
+		.svm_cid = cid,
+		.svm_port = port,
+	};
+	int sd;
+
+	sd = socket(AF_VSOCK, SOCK_STREAM, 0);
+	if (sd < 0)
+		return -1;
+
+	if (connect(sd, (struct sockaddr *)&addr, sizeof(addr))) {
+		close(sd);
+		return -1;
+	}
+
+	return sd;
+}
+
+struct pids {
+	struct pids		*next;
+	int			pid;
+};
+
+struct trace_info {
+	struct tracefs_instance		*instance;
+	struct tep_handle		*tep;
+	struct tep_event		*wake_up;
+	struct tep_event		*kvm_exit;
+	struct tep_format_field		*wake_pid;
+	struct pids			*pids;
+	int				pid;
+};
+
+static void tear_down_trace(struct trace_info *info)
+{
+	tracefs_event_disable(info->instance, NULL, NULL);
+	tep_free(info->tep);
+	info->tep = NULL;
+}
+
+static int add_pid(struct pids **pids, int pid)
+{
+	struct pids *new_pid;
+
+	new_pid = malloc(sizeof(*new_pid));
+	if (!new_pid)
+		return -1;
+
+	new_pid->pid = pid;
+	new_pid->next = *pids;
+	*pids = new_pid;
+	return 0;
+}
+
+static bool match_pid(struct pids *pids, int pid)
+{
+	while (pids) {
+		if (pids->pid == pid)
+			return true;
+		pids = pids->next;
+	}
+	return false;
+}
+
+static int waking_callback(struct tep_event *event, struct tep_record *record,
+			   int cpu, void *data)
+{
+	struct trace_info *info = data;
+	unsigned long long val;
+	int flags;
+	int pid;
+	int ret;
+
+	pid = tep_data_pid(event->tep, record);
+	if (!match_pid(info->pids, pid))
+		return 0;
+
+	/* Ignore wakeups in interrupts */
+	flags = tep_data_flags(event->tep, record);
+	if (flags & (TRACE_FLAG_HARDIRQ | TRACE_FLAG_SOFTIRQ))
+		return 0;
+
+	if (!info->wake_pid) {
+		info->wake_pid = tep_find_field(event, "pid");
+
+		if (!info->wake_pid)
+			return -1;
+	}
+
+	ret = tep_read_number_field(info->wake_pid, record->data, &val);
+	if (ret < 0)
+		return -1;
+
+	return add_pid(&info->pids, (int)val);
+}
+
+static int exit_callback(struct tep_event *event, struct tep_record *record,
+			 int cpu, void *data)
+{
+	struct trace_info *info = data;
+	int pid;
+
+	pid = tep_data_pid(event->tep, record);
+	if (!match_pid(info->pids, pid))
+		return 0;
+
+	info->pid = pid;
+
+	/* Found the pid we are looking for, stop the trace */
+	return -1;
+}
+
+static int setup_trace(struct trace_info *info)
+{
+	const char *systems[] = { "sched", "kvm", NULL};
+	int ret;
+
+	info->pids = NULL;
+
+	tracefs_trace_off(info->instance);
+	info->tep = tracefs_local_events_system(NULL, systems);
+	if (!info->tep)
+		return -1;
+
+	/*
+	 * Follow the wake ups, starting with this pid, to find
+	 * the one that exits to the guest. That will be the thread
+	 * of the vCPU of the guest.
+	 */
+	ret = tracefs_follow_event(info->tep, info->instance,
+				   "sched", "sched_waking",
+				   waking_callback, info);
+	if (ret < 0)
+		goto fail;
+
+	ret = tracefs_follow_event(info->tep, info->instance,
+				   "kvm", "kvm_exit",
+				   exit_callback, info);
+	if (ret < 0)
+		goto fail;
+
+	ret = tracefs_event_enable(info->instance, "sched", "sched_waking");
+	if (ret < 0)
+		goto fail;
+
+	ret = tracefs_event_enable(info->instance, "kvm", "kvm_exit");
+	if (ret < 0)
+		goto fail;
+
+	return 0;
+fail:
+	tear_down_trace(info);
+	return -1;
+}
+
+
+static void free_pids(struct pids *pids)
+{
+	struct pids *next;
+
+	while (pids) {
+		next = pids;
+		pids = pids->next;
+		free(next);
+	}
+}
+
+static int find_thread_leader(int pid)
+{
+	FILE *fp;
+	char *path;
+	char *save;
+	char *buf = NULL;
+	size_t l = 0;
+	int tgid = -1;
+
+	if (asprintf(&path, "/proc/%d/status", pid) < 0)
+		return -1;
+
+	fp = fopen(path, "r");
+	free(path);
+	if (!fp)
+		return -1;
+
+	while (getline(&buf, &l, fp) > 0) {
+		char *tok;
+
+		if (strncmp(buf, "Tgid:", 5) != 0)
+			continue;
+		tok = strtok_r(buf, ":", &save);
+		if (!tok)
+			continue;
+		tok = strtok_r(NULL, ":", &save);
+		if (!tok)
+			continue;
+		while (isspace(*tok))
+			tok++;
+		tgid = strtol(tok, NULL, 0);
+		break;
+	}
+	free(buf);
+
+	return tgid > 0 ? tgid : -1;
+}
+
+int tracefs_instance_find_cid_pid(struct tracefs_instance *instance, int cid)
+{
+	struct trace_info info = {};
+	int this_pid = getpid();
+	int ret;
+	int fd;
+
+	info.instance = instance;
+
+	if (setup_trace(&info) < 0)
+		return -1;
+
+	ret = add_pid(&info.pids, this_pid);
+	if (ret < 0)
+		goto out;
+
+	tracefs_instance_file_clear(info.instance, "trace");
+	tracefs_trace_on(info.instance);
+	fd = open_vsock(cid, -1);
+	tracefs_trace_off(info.instance);
+	if (fd >= 0)
+		close(fd);
+	info.pid = -1;
+	ret = tracefs_iterate_raw_events(info.tep, info.instance,
+					 NULL, 0, NULL, &info);
+	if (info.pid <= 0)
+		ret = -1;
+	if (ret == 0)
+		ret = find_thread_leader(info.pid);
+
+ out:
+	free_pids(info.pids);
+	info.pids = NULL;
+	tear_down_trace(&info);
+
+	return ret;
+}
+
+int tracefs_find_cid_pid(int cid)
+{
+	struct tracefs_instance *instance;
+	char *name;
+	int ret;
+
+	ret = asprintf(&name, "_tracefs_vsock_find-%d\n", getpid());
+	if (ret < 0)
+		return ret;
+
+	instance = tracefs_instance_create(name);
+	free(name);
+	if (!instance)
+		return -1;
+
+	ret = tracefs_instance_find_cid_pid(instance, cid);
+
+	tracefs_instance_destroy(instance);
+	tracefs_instance_free(instance);
+
+	return ret;
+}
diff --git a/utest/meson.build b/utest/meson.build
new file mode 100644
index 0000000..c79313c
--- /dev/null
+++ b/utest/meson.build
@@ -0,0 +1,17 @@
+# SPDX-License-Identifier: LGPL-2.1
+#
+# Copyright (c) 2023 Daniel Wagner, SUSE LLC
+
+source = [
+    'trace-utest.c',
+    'tracefs-utest.c',
+]
+
+e = executable(
+   'trace-utest',
+   source,
+   include_directories: [incdir],
+   dependencies: [libtraceevent_dep, threads_dep, cunit_dep],
+   link_with: libtracefs_static)
+
+test('trace-utest', e)
diff --git a/utest/trace-utest.c b/utest/trace-utest.c
index 58d4d4e..39485a1 100644
--- a/utest/trace-utest.c
+++ b/utest/trace-utest.c
@@ -3,6 +3,7 @@
  * Copyright (C) 2020, VMware, Tzvetomir Stoyanov <tz.stoyanov@gmail.com>
  *
  */
+#include <libgen.h>
 #include <stdio.h>
 #include <unistd.h>
 #include <getopt.h>
diff --git a/utest/tracefs-utest.c b/utest/tracefs-utest.c
index e0e3c07..b295253 100644
--- a/utest/tracefs-utest.c
+++ b/utest/tracefs-utest.c
@@ -3,6 +3,8 @@
  * Copyright (C) 2020, VMware, Tzvetomir Stoyanov <tz.stoyanov@gmail.com>
  *
  */
+#define _LARGEFILE64_SOURCE
+
 #include <stdio.h>
 #include <stdlib.h>
 #include <sys/stat.h>
@@ -11,17 +13,25 @@
 #include <time.h>
 #include <dirent.h>
 #include <ftw.h>
+#include <ctype.h>
 #include <libgen.h>
 #include <kbuffer.h>
 #include <pthread.h>
 
 #include <sys/mount.h>
+#include <sys/syscall.h>
 
 #include <CUnit/CUnit.h>
 #include <CUnit/Basic.h>
 
 #include "tracefs.h"
 
+#define gettid() syscall(__NR_gettid)
+
+#ifndef PATH_MAX
+#define PATH_MAX 1024
+#endif
+
 #define TRACEFS_SUITE		"tracefs library"
 #define TEST_INSTANCE_NAME	"cunit_test_iter"
 #define TEST_TRACE_DIR		"/tmp/trace_utest.XXXXXX"
@@ -33,26 +43,81 @@
 #define TRACE_ON	"tracing_on"
 #define TRACE_CLOCK	"trace_clock"
 
+/* Used to insert sql types and actions, must be big enough to hold them */
+#define SQL_REPLACE	"RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR"
+
 #define SQL_1_EVENT	"wakeup_1"
 #define SQL_1_SQL	"select sched_switch.next_pid as woke_pid, sched_waking.common_pid as waking_pid from sched_waking join sched_switch on sched_switch.next_pid = sched_waking.pid"
+#define SQL_1_MATCH	"echo 's:wakeup_1 pid_t woke_pid; s32 waking_pid;' >> /sys/kernel/tracing/dynamic_events\n" \
+			"echo 'hist:keys=pid:__arg_XXXXXXXX_1=common_pid' >> /sys/kernel/tracing/events/sched/sched_waking/trigger\n" \
+			"echo 'hist:keys=next_pid:__woke_pid_XXXXXXXX_2=next_pid,__waking_pid_XXXXXXXX_3=$__arg_XXXXXXXX_1:" SQL_REPLACE "' >> /sys/kernel/tracing/events/sched/sched_switch/trigger\n"
+#define SQL_1_VAR "$__waking_pid_XXXXXXXX_3"
+#define SQL_1_ONMATCH "onmatch(sched.sched_waking)"
+#define SQL_1_TRACE "trace(wakeup_1,$__woke_pid_XXXXXXXX_2,$__waking_pid_XXXXXXXX_3)"
+#define SQL_1_SAVE { "prev_prio" , "prev_state", NULL }
 
 #define SQL_2_EVENT	"wakeup_2"
 #define SQL_2_SQL	"select woke.next_pid as woke_pid, wake.common_pid as waking_pid from sched_waking as wake join sched_switch as woke on woke.next_pid = wake.pid"
+#define SQL_2_MATCH	"echo 's:wakeup_2 pid_t woke_pid; s32 waking_pid;' >> /sys/kernel/tracing/dynamic_events\n" \
+			"echo 'hist:keys=pid:__arg_XXXXXXXX_1=common_pid' >> /sys/kernel/tracing/events/sched/sched_waking/trigger\n" \
+			"echo 'hist:keys=next_pid:__woke_pid_XXXXXXXX_2=next_pid,__waking_pid_XXXXXXXX_3=$__arg_XXXXXXXX_1:" SQL_REPLACE "' >> /sys/kernel/tracing/events/sched/sched_switch/trigger\n"
+#define SQL_2_MATCH_EVENT "sched.sched_waking"
+#define SQL_2_VAR "$__woke_pid_XXXXXXXX_2"
+#define SQL_2_ONMATCH "onmatch(sched.sched_waking)"
+#define SQL_2_TRACE "trace(wakeup_2,$__woke_pid_XXXXXXXX_2,$__waking_pid_XXXXXXXX_3)"
+#define SQL_2_SAVE { "prev_prio" , "prev_state", NULL }
 
 #define SQL_3_EVENT	"wakeup_lat"
 #define SQL_3_SQL	"select sched_switch.next_prio as prio, end.prev_prio as pprio, (sched.sched_waking.common_timestamp.usecs - end.TIMESTAMP_USECS) as lat from sched_waking as start join sched_switch as end on start.pid = end.next_pid"
+#define SQL_3_MATCH	"echo 's:wakeup_lat s32 prio; s32 pprio; u64 lat;' >> /sys/kernel/tracing/dynamic_events\n" \
+			"echo 'hist:keys=pid:__arg_XXXXXXXX_1=common_timestamp.usecs' >> /sys/kernel/tracing/events/sched/sched_waking/trigger\n" \
+			"echo 'hist:keys=next_pid:__prio_XXXXXXXX_2=next_prio,__pprio_XXXXXXXX_3=prev_prio,__lat_XXXXXXXX_4=common_timestamp.usecs-$__arg_XXXXXXXX_1:" SQL_REPLACE "' >> /sys/kernel/tracing/events/sched/sched_switch/trigger\n"
+#define SQL_3_MATCH_EVENT "sched.sched_waking"
+#define SQL_3_VAR "$__lat_XXXXXXXX_4"
+#define SQL_3_ONMATCH "onmatch(sched.sched_waking)"
+#define SQL_3_TRACE "trace(wakeup_lat,$__prio_XXXXXXXX_2,$__pprio_XXXXXXXX_3,$__lat_XXXXXXXX_4)"
+#define SQL_3_SAVE { "prev_prio" , "prev_state", NULL }
 
 #define SQL_4_EVENT	"wakeup_lat_2"
 #define SQL_4_SQL	"select start.pid, end.next_prio as prio, (end.TIMESTAMP_USECS - start.TIMESTAMP_USECS) as lat from sched_waking as start join sched_switch as end on start.pid = end.next_pid where (start.prio >= 1 && start.prio < 100) || !(start.pid >= 0 && start.pid <= 1) && end.prev_pid != 0"
+#define SQL_4_MATCH	"echo 's:wakeup_lat_2 pid_t pid; s32 prio; u64 lat;' >> /sys/kernel/tracing/dynamic_events\n" \
+			"echo 'hist:keys=pid:__arg_XXXXXXXX_1=pid,__arg_XXXXXXXX_2=common_timestamp.usecs if (prio >= 1&&prio < 100)||!(pid >= 0&&pid <= 1)' >> /sys/kernel/tracing/events/sched/sched_waking/trigger\n" \
+			"echo 'hist:keys=next_pid:__pid_XXXXXXXX_3=$__arg_XXXXXXXX_1,__prio_XXXXXXXX_4=next_prio,__lat_XXXXXXXX_5=common_timestamp.usecs-$__arg_XXXXXXXX_2:" SQL_REPLACE " if prev_pid != 0' >> /sys/kernel/tracing/events/sched/sched_switch/trigger\n"
+#define SQL_4_MATCH_EVENT "sched.sched_waking"
+#define SQL_4_VAR "$__lat_XXXXXXXX_5"
+#define SQL_4_ONMATCH "onmatch(sched.sched_waking)"
+#define SQL_4_TRACE "trace(wakeup_lat_2,$__pid_XXXXXXXX_3,$__prio_XXXXXXXX_4,$__lat_XXXXXXXX_5)"
+#define SQL_4_SAVE { "prev_prio" , "prev_state", NULL }
 
 #define SQL_5_EVENT	"irq_lat"
 #define SQL_5_SQL	"select end.common_pid as pid, (end.common_timestamp.usecs - start.common_timestamp.usecs) as irq_lat from irq_disable as start join irq_enable as end on start.common_pid = end.common_pid, start.parent_offs == end.parent_offs where start.common_pid != 0"
 #define SQL_5_START	"irq_disable"
+#define SQL_5_MATCH	"echo 's:irq_lat s32 pid; u64 irq_lat;' >> /sys/kernel/tracing/dynamic_events\n" \
+			"echo 'hist:keys=common_pid,parent_offs:__arg_XXXXXXXX_1=common_timestamp.usecs if common_pid != 0' >> /sys/kernel/tracing/events/preemptirq/irq_disable/trigger\n" \
+			"echo 'hist:keys=common_pid,parent_offs:__pid_XXXXXXXX_2=common_pid,__irq_lat_XXXXXXXX_3=common_timestamp.usecs-$__arg_XXXXXXXX_1:" SQL_REPLACE "' >> /sys/kernel/tracing/events/preemptirq/irq_enable/trigger\n"
+#define SQL_5_MATCH_EVENT "preemptirq.irq_disable"
+#define SQL_5_VAR "$__irq_lat_XXXXXXXX_3"
+#define SQL_5_ONMATCH "onmatch(preemptirq.irq_disable)"
+#define SQL_5_TRACE "trace(irq_lat,$__pid_XXXXXXXX_2,$__irq_lat_XXXXXXXX_3)"
+#define SQL_5_SAVE { "caller_offs", NULL }
+
+#define SQL_6_EVENT	"wakeup_lat_3"
+#define SQL_6_SQL	"select start.pid, end.next_prio as prio, (end.TIMESTAMP_USECS - start.TIMESTAMP_USECS) as lat from sched_waking as start join sched_switch as end on start.pid = end.next_pid where (start.prio >= 1 && start.prio < 100) || !(start.pid >= 0 && start.pid <= 1) && end.prev_pid != 0"
+#define SQL_6_MATCH	"echo 's:wakeup_lat_3 pid_t pid; s32 prio; u64 lat;' >> /sys/kernel/tracing/dynamic_events\n" \
+			"echo 'hist:keys=pid:__arg_XXXXXXXX_1=pid,__arg_XXXXXXXX_2=common_timestamp.usecs if (prio >= 1&&prio < 100)||!(pid >= 0&&pid <= 1)' >> /sys/kernel/tracing/events/sched/sched_waking/trigger\n" \
+			"echo 'hist:keys=next_pid:__pid_XXXXXXXX_3=$__arg_XXXXXXXX_1,__prio_XXXXXXXX_4=next_prio,__lat_XXXXXXXX_5=common_timestamp.usecs-$__arg_XXXXXXXX_2:" SQL_REPLACE " if prev_pid != 0' >> /sys/kernel/tracing/events/sched/sched_switch/trigger\n"
+#define SQL_6_MATCH_EVENT "sched.sched_waking"
+#define SQL_6_VAR "$__lat_XXXXXXXX_5"
+#define SQL_6_ONMATCH "onmatch(sched.sched_waking)"
+#define SQL_6_TRACE "trace(wakeup_lat_3,$__pid_XXXXXXXX_3,$__prio_XXXXXXXX_4,$__lat_XXXXXXXX_5)"
+#define SQL_6_SAVE { "prev_prio" , "prev_state", NULL }
 
 #define DEBUGFS_DEFAULT_PATH "/sys/kernel/debug"
 #define TRACEFS_DEFAULT_PATH "/sys/kernel/tracing"
 #define TRACEFS_DEFAULT2_PATH "/sys/kernel/debug/tracing"
 
+static pthread_barrier_t trace_barrier;
+
 static struct tracefs_instance *test_instance;
 static struct tep_handle *test_tep;
 struct test_sample {
@@ -63,6 +128,18 @@ static struct test_sample test_array[TEST_ARRAY_SIZE];
 static int test_found;
 static unsigned long long last_ts;
 
+static bool mapping_is_supported;
+
+static void msleep(int ms)
+{
+	struct timespec tspec;
+
+	/* Sleep for 1ms */
+	tspec.tv_sec = 0;
+	tspec.tv_nsec = 1000000 * ms;
+	nanosleep(&tspec, NULL);
+}
+
 static int test_callback(struct tep_event *event, struct tep_record *record,
 			  int cpu, void *context)
 {
@@ -163,7 +240,7 @@ static void test_iter_write(struct tracefs_instance *instance)
 }
 
 
-static void iter_raw_events_on_cpu(struct tracefs_instance *instance, int cpu)
+static void iter_raw_events_on_cpu(struct tracefs_instance *instance, int cpu, bool snapshot)
 {
 	int cpus = sysconf(_SC_NPROCESSORS_CONF);
 	cpu_set_t *cpuset = NULL;
@@ -172,6 +249,9 @@ static void iter_raw_events_on_cpu(struct tracefs_instance *instance, int cpu)
 	int ret;
 	int i;
 
+	if (snapshot)
+		tracefs_instance_clear(instance);
+
 	if (cpu >= 0) {
 		cpuset = CPU_ALLOC(cpus);
 		cpu_size = CPU_ALLOC_SIZE(cpus);
@@ -181,8 +261,15 @@ static void iter_raw_events_on_cpu(struct tracefs_instance *instance, int cpu)
 	test_found = 0;
 	last_ts = 0;
 	test_iter_write(instance);
-	ret = tracefs_iterate_raw_events(test_tep, instance, cpuset, cpu_size,
-					 test_callback, &cpu);
+
+	if (snapshot) {
+		tracefs_snapshot_snap(instance);
+		ret = tracefs_iterate_snapshot_events(test_tep, instance, cpuset, cpu_size,
+						      test_callback, &cpu);
+	} else {
+		ret = tracefs_iterate_raw_events(test_tep, instance, cpuset, cpu_size,
+						 test_callback, &cpu);
+	}
 	CU_TEST(ret == 0);
 	if (cpu < 0) {
 		CU_TEST(test_found == TEST_ARRAY_SIZE);
@@ -216,16 +303,35 @@ static void test_instance_iter_raw_events(struct tracefs_instance *instance)
 	ret = tracefs_iterate_raw_events(test_tep, instance, NULL, 0, NULL, NULL);
 	CU_TEST(ret < 0);
 
-	iter_raw_events_on_cpu(instance, -1);
+	iter_raw_events_on_cpu(instance, -1, false);
 	for (i = 0; i < cpus; i++)
-		iter_raw_events_on_cpu(instance, i);
+		iter_raw_events_on_cpu(instance, i, false);
 }
 
 static void test_iter_raw_events(void)
 {
+	test_instance_iter_raw_events(NULL);
 	test_instance_iter_raw_events(test_instance);
 }
 
+static void test_instance_iter_snapshot_events(struct tracefs_instance *instance)
+{
+	int cpus = sysconf(_SC_NPROCESSORS_CONF);
+	int i;
+
+	iter_raw_events_on_cpu(instance, -1, true);
+	for (i = 0; i < cpus; i++)
+		iter_raw_events_on_cpu(instance, i, true);
+	tracefs_snapshot_free(instance);
+}
+
+static void test_iter_snapshot_events(void)
+{
+	test_instance_iter_snapshot_events(NULL);
+	test_instance_iter_snapshot_events(test_instance);
+}
+
+
 #define RAND_STR_SIZE 20
 #define RAND_ASCII "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
 static const char *get_rand_str(void)
@@ -358,64 +464,609 @@ static void test_ftrace_marker(void)
 	test_instance_ftrace_marker(test_instance);
 }
 
-static void test_instance_trace_sql(struct tracefs_instance *instance)
+static void replace_str(char *str, char *rep, char *with, int rep_len, int with_len)
+{
+	char find[rep_len + 1];
+	char *s = str;
+	int delta = rep_len - with_len;
+
+	CU_TEST(delta >= 0);
+	if (delta < 0) {
+		printf("rep_len:%d with_len:%d\n", rep_len, with_len);
+		return;
+	}
+
+	strncpy(find, rep, rep_len + 1);
+	find[rep_len] = '\0';
+
+	while ((s = strstr(s, find))) {
+		strncpy(s, with, with_len);
+		s += with_len;
+		if (delta) {
+			int new_len = strlen(s) - delta;
+			memmove(s, s + delta, new_len);
+			s[new_len] = '\0';
+		}
+	}
+}
+
+enum sql_type {
+	SQL_ONMATCH,
+	SQL_ONMAX,
+	SQL_ONCHANGE,
+};
+
+enum sql_action {
+	SQL_TRACE,
+	SQL_SNAPSHOT,
+	SQL_SAVE,
+	SQL_TRACE_SNAPSHOT,
+};
+
+struct trace_sql_strings {
+	const char		*match;
+	const char		*onmatch;
+	const char		*var;
+	const char		*trace;
+	char			*save[4];
+};
+
+#define SQL_VAR_REPLACE		"_XXXXXXXX_"
+
+static bool test_sql(struct trace_seq *seq, struct trace_sql_strings *strings,
+		     enum sql_type stype, enum sql_action atype)
+{
+	char string[strlen(strings->match) + 256]; /* add a bunch for replacement */
+	char replace[1024];
+	char type[256];
+	char *p, *s, *e, *c = seq->buffer;
+	bool ret;
+
+	strcpy(string, strings->match);
+	s = string;
+
+	switch (stype) {
+	case SQL_ONMATCH:
+		sprintf(type, "%s", strings->onmatch);
+		break;
+	case SQL_ONMAX:
+		sprintf(type, "onmax(%s)", strings->var);
+		break;
+	case SQL_ONCHANGE:
+		sprintf(type, "onchange(%s)", strings->var);
+		break;
+	}
+
+	switch (atype) {
+	case SQL_TRACE:
+		sprintf(replace, "%s.%s", type, strings->trace);
+		break;
+	case SQL_SNAPSHOT:
+		sprintf(replace, "%s.snapshot()", type);
+		break;
+	case SQL_SAVE:
+		sprintf(replace, "%s.save(", type);
+
+		for (int i = 0; strings->save[i]; i++) {
+			if (i)
+				strcat(replace, ",");
+			strcat(replace, strings->save[i]);
+		}
+		strcat(replace, ")");
+		break;
+	case SQL_TRACE_SNAPSHOT:
+		sprintf(replace, "%s.%s:%s.snapshot()", type, strings->trace, type);
+		break;
+	}
+
+	replace_str(string, SQL_REPLACE, replace, strlen(SQL_REPLACE), strlen(replace));
+
+	while ((p = strstr(s, SQL_VAR_REPLACE))) {
+		CU_TEST(ret = strncmp(c, s, p - s) == 0);
+		if (!ret) {
+			printf("\n\t'%*.s'\nDOES NOT MATCH\n\t%*.s\n",
+			       (int)(p - s), c, (int)(p - s), s);
+			return ret;
+		}
+
+		/* Move c passed what was matched */
+		c += p - s;
+
+		/* Set e to the next value */
+		e = c + 1;
+		while (isdigit(*e))
+			e++;
+		/* Skip the next '_' */
+		e++;
+		/* Skip the next numbers */
+		while (isdigit(*e))
+			e++;
+
+		/* Skip the "_XXXXXXXX_" */
+		s = p + strlen(SQL_VAR_REPLACE);
+		/* Skip the next numbers */
+		while (isdigit(*s))
+			s++;
+
+		/* Now replace all of these */
+		replace_str(s, p, c, s - p, e - c);
+
+		c = e;
+	}
+
+	ret = strcmp(s, c) == 0;
+	if (!ret)
+		printf("\n\t'%s'\nDOES NOT MATCH\n\t%s\n", s, c);
+
+	return ret;
+}
+
+static void unhash_var(char *var, const char *hash_var)
+{
+	const char *p = hash_var + strlen(hash_var) - 1;
+	int len;
+
+	/* Skip $__ */
+	hash_var += 3;
+
+	/* Find the _XXXXXXXXX_ */
+	p = strstr(hash_var, SQL_VAR_REPLACE);
+	CU_TEST(p != NULL);
+
+	len = p - hash_var;
+
+	strncpy(var, hash_var, len);
+	var[len] = '\0';
+}
+
+static bool set_sql_type(struct tracefs_synth *synth, struct trace_sql_strings *strings,
+			 enum sql_type stype, enum sql_action atype)
+{
+	enum tracefs_synth_handler handler = 0;
+	char var[256];
+	int ret = 0;
+
+	switch (stype) {
+	case SQL_ONMATCH:
+		break;
+	case SQL_ONMAX:
+		handler = TRACEFS_SYNTH_HANDLE_MAX;
+		break;
+	case SQL_ONCHANGE:
+		handler = TRACEFS_SYNTH_HANDLE_CHANGE;
+		break;
+	}
+
+	unhash_var(var, strings->var);
+
+	switch (atype) {
+	case SQL_TRACE:
+		if (handler)
+			ret = tracefs_synth_trace(synth, handler, var);
+		break;
+	case SQL_SNAPSHOT:
+		ret = tracefs_synth_snapshot(synth, handler, var);
+		break;
+	case SQL_SAVE:
+		ret = tracefs_synth_save(synth, handler, var, strings->save);
+		break;
+	case SQL_TRACE_SNAPSHOT:
+		ret = tracefs_synth_trace(synth, handler, var);
+		ret |= tracefs_synth_snapshot(synth, handler, var);
+		break;
+	}
+
+	return ret == 0;
+}
+
+#define sql_assign_save(str, arr)			\
+	do {						\
+		char *__array__[] = arr;		\
+		int i;					\
+							\
+		for (i = 0; __array__[i]; i++) {	\
+			(str)[i] = __array__[i];	\
+		}					\
+		(str)[i] = NULL;			\
+	} while (0)
+
+static void test_instance_trace_sql(struct tracefs_instance *instance,
+				    enum sql_type stype, enum sql_action atype)
 {
 	struct tracefs_synth *synth;
 	struct trace_seq seq;
 	struct tep_handle *tep;
 	struct tep_event *event;
+	struct trace_sql_strings strings;
 	int ret;
 
-	tep = tracefs_local_events(NULL);
-	CU_TEST(tep != NULL);
+	tep = test_tep;
 
 	trace_seq_init(&seq);
 
+	strings.match = SQL_1_MATCH;
+	strings.var = SQL_1_VAR;
+	strings.onmatch = SQL_1_ONMATCH;
+	strings.trace = SQL_1_TRACE;
+	sql_assign_save(strings.save, SQL_1_SAVE);
+
 	synth = tracefs_sql(tep, SQL_1_EVENT, SQL_1_SQL, NULL);
 	CU_TEST(synth != NULL);
+	CU_TEST(set_sql_type(synth, &strings, stype, atype));
 	ret = tracefs_synth_echo_cmd(&seq, synth);
 	CU_TEST(ret == 0);
+	CU_TEST(test_sql(&seq, &strings, stype, atype));
 	tracefs_synth_free(synth);
 	trace_seq_reset(&seq);
 
+	strings.match = SQL_2_MATCH;
+	strings.var = SQL_2_VAR;
+	strings.onmatch = SQL_2_ONMATCH;
+	strings.trace = SQL_2_TRACE;
+	sql_assign_save(strings.save, SQL_2_SAVE);
+
 	synth = tracefs_sql(tep, SQL_2_EVENT, SQL_2_SQL, NULL);
 	CU_TEST(synth != NULL);
+	CU_TEST(set_sql_type(synth, &strings, stype, atype));
 	ret = tracefs_synth_echo_cmd(&seq, synth);
 	CU_TEST(ret == 0);
+	CU_TEST(test_sql(&seq, &strings, stype, atype));
 	tracefs_synth_free(synth);
 	trace_seq_reset(&seq);
 
+	strings.match = SQL_3_MATCH;
+	strings.var = SQL_3_VAR;
+	strings.onmatch = SQL_3_ONMATCH;
+	strings.trace = SQL_3_TRACE;
+	sql_assign_save(strings.save, SQL_3_SAVE);
+
 	synth = tracefs_sql(tep, SQL_3_EVENT, SQL_3_SQL, NULL);
 	CU_TEST(synth != NULL);
+	CU_TEST(set_sql_type(synth, &strings, stype, atype));
 	ret = tracefs_synth_echo_cmd(&seq, synth);
 	CU_TEST(ret == 0);
+	CU_TEST(test_sql(&seq, &strings, stype, atype));
 	tracefs_synth_free(synth);
 	trace_seq_reset(&seq);
 
+	strings.match = SQL_4_MATCH;
+	strings.var = SQL_4_VAR;
+	strings.onmatch = SQL_4_ONMATCH;
+	strings.trace = SQL_4_TRACE;
+	sql_assign_save(strings.save, SQL_4_SAVE);
+
 	synth = tracefs_sql(tep, SQL_4_EVENT, SQL_4_SQL, NULL);
 	CU_TEST(synth != NULL);
+	CU_TEST(set_sql_type(synth, &strings, stype, atype));
 	ret = tracefs_synth_echo_cmd(&seq, synth);
 	CU_TEST(ret == 0);
+	CU_TEST(test_sql(&seq, &strings, stype, atype));
 	tracefs_synth_free(synth);
 	trace_seq_reset(&seq);
 
 	event = tep_find_event_by_name(tep, NULL, SQL_5_START);
 	if (event) {
+
+		strings.match = SQL_5_MATCH;
+		strings.var = SQL_5_VAR;
+		strings.onmatch = SQL_5_ONMATCH;
+		strings.trace = SQL_5_TRACE;
+		sql_assign_save(strings.save, SQL_5_SAVE);
+
 		synth = tracefs_sql(tep, SQL_5_EVENT, SQL_5_SQL, NULL);
 		CU_TEST(synth != NULL);
+		CU_TEST(set_sql_type(synth, &strings, stype, atype));
 		ret = tracefs_synth_echo_cmd(&seq, synth);
 		CU_TEST(ret == 0);
+		CU_TEST(test_sql(&seq, &strings, stype, atype));
 		tracefs_synth_free(synth);
 		trace_seq_reset(&seq);
 	}
 
-	tep_free(tep);
+	strings.match = SQL_6_MATCH;
+	strings.var = SQL_6_VAR;
+	strings.onmatch = SQL_6_ONMATCH;
+	strings.trace = SQL_6_TRACE;
+	sql_assign_save(strings.save, SQL_6_SAVE);
+
+	synth = tracefs_sql(tep, SQL_6_EVENT, SQL_6_SQL, NULL);
+	CU_TEST(synth != NULL);
+	CU_TEST(set_sql_type(synth, &strings, stype, atype));
+	ret = tracefs_synth_echo_cmd(&seq, synth);
+	CU_TEST(ret == 0);
+	CU_TEST(test_sql(&seq, &strings, stype, atype));
+	tracefs_synth_free(synth);
+	trace_seq_reset(&seq);
+
 	trace_seq_destroy(&seq);
 }
 
 static void test_trace_sql(void)
 {
-	test_instance_trace_sql(test_instance);
+	test_instance_trace_sql(test_instance, SQL_ONMATCH, SQL_TRACE);
+}
+
+static void test_trace_sql_trace_onmax(void)
+{
+	test_instance_trace_sql(test_instance, SQL_ONMAX, SQL_TRACE);
+}
+
+static void test_trace_sql_trace_onchange(void)
+{
+	test_instance_trace_sql(test_instance, SQL_ONCHANGE, SQL_TRACE);
+}
+
+static void test_trace_sql_snapshot_onmax(void)
+{
+	test_instance_trace_sql(test_instance, SQL_ONMAX, SQL_SNAPSHOT);
+}
+
+static void test_trace_sql_snapshot_onchange(void)
+{
+	test_instance_trace_sql(test_instance, SQL_ONCHANGE, SQL_SNAPSHOT);
+}
+
+static void test_trace_sql_save_onmax(void)
+{
+	test_instance_trace_sql(test_instance, SQL_ONMAX, SQL_SAVE);
+}
+
+static void test_trace_sql_save_onchange(void)
+{
+	test_instance_trace_sql(test_instance, SQL_ONCHANGE, SQL_SAVE);
+}
+
+static void test_trace_sql_trace_snapshot_onmax(void)
+{
+	test_instance_trace_sql(test_instance, SQL_ONMAX, SQL_TRACE_SNAPSHOT);
+}
+
+static void test_trace_sql_trace_snapshot_onchange(void)
+{
+	test_instance_trace_sql(test_instance, SQL_ONCHANGE, SQL_TRACE_SNAPSHOT);
+}
+
+
+static void call_getppid(int cnt)
+{
+	int i;
+
+	for (i = 0; i < cnt; i++)
+		getppid();
+}
+
+struct check_data {
+	int	this_pid;
+	int	other_pid;
+	bool	trace_this;
+	bool	trace_other;
+	bool	trace_all;
+	bool	hit;
+	int (*filter_clear)(struct tracefs_instance *instance, bool notrace);
+};
+
+static int check_callback(struct tep_event *event, struct tep_record *record,
+			  int cpu, void *data)
+{
+	struct check_data *cdata = data;
+	int pid;
+
+	cdata->hit = true;
+
+	pid = tep_data_pid(event->tep, record);
+
+	if (pid == cdata->this_pid) {
+		CU_TEST(cdata->trace_this);
+		return cdata->trace_this ? 0 : -1;
+	}
+
+	if (pid == cdata->other_pid) {
+		CU_TEST(cdata->trace_other);
+		return cdata->trace_other ? 0 : -1;
+	}
+
+	CU_TEST(cdata->trace_all);
+	if (!cdata->trace_all) {
+		printf(" (Traced %d but should not have", pid);
+		if (cdata->trace_this)
+			printf(", this_pid:%d", cdata->this_pid);
+		if (cdata->trace_other)
+			printf(", other_pid:%d", cdata->other_pid);
+		printf(") ");
+	}
+
+	return cdata->trace_all ? 0 : -1;
+}
+
+static int check_filtered_pid(struct tep_handle *tep, struct tracefs_instance *instance,
+			      struct check_data *cdata)
+{
+	int ret;
+
+	cdata->hit = false;
+	ret = tracefs_iterate_raw_events(tep, instance, NULL, 0, check_callback, cdata);
+
+	tracefs_instance_clear(instance);
+
+	cdata->filter_clear(instance, false);
+	cdata->filter_clear(instance, true);
+
+	return ret;
+}
+
+struct spin_data {
+	bool	stop;
+	bool	done;
+	int	tid;
+};
+
+static void *trace_spin_thread(void *arg)
+{
+	struct spin_data *data = arg;
+
+	data->tid = gettid();
+	pthread_barrier_wait(&trace_barrier);
+
+	while (!data->done) {
+		pthread_barrier_wait(&trace_barrier);
+		while (!data->stop && !data->done)
+			getppid();
+		pthread_barrier_wait(&trace_barrier);
+	}
+
+	return NULL;
+}
+
+static void run_test(struct tracefs_instance *instance, struct tep_handle *tep,
+		     struct spin_data *data, struct check_data *cdata)
+{
+	tracefs_trace_on(instance);
+
+	/* Run a little */
+	call_getppid(1000);
+
+	/* Start the spinner */
+	data->stop = false;
+	pthread_barrier_wait(&trace_barrier);
+
+	/* Allow the other threads run */
+	msleep(100);
+
+	/* Stop the spinners */
+	data->stop = true;
+	pthread_barrier_wait(&trace_barrier);
+	/* Run a little more  */
+	call_getppid(10);
+	tracefs_trace_off(instance);
+
+	check_filtered_pid(tep, instance, cdata);
+}
+
+
+static void test_instance_pid_filter(struct tracefs_instance *instance,
+				     int (*filter_pid)(struct tracefs_instance *instance,
+						       int pid, bool reset, bool notrace),
+				     int (*filter_clear)(struct tracefs_instance *instance,
+							 bool notrace))
+{
+	struct tep_handle *tep = test_tep;
+	struct check_data cdata;
+	struct spin_data data = { };
+	pthread_t thread1;
+	pthread_t thread2;
+	int this_pid = getpid();
+
+	pthread_barrier_init(&trace_barrier, NULL, 3);
+
+	/* create two spinners, one will be used for tracing */
+	pthread_create(&thread1, NULL, trace_spin_thread, &data);
+	pthread_create(&thread2, NULL, trace_spin_thread, &data);
+
+	pthread_barrier_wait(&trace_barrier);
+
+	cdata.this_pid = this_pid;
+	cdata.other_pid = data.tid;
+	cdata.filter_clear = filter_clear;
+
+	/* Test 1 */
+	cdata.trace_this = true;
+	cdata.trace_other = false;
+	cdata.trace_all = false;
+
+	/* Add the thread, but then reset it out */
+	filter_pid(instance, data.tid, true, false);
+	filter_pid(instance, this_pid, true, false);
+
+	/* Only this thread should be traced */
+	run_test(instance, tep, &data, &cdata);
+	CU_TEST(cdata.hit);
+
+
+	/* Test 2 */
+	cdata.trace_this = true;
+	cdata.trace_other = true;
+	cdata.trace_all = false;
+
+	/* Add the thread, but then reset it out */
+	filter_pid(instance, data.tid, true, false);
+	filter_pid(instance, this_pid, false, false);
+
+	/* Only this thread should be traced */
+	run_test(instance, tep, &data, &cdata);
+	CU_TEST(cdata.hit);
+
+
+	/* Test 3 */
+	cdata.trace_this = false;
+	cdata.trace_other = true;
+	cdata.trace_all = true;
+
+	/* Add the thread, but then reset it out */
+	filter_pid(instance, data.tid, true, true);
+	filter_pid(instance, this_pid, true, true);
+
+	/* Only this thread should be traced */
+	run_test(instance, tep, &data, &cdata);
+	CU_TEST(cdata.hit);
+
+
+	/* Test 4 */
+	cdata.trace_this = false;
+	cdata.trace_other = false;
+	cdata.trace_all = true;
+
+	/* Add the thread, but then reset it out */
+	filter_pid(instance, data.tid, true, true);
+	filter_pid(instance, this_pid, false, true);
+
+	/* Only this thread should be traced */
+	run_test(instance, tep, &data, &cdata);
+	CU_TEST(cdata.hit);
+
+	/* exit out */
+	data.done = true;
+	pthread_barrier_wait(&trace_barrier);
+	pthread_barrier_wait(&trace_barrier);
+
+	pthread_join(thread1, NULL);
+	pthread_join(thread2, NULL);
+}
+
+static void test_function_pid_filter(struct tracefs_instance *instance)
+{
+	tracefs_trace_off(instance);
+	tracefs_instance_clear(instance);
+	tracefs_tracer_set(instance, TRACEFS_TRACER_FUNCTION);
+	test_instance_pid_filter(instance,
+				 tracefs_filter_pid_function,
+				 tracefs_filter_pid_function_clear);
+	tracefs_tracer_clear(instance);
+	tracefs_trace_on(instance);
+}
+
+static void test_trace_function_pid_filter(void)
+{
+	test_function_pid_filter(NULL);
+	test_function_pid_filter(test_instance);
+}
+
+static void test_events_pid_filter(struct tracefs_instance *instance)
+{
+	tracefs_trace_off(instance);
+	tracefs_instance_clear(instance);
+	tracefs_event_enable(instance, "syscalls", NULL);
+	tracefs_event_enable(instance, "raw_syscalls", NULL);
+	test_instance_pid_filter(instance,
+				 tracefs_filter_pid_events,
+				 tracefs_filter_pid_events_clear);
+	tracefs_event_disable(instance, NULL, NULL);
+	tracefs_trace_on(instance);
+}
+
+static void test_trace_events_pid_filter(void)
+{
+	test_events_pid_filter(NULL);
+	test_events_pid_filter(test_instance);
 }
 
 struct test_cpu_data {
@@ -427,6 +1078,7 @@ struct test_cpu_data {
 	void				*buf;
 	int				events_per_buf;
 	int				bufsize;
+	int				nr_subbufs;
 	int				data_size;
 	int				this_pid;
 	int				fd;
@@ -436,7 +1088,6 @@ struct test_cpu_data {
 static void cleanup_trace_cpu(struct test_cpu_data *data)
 {
 	close(data->fd);
-	tep_free(data->tep);
 	tracefs_cpu_close(data->tcpu);
 	free(data->buf);
 	kbuffer_free(data->kbuf);
@@ -445,11 +1096,21 @@ static void cleanup_trace_cpu(struct test_cpu_data *data)
 #define EVENT_SYSTEM "syscalls"
 #define EVENT_NAME  "sys_enter_getppid"
 
-static int setup_trace_cpu(struct tracefs_instance *instance, struct test_cpu_data *data)
+static int make_trace_temp_file(void)
+{
+	char tmpfile[] = "/tmp/utest-libtracefsXXXXXX";
+	int fd;
+
+	fd = mkstemp(tmpfile);
+	unlink(tmpfile);
+	return fd;
+}
+
+static int setup_trace_cpu(struct tracefs_instance *instance, struct test_cpu_data *data, bool nonblock, bool map)
 {
 	struct tep_format_field **fields;
 	struct tep_event *event;
-	char tmpfile[] = "/tmp/utest-libtracefsXXXXXX";
+	ssize_t buffer_size;
 	int max = 0;
 	int ret;
 	int i;
@@ -461,36 +1122,41 @@ static int setup_trace_cpu(struct tracefs_instance *instance, struct test_cpu_da
 
 	data->instance = instance;
 
-	data->fd = mkstemp(tmpfile);
+	data->fd = make_trace_temp_file();
 	CU_TEST(data->fd >= 0);
-	unlink(tmpfile);
 	if (data->fd < 0)
 		return -1;
 
-	data->tep = tracefs_local_events(NULL);
-	CU_TEST(data->tep != NULL);
-	if (!data->tep)
-		goto fail;
+	data->tep = test_tep;
+
+	if (map)
+		data->tcpu = tracefs_cpu_open_mapped(instance, 0, nonblock);
+	else
+		data->tcpu = tracefs_cpu_open(instance, 0, nonblock);
 
-	data->tcpu = tracefs_cpu_open(instance, 0, true);
 	CU_TEST(data->tcpu != NULL);
 	if (!data->tcpu)
 		goto fail;
 
 	data->bufsize = tracefs_cpu_read_size(data->tcpu);
+	CU_TEST(data->bufsize > 0);
+
+	data->data_size = tep_get_sub_buffer_data_size(data->tep);
+	CU_TEST(data->data_size > 0);
+
+	buffer_size = tracefs_instance_get_buffer_size(instance, 0) * 1024;
+	data->nr_subbufs = buffer_size/ data->data_size;
 
 	data->buf = calloc(1, data->bufsize);
 	CU_TEST(data->buf != NULL);
 	if (!data->buf)
 		goto fail;
 
-	data->kbuf = kbuffer_alloc(sizeof(long) == 8, !tep_is_bigendian());
+	data->kbuf = tep_kbuffer(data->tep);
 	CU_TEST(data->kbuf != NULL);
 	if (!data->kbuf)
 		goto fail;
 
-	data->data_size = data->bufsize - kbuffer_start_of_data(data->kbuf);
-
 	tracefs_instance_file_clear(instance, "trace");
 
 	event = tep_find_event_by_name(data->tep, EVENT_SYSTEM, EVENT_NAME);
@@ -514,6 +1180,12 @@ static int setup_trace_cpu(struct tracefs_instance *instance, struct test_cpu_da
 	if (!max)
 		goto fail;
 
+	/* round up to long size alignment */
+	max = ((max + sizeof(long) - 1)) & ~(sizeof(long) - 1);
+
+	/* Add meta header */
+	max += 4;
+
 	data->events_per_buf = data->data_size / max;
 
 	data->this_pid = getpid();
@@ -545,12 +1217,18 @@ static void shutdown_trace_cpu(struct test_cpu_data *data)
 	cleanup_trace_cpu(data);
 }
 
-static void call_getppid(int cnt)
+static void reset_trace_cpu(struct test_cpu_data *data, bool nonblock, bool map)
 {
-	int i;
+	close(data->fd);
+	tracefs_cpu_close(data->tcpu);
 
-	for (i = 0; i < cnt; i++)
-		getppid();
+	data->fd = make_trace_temp_file();
+	CU_TEST(data->fd >= 0);
+	if (map)
+		data->tcpu = tracefs_cpu_open_mapped(data->instance, 0, nonblock);
+	else
+		data->tcpu = tracefs_cpu_open(data->instance, 0, nonblock);
+	CU_TEST(data->tcpu != NULL);
 }
 
 static void test_cpu_read(struct test_cpu_data *data, int expect)
@@ -589,35 +1267,167 @@ static void test_cpu_read(struct test_cpu_data *data, int expect)
 	CU_TEST(cnt == expect);
 }
 
-static void test_instance_trace_cpu_read(struct tracefs_instance *instance)
-{
-	struct test_cpu_data data;
+static void test_instance_trace_cpu_read(struct tracefs_instance *instance, bool map)
+{
+	struct test_cpu_data data;
+
+	if (setup_trace_cpu(instance, &data, true, map))
+		return;
+
+	test_cpu_read(&data, 1);
+	test_cpu_read(&data, data.events_per_buf / 2);
+	test_cpu_read(&data, data.events_per_buf);
+	test_cpu_read(&data, data.events_per_buf + 1);
+	test_cpu_read(&data, data.events_per_buf * 50);
+
+	shutdown_trace_cpu(&data);
+}
+
+static void test_trace_cpu_read(void)
+{
+	test_instance_trace_cpu_read(NULL, false);
+	if (mapping_is_supported)
+		test_instance_trace_cpu_read(NULL, true);
+
+	test_instance_trace_cpu_read(test_instance, false);
+	if (mapping_is_supported)
+		test_instance_trace_cpu_read(test_instance, true);
+}
+
+static void *trace_cpu_read_thread(void *arg)
+{
+	struct test_cpu_data *data = arg;
+	struct tracefs_cpu *tcpu = data->tcpu;
+	struct kbuffer *kbuf;
+	long ret = 0;
+
+	pthread_barrier_wait(&trace_barrier);
+
+	kbuf = tracefs_cpu_read_buf(tcpu, false);
+	CU_TEST(kbuf != NULL);
+	data->done = true;
+
+	return (void *)ret;
+}
+
+static void test_cpu_read_buf_percent(struct test_cpu_data *data, int percent)
+{
+	char buffer[tracefs_cpu_read_size(data->tcpu)];
+	pthread_t thread;
+	int save_percent;
+	ssize_t expect;
+	int ret;
+
+	tracefs_instance_clear(data->instance);
+
+	save_percent = tracefs_instance_get_buffer_percent(data->instance);
+	CU_TEST(save_percent >= 0);
+
+	ret = tracefs_instance_set_buffer_percent(data->instance, percent);
+	CU_TEST(ret == 0);
+
+	data->done = false;
+
+	pthread_barrier_init(&trace_barrier, NULL, 2);
+
+	pthread_create(&thread, NULL, trace_cpu_read_thread, data);
+
+	pthread_barrier_wait(&trace_barrier);
+
+	msleep(100);
+
+	CU_TEST(data->done == false);
+
+	/* For percent == 0, just test for any data */
+	if (percent) {
+		expect = data->nr_subbufs * data->events_per_buf * percent / 100;
+
+		/* Add just under the percent */
+		expect -= data->events_per_buf;
+		CU_TEST(expect > 0);
+
+		call_getppid(expect);
+
+		msleep(100);
+
+		CU_TEST(data->done == false);
+
+		/* Add just over the percent */
+		expect = data->events_per_buf * 2;
+	} else {
+		expect = data->events_per_buf;
+	}
+
+	call_getppid(expect);
+
+	msleep(100);
+
+	CU_TEST(data->done == true);
+
+	while (tracefs_cpu_flush(data->tcpu, buffer))
+		;
+
+	tracefs_cpu_stop(data->tcpu);
+	pthread_join(thread, NULL);
+
+	ret = tracefs_instance_set_buffer_percent(data->instance, save_percent);
+	CU_TEST(ret == 0);
+}
+
+static void test_instance_trace_cpu_read_buf_percent(struct tracefs_instance *instance, bool map)
+{
+	struct test_cpu_data data;
+
+	if (setup_trace_cpu(instance, &data, false, map))
+		return;
+
+	test_cpu_read_buf_percent(&data, 0);
+
+	reset_trace_cpu(&data, false, map);
+
+	test_cpu_read_buf_percent(&data, 1);
+
+	reset_trace_cpu(&data, false, map);
 
-	if (setup_trace_cpu(instance, &data))
-		return;
+	test_cpu_read_buf_percent(&data, 50);
 
-	test_cpu_read(&data, 1);
-	test_cpu_read(&data, data.events_per_buf / 2);
-	test_cpu_read(&data, data.events_per_buf);
-	test_cpu_read(&data, data.events_per_buf + 1);
-	test_cpu_read(&data, data.events_per_buf * 50);
+	reset_trace_cpu(&data, false, map);
+
+	test_cpu_read_buf_percent(&data, 100);
 
 	shutdown_trace_cpu(&data);
 }
 
-static void test_trace_cpu_read(void)
+static void test_trace_cpu_read_buf_percent(void)
 {
-	test_instance_trace_cpu_read(NULL);
-	test_instance_trace_cpu_read(test_instance);
+	test_instance_trace_cpu_read_buf_percent(NULL, false);
+	if (mapping_is_supported)
+		test_instance_trace_cpu_read_buf_percent(NULL, true);
+	test_instance_trace_cpu_read_buf_percent(test_instance, false);
+	if (mapping_is_supported)
+		test_instance_trace_cpu_read_buf_percent(test_instance, true);
 }
 
 struct follow_data {
 	struct tep_event *sched_switch;
 	struct tep_event *sched_waking;
+	struct tep_event *getppid;
 	struct tep_event *function;
 	int missed;
+	int switch_hit;
+	int waking_hit;
+	int getppid_hit;
+	int missed_hit;
 };
 
+static void clear_hits(struct follow_data *fdata)
+{
+	fdata->switch_hit = 0;
+	fdata->waking_hit = 0;
+	fdata->getppid_hit = 0;
+	fdata->missed_hit = 0;
+}
+
 static int switch_callback(struct tep_event *event, struct tep_record *record,
 			   int cpu, void *data)
 {
@@ -625,6 +1435,7 @@ static int switch_callback(struct tep_event *event, struct tep_record *record,
 
 	CU_TEST(cpu == record->cpu);
 	CU_TEST(event->id == fdata->sched_switch->id);
+	fdata->switch_hit++;
 	return 0;
 }
 
@@ -635,6 +1446,18 @@ static int waking_callback(struct tep_event *event, struct tep_record *record,
 
 	CU_TEST(cpu == record->cpu);
 	CU_TEST(event->id == fdata->sched_waking->id);
+	fdata->waking_hit++;
+	return 0;
+}
+
+static int getppid_callback(struct tep_event *event, struct tep_record *record,
+			    int cpu, void *data)
+{
+	struct follow_data *fdata = data;
+
+	CU_TEST(cpu == record->cpu);
+	CU_TEST(event->id == fdata->getppid->id);
+	fdata->getppid_hit++;
 	return 0;
 }
 
@@ -654,6 +1477,7 @@ static int missed_callback(struct tep_event *event, struct tep_record *record,
 	struct follow_data *fdata = data;
 
 	fdata->missed = record->missed_events;
+	fdata->missed_hit++;
 	return 0;
 }
 
@@ -685,10 +1509,7 @@ static void test_instance_follow_events(struct tracefs_instance *instance)
 
 	memset(&fdata, 0, sizeof(fdata));
 
-	tep = tracefs_local_events(NULL);
-	CU_TEST(tep != NULL);
-	if (!tep)
-		return;
+	tep = test_tep;
 
 	fdata.sched_switch = tep_find_event_by_name(tep, "sched", "sched_switch");
 	CU_TEST(fdata.sched_switch != NULL);
@@ -734,6 +1555,11 @@ static void test_instance_follow_events(struct tracefs_instance *instance)
 	ret = tracefs_iterate_raw_events(tep, instance, NULL, 0, all_callback, &fdata);
 	CU_TEST(ret == 0);
 
+	ret = tracefs_follow_event_clear(instance, NULL, NULL);
+	CU_TEST(ret == 0);
+	ret = tracefs_follow_missed_events_clear(instance);
+	CU_TEST(ret == 0);
+
 	pthread_join(thread, NULL);
 
 	tracefs_tracer_clear(instance);
@@ -746,6 +1572,204 @@ static void test_follow_events(void)
 	test_instance_follow_events(test_instance);
 }
 
+static void test_instance_follow_events_clear(struct tracefs_instance *instance)
+{
+	struct follow_data fdata;
+	struct tep_handle *tep;
+	unsigned long page_size;
+	size_t save_size;
+	char **list;
+	int ret;
+
+	memset(&fdata, 0, sizeof(fdata));
+
+	tep = test_tep;
+
+	fdata.sched_switch = tep_find_event_by_name(tep, "sched", "sched_switch");
+	CU_TEST(fdata.sched_switch != NULL);
+	if (!fdata.sched_switch)
+		return;
+
+	fdata.sched_waking = tep_find_event_by_name(tep, "sched", "sched_waking");
+	CU_TEST(fdata.sched_waking != NULL);
+	if (!fdata.sched_waking)
+		return;
+
+	fdata.getppid = tep_find_event_by_name(tep, EVENT_SYSTEM, EVENT_NAME);
+	CU_TEST(fdata.getppid != NULL);
+	if (!fdata.getppid)
+		return;
+
+	ret = tracefs_follow_event(tep, instance, "sched", "sched_switch",
+				   switch_callback, &fdata);
+	CU_TEST(ret == 0);
+
+	ret = tracefs_follow_event(tep, instance, "sched", "sched_waking",
+				   waking_callback, &fdata);
+	CU_TEST(ret == 0);
+
+	ret = tracefs_follow_event(tep, instance, EVENT_SYSTEM, EVENT_NAME,
+				   getppid_callback, &fdata);
+	CU_TEST(ret == 0);
+
+	ret = tracefs_follow_missed_events(instance, missed_callback, &fdata);
+	CU_TEST(ret == 0);
+
+	ret = tracefs_event_enable(instance, "sched", "sched_switch");
+	CU_TEST(ret == 0);
+
+	ret = tracefs_event_enable(instance, "sched", "sched_waking");
+	CU_TEST(ret == 0);
+
+	ret = tracefs_event_enable(instance, EVENT_SYSTEM, EVENT_NAME);
+	CU_TEST(ret == 0);
+
+	tracefs_trace_on(instance);
+	call_getppid(100);
+	msleep(100);
+	tracefs_trace_off(instance);
+
+	ret = tracefs_iterate_raw_events(tep, instance, NULL, 0, NULL, &fdata);
+	CU_TEST(ret == 0);
+
+	/* Make sure all are hit */
+	CU_TEST(fdata.switch_hit > 0);
+	CU_TEST(fdata.waking_hit > 0);
+	CU_TEST(fdata.getppid_hit == 100);
+	/* No missed events */
+	CU_TEST(fdata.missed_hit == 0);
+	clear_hits(&fdata);
+
+
+
+	/* Disable getppid and do the same thing */
+	ret = tracefs_follow_event_clear(instance, EVENT_SYSTEM, EVENT_NAME);
+	CU_TEST(ret == 0);
+
+	tracefs_trace_on(instance);
+	call_getppid(100);
+	msleep(100);
+	tracefs_trace_off(instance);
+
+	ret = tracefs_iterate_raw_events(tep, instance, NULL, 0, NULL, &fdata);
+	CU_TEST(ret == 0);
+
+	/* All but getppid should be hit */
+	CU_TEST(fdata.switch_hit > 0);
+	CU_TEST(fdata.waking_hit > 0);
+	CU_TEST(fdata.getppid_hit == 0);
+	/* No missed events */
+	CU_TEST(fdata.missed_hit == 0);
+	clear_hits(&fdata);
+
+
+
+	/* Add function and remove sched */
+	ret = tracefs_follow_event(tep, instance, "ftrace", "function",
+				   function_callback, &fdata);
+	CU_TEST(ret == 0);
+	ret = tracefs_follow_event_clear(instance, "sched", NULL);
+	CU_TEST(ret == 0);
+
+	tracefs_trace_on(instance);
+	call_getppid(100);
+	system("ls -l /usr/bin > /dev/null");
+	tracefs_trace_off(instance);
+
+	ret = tracefs_iterate_raw_events(tep, instance, NULL, 0, NULL, &fdata);
+	CU_TEST(ret == 0);
+
+	/* Nothing should have been hit */
+	CU_TEST(fdata.switch_hit == 0);
+	CU_TEST(fdata.waking_hit == 0);
+	CU_TEST(fdata.getppid_hit == 0);
+	/* No missed events */
+	CU_TEST(fdata.missed_hit == 0);
+	clear_hits(&fdata);
+
+
+	/* Enable function tracing and see if we missed hits */
+	ret = tracefs_tracer_set(instance, TRACEFS_TRACER_FUNCTION);
+	CU_TEST(ret == 0);
+
+	fdata.function = tep_find_event_by_name(tep, "ftrace", "function");
+	CU_TEST(fdata.function != NULL);
+	if (!fdata.function)
+		return;
+
+	/* Shrink the buffer to make sure we have missed events */
+	page_size = getpagesize();
+	save_size = tracefs_instance_get_buffer_size(instance, 0);
+	ret = tracefs_instance_set_buffer_size(instance, page_size * 4, 0);
+	CU_TEST(ret == 0);
+
+	tracefs_trace_on(instance);
+	call_getppid(100);
+	/* Stir the kernel a bit */
+	list = tracefs_event_systems(NULL);
+	tracefs_list_free(list);
+	system("ls -l /usr/bin > /dev/null");
+	tracefs_trace_off(instance);
+
+	ret = tracefs_iterate_raw_events(tep, instance, NULL, 0, NULL, &fdata);
+	CU_TEST(ret == 0);
+
+	ret = tracefs_instance_set_buffer_size(instance, save_size, 0);
+	CU_TEST(ret == 0);
+
+	/* Nothing should have been hit */
+	CU_TEST(fdata.switch_hit == 0);
+	CU_TEST(fdata.waking_hit == 0);
+	CU_TEST(fdata.getppid_hit == 0);
+	/* We should have missed events! */
+	CU_TEST(fdata.missed_hit > 0);
+	clear_hits(&fdata);
+
+
+	/* Now remove missed events follower */
+	ret = tracefs_follow_missed_events_clear(instance);
+	CU_TEST(ret == 0);
+
+	tracefs_trace_on(instance);
+	call_getppid(100);
+	sleep(1);
+	tracefs_trace_off(instance);
+
+	ret = tracefs_iterate_raw_events(tep, instance, NULL, 0, NULL, &fdata);
+	CU_TEST(ret == 0);
+
+	/* Nothing should have been hit */
+	CU_TEST(fdata.switch_hit == 0);
+	CU_TEST(fdata.waking_hit == 0);
+	CU_TEST(fdata.getppid_hit == 0);
+	/* No missed events either */
+	CU_TEST(fdata.missed_hit == 0);
+	clear_hits(&fdata);
+
+	/* Turn everything off */
+	tracefs_tracer_clear(instance);
+	tracefs_event_disable(instance, NULL, NULL);
+
+	tracefs_trace_on(instance);
+
+	/* Clear the function follower */
+	ret = tracefs_follow_event_clear(instance, NULL, "function");
+
+	/* Should not have any more followers */
+	ret = tracefs_follow_event_clear(instance, NULL, NULL);
+	CU_TEST(ret != 0);
+
+	/* Nor missed event followers */
+	ret = tracefs_follow_missed_events_clear(instance);
+	CU_TEST(ret != 0);
+}
+
+static void test_follow_events_clear(void)
+{
+	test_instance_follow_events_clear(NULL);
+	test_instance_follow_events_clear(test_instance);
+}
+
 extern char *find_tracing_dir(bool debugfs, bool mount);
 static void test_mounting(void)
 {
@@ -928,11 +1952,11 @@ static void test_cpu_pipe(struct test_cpu_data *data, int expect)
 	CU_TEST(cnt == expect);
 }
 
-static void test_instance_trace_cpu_pipe(struct tracefs_instance *instance)
+static void test_instance_trace_cpu_pipe(struct tracefs_instance *instance, bool map)
 {
 	struct test_cpu_data data;
 
-	if (setup_trace_cpu(instance, &data))
+	if (setup_trace_cpu(instance, &data, true, map))
 		return;
 
 	test_cpu_pipe(&data, 1);
@@ -946,8 +1970,12 @@ static void test_instance_trace_cpu_pipe(struct tracefs_instance *instance)
 
 static void test_trace_cpu_pipe(void)
 {
-	test_instance_trace_cpu_pipe(NULL);
-	test_instance_trace_cpu_pipe(test_instance);
+	test_instance_trace_cpu_pipe(NULL, false);
+	if (mapping_is_supported)
+		test_instance_trace_cpu_pipe(NULL, true);
+	test_instance_trace_cpu_pipe(test_instance, false);
+	if (mapping_is_supported)
+		test_instance_trace_cpu_pipe(test_instance, true);
 }
 
 static struct tracefs_dynevent **get_dynevents_check(enum tracefs_dynevent_type types, int count)
@@ -983,7 +2011,7 @@ struct test_synth {
 	char *match_name;
 };
 
-static void test_synth_compare(struct test_synth *synth, struct tracefs_dynevent **devents)
+static void test_synth_compare(struct test_synth *sevents, struct tracefs_dynevent **devents)
 {
 	enum tracefs_dynevent_type stype;
 	char *format;
@@ -994,9 +2022,11 @@ static void test_synth_compare(struct test_synth *synth, struct tracefs_dynevent
 		stype = tracefs_dynevent_info(devents[i], NULL,
 					      &event, NULL, NULL, &format);
 		CU_TEST(stype == TRACEFS_DYNEVENT_SYNTH);
-		CU_TEST(strcmp(event, synth[i].name) == 0);
-		if (synth[i].match_name) {
-			CU_TEST(strstr(format, synth[i].match_name) != NULL);
+		if (stype != TRACEFS_DYNEVENT_SYNTH)
+			continue;
+		CU_TEST(event && sevents[i].name && strcmp(event, sevents[i].name) == 0);
+		if (sevents[i].match_name) {
+			CU_TEST(strstr(format, sevents[i].match_name) != NULL);
 		}
 		free(event);
 		free(format);
@@ -1004,6 +2034,15 @@ static void test_synth_compare(struct test_synth *synth, struct tracefs_dynevent
 	CU_TEST(devents == NULL || devents[i] == NULL);
 }
 
+static void destroy_dynevents(unsigned int type)
+{
+	int ret;
+
+	ret = tracefs_dynevent_destroy_all(type, true);
+	CU_TEST(ret == 0);
+	get_dynevents_check(type, 0);
+}
+
 static void test_instance_synthetic(struct tracefs_instance *instance)
 {
 	struct test_synth sevents[] = {
@@ -1023,9 +2062,7 @@ static void test_instance_synthetic(struct tracefs_instance *instance)
 	CU_TEST(tep != NULL);
 
 	/* kprobes APIs */
-	ret = tracefs_dynevent_destroy_all(TRACEFS_DYNEVENT_SYNTH, true);
-	CU_TEST(ret == 0);
-	get_dynevents_check(TRACEFS_DYNEVENT_SYNTH, 0);
+	destroy_dynevents(TRACEFS_DYNEVENT_SYNTH);
 
 	for (i = 0; i < sevents_count; i++) {
 		synth[i] = tracefs_synth_alloc(tep,  sevents[i].name,
@@ -1045,6 +2082,12 @@ static void test_instance_synthetic(struct tracefs_instance *instance)
 
 	devents = get_dynevents_check(TRACEFS_DYNEVENT_SYNTH, sevents_count);
 	CU_TEST(devents != NULL);
+	if (!devents)
+		goto out;
+	CU_TEST(devents[sevents_count] == NULL);
+	if (devents[sevents_count])
+		goto out;
+
 	test_synth_compare(sevents, devents);
 	tracefs_dynevent_list_free(devents);
 
@@ -1055,6 +2098,7 @@ static void test_instance_synthetic(struct tracefs_instance *instance)
 
 	get_dynevents_check(TRACEFS_DYNEVENT_SYNTH, 0);
 
+ out:
 	for (i = 0; i < sevents_count; i++)
 		tracefs_synth_free(synth[i]);
 
@@ -1251,9 +2295,7 @@ static void test_kprobes_instance(struct tracefs_instance *instance)
 	CU_TEST(tracefs_kretprobe_raw("test", "test", NULL, "test") != 0);
 
 	/* kprobes APIs */
-	ret = tracefs_dynevent_destroy_all(TRACEFS_DYNEVENT_KPROBE | TRACEFS_DYNEVENT_KRETPROBE, true);
-	CU_TEST(ret == 0);
-	get_dynevents_check(TRACEFS_DYNEVENT_KPROBE | TRACEFS_DYNEVENT_KRETPROBE, 0);
+	destroy_dynevents(TRACEFS_DYNEVENT_KPROBE | TRACEFS_DYNEVENT_KRETPROBE);
 
 	for (i = 0; i < kprobe_count; i++) {
 		dkprobe[i] = tracefs_kprobe_alloc(ktests[i].system, ktests[i].event,
@@ -1318,9 +2360,7 @@ static void test_kprobes_instance(struct tracefs_instance *instance)
 		tracefs_dynevent_free(dkretprobe[i]);
 
 	/* kprobes raw APIs */
-	ret = tracefs_dynevent_destroy_all(TRACEFS_DYNEVENT_KPROBE | TRACEFS_DYNEVENT_KRETPROBE, true);
-	CU_TEST(ret == 0);
-	get_dynevents_check(TRACEFS_DYNEVENT_KPROBE | TRACEFS_DYNEVENT_KRETPROBE, 0);
+	destroy_dynevents(TRACEFS_DYNEVENT_KPROBE | TRACEFS_DYNEVENT_KRETPROBE);
 
 	for (i = 0; i < kprobe_count; i++) {
 		ret = tracefs_kprobe_raw(ktests[i].system, ktests[i].event,
@@ -1356,9 +2396,27 @@ static void test_kprobes_instance(struct tracefs_instance *instance)
 	tracefs_dynevent_list_free(devents);
 	devents = NULL;
 
-	ret = tracefs_dynevent_destroy_all(TRACEFS_DYNEVENT_KPROBE | TRACEFS_DYNEVENT_KRETPROBE, true);
-	CU_TEST(ret == 0);
-	get_dynevents_check(TRACEFS_DYNEVENT_KPROBE | TRACEFS_DYNEVENT_KRETPROBE, 0);
+	/* Try destroying all the events using tracefs_kprobe_destroy */
+	for (i = 0; i < kprobe_count; i++) {
+		ret = tracefs_kprobe_destroy(ktests[i].system, ktests[i].event,
+					     ktests[i].address, ktests[i].format, true);
+		CU_TEST(ret == 0);
+		devents = get_dynevents_check(TRACEFS_DYNEVENT_KPROBE,
+					      kprobe_count - (i + 1));
+		tracefs_dynevent_list_free(devents);
+	}
+	get_dynevents_check(TRACEFS_DYNEVENT_KPROBE, 0);
+
+	for (i = 0; i < kretprobe_count; i++) {
+		ret = tracefs_kprobe_destroy(kretests[i].system, kretests[i].event,
+					     kretests[i].address, kretests[i].format, true);
+		CU_TEST(ret == 0);
+		devents = get_dynevents_check(TRACEFS_DYNEVENT_KRETPROBE,
+					      kretprobe_count - (i + 1));
+		tracefs_dynevent_list_free(devents);
+	}
+	get_dynevents_check(TRACEFS_DYNEVENT_KRETPROBE, 0);
+
 	free(dkretprobe);
 	free(dkprobe);
 	tep_free(tep);
@@ -1383,7 +2441,6 @@ static void test_eprobes_instance(struct tracefs_instance *instance)
 	struct tep_handle *tep;
 	char *tsys, *tevent;
 	char *tmp, *sav;
-	int ret;
 	int i;
 
 	tep = tep_alloc();
@@ -1396,9 +2453,7 @@ static void test_eprobes_instance(struct tracefs_instance *instance)
 	CU_TEST(tracefs_eprobe_alloc("test", "test", NULL, "test", "test") == NULL);
 	CU_TEST(tracefs_eprobe_alloc("test", "test", "test", NULL, "test") == NULL);
 
-	ret = tracefs_dynevent_destroy_all(TRACEFS_DYNEVENT_EPROBE, true);
-	CU_TEST(ret == 0);
-	get_dynevents_check(TRACEFS_DYNEVENT_EPROBE, 0);
+	destroy_dynevents(TRACEFS_DYNEVENT_EPROBE);
 
 	for (i = 0; i < count; i++) {
 		tmp = strdup(etests[i].address);
@@ -1618,6 +2673,193 @@ static void test_instance_file(void)
 	free(inst_dir);
 }
 
+static bool test_check_file_content(struct tracefs_instance *instance, char *file,
+				    char *content, bool full_match, bool ignore_comments)
+{
+	char *save = NULL;
+	char *buf, *line;
+	bool ret = false;
+	int len;
+
+	if (!tracefs_file_exists(instance, file))
+		return false;
+
+	buf = tracefs_instance_file_read(instance, file, NULL);
+	if (strlen(content) == 0) {
+		/* check for empty file */
+		if (!buf)
+			return true;
+		if (!ignore_comments) {
+			if (strlen(buf) > 0)
+				goto out;
+		} else {
+			line = strtok_r(buf, "\n", &save);
+			while (line) {
+				if (line[0] != '#')
+					goto out;
+				line = strtok_r(NULL, "\n", &save);
+			}
+		}
+	} else {
+		if (!buf || strlen(buf) < 1)
+			return false;
+		if (full_match) {
+			/* strip the newline */
+			len = strlen(buf) - 1;
+			while (buf[len] == '\n' || buf[len] == '\r') {
+				buf[len] = '\0';
+				len = strlen(buf) - 1;
+				if (len < 0)
+					goto out;
+			}
+			if (strcmp(buf, content))
+				goto out;
+		} else {
+			if (!strstr(buf, content))
+				goto out;
+		}
+	}
+
+	ret = true;
+out:
+	free(buf);
+	return ret;
+}
+
+static bool test_check_event_file_content(struct tracefs_instance *instance,
+					  char *system, char *event, char *file,
+					  char *content, bool full_match, bool ignore_comments)
+{
+	char *efile;
+	int ret;
+
+	ret = asprintf(&efile, "events/%s/%s/%s", system, event, file);
+	if (ret <= 0)
+		return false;
+	ret = test_check_file_content(instance, efile, content, full_match, ignore_comments);
+	free(efile);
+	return ret;
+}
+
+static bool check_cpu_mask(struct tracefs_instance *instance)
+{
+	int cpus = sysconf(_SC_NPROCESSORS_CONF);
+	int fullwords = (cpus - 1) / 32;
+	int bits = (cpus - 1) % 32 + 1;
+	int len = (fullwords + 1) * 9;
+	char buf[len + 1];
+
+	buf[0] = '\0';
+	sprintf(buf, "%x", (unsigned int)((1ULL << bits) - 1));
+	while (fullwords-- > 0)
+		strcat(buf, ",ffffffff");
+
+	return test_check_file_content(instance, "tracing_cpumask", buf, true, false);
+}
+
+static bool test_instance_check_default_state(struct tracefs_instance *instance)
+{
+	char **systems;
+	char **events;
+	int i, j;
+	int ok;
+
+	if (tracefs_trace_is_on(instance) != 1)
+		return false;
+	if (!test_check_file_content(instance, "current_tracer", "nop", true, false))
+		return false;
+	if (!test_check_file_content(instance, "events/enable", "0", true, false))
+		return false;
+	if (!test_check_file_content(instance, "set_ftrace_pid", "no pid", true, false))
+		return false;
+	if (!test_check_file_content(instance, "trace", "", true, true))
+		return false;
+	if (!test_check_file_content(instance, "error_log", "", true, false))
+		return false;
+	if (!test_check_file_content(instance, "trace_clock", "[local]", false, false))
+		return false;
+	if (!test_check_file_content(instance, "set_event_pid", "", true, false))
+		return false;
+	if (!test_check_file_content(instance, "tracing_max_latency", "0", true, false))
+		return false;
+	if (!test_check_file_content(instance, "set_ftrace_filter", "", true, true))
+		return false;
+	if (!test_check_file_content(instance, "set_ftrace_notrace", "", true, true))
+		return false;
+	if (!check_cpu_mask(instance))
+		return false;
+
+	ok = 1;
+	systems = tracefs_event_systems(NULL);
+	if (systems) {
+		for (i = 0; systems[i]; i++) {
+			events = tracefs_system_events(NULL, systems[i]);
+			if (!events)
+				continue;
+			for (j = 0; events[j]; j++) {
+				if (!test_check_event_file_content(instance, systems[i], events[j],
+								    "enable", "0", true, false))
+					break;
+				if (!test_check_event_file_content(instance, systems[i], events[j],
+								    "filter", "none", true, false))
+					break;
+				if (!test_check_event_file_content(instance, systems[i], events[j],
+								    "trigger", "", true, true))
+					break;
+			}
+			if (events[j])
+				ok = 0;
+			tracefs_list_free(events);
+			if (!ok)
+				return false;
+		}
+		tracefs_list_free(systems);
+	}
+
+	return true;
+}
+
+static void test_instance_reset(void)
+{
+	struct tracefs_instance *instance = NULL;
+	const char *name = get_rand_str();
+	char **tracers;
+
+	CU_TEST(tracefs_instance_exists(name) == false);
+	instance = tracefs_instance_create(name);
+	CU_TEST(instance != NULL);
+
+	CU_TEST(test_instance_check_default_state(instance) == true);
+
+	tracers = tracefs_instance_tracers(instance);
+	CU_TEST(tracers != NULL);
+	if (tracers) {
+		CU_TEST(tracefs_tracer_set(instance, TRACEFS_TRACER_CUSTOM, tracers[0]) == 0);
+		tracefs_list_free(tracers);
+	}
+	CU_TEST(tracefs_event_enable(instance, "sched", "sched_switch") == 0);
+	CU_TEST(tracefs_instance_file_write(instance, "set_ftrace_pid", "5") > 0);
+	CU_TEST(tracefs_instance_file_write(instance, "trace_clock", "global") > 0);
+	CU_TEST(tracefs_instance_file_write(instance, "set_event_pid", "5") > 0);
+	CU_TEST(tracefs_instance_file_write(instance, "set_ftrace_filter",
+						      "schedule:stacktrace") > 0);
+	CU_TEST(tracefs_instance_file_write(instance, "set_ftrace_notrace",
+						      "schedule:stacktrace") > 0);
+	CU_TEST(tracefs_instance_file_write(instance, "tracing_cpumask", "0f") > 0);
+	CU_TEST(tracefs_event_file_write(instance, "syscalls", "sys_exit_read", "trigger",
+						      "enable_event:kmem:kmalloc:1") > 0);
+	CU_TEST(tracefs_event_file_write(instance, "sched", "sched_switch", "filter",
+						      "common_pid == 5") > 0);
+
+	CU_TEST(test_instance_check_default_state(instance) == false);
+
+	tracefs_instance_reset(instance);
+	CU_TEST(test_instance_check_default_state(instance) == true);
+
+	CU_TEST(tracefs_instance_destroy(instance) == 0);
+	tracefs_instance_free(instance);
+}
+
 static bool check_fd_name(int fd, const char *dir, const char *name)
 {
 	char link[PATH_MAX + 1];
@@ -1693,6 +2935,7 @@ static void test_instance_file_fd(struct tracefs_instance *instance)
 	const char *name = get_rand_str();
 	const char *tdir = tracefs_instance_get_trace_dir(instance);
 	long long res = -1;
+	long long res2;
 	char rd[2];
 	int fd;
 
@@ -1712,7 +2955,34 @@ static void test_instance_file_fd(struct tracefs_instance *instance)
 	CU_TEST(read(fd, &rd, 1) == 1);
 	rd[1] = 0;
 	CU_TEST(res == atoi(rd));
+	close(fd);
+
+	/* Inverse tracing_on and test changing it with write_number */
+	res ^= 1;
+
+	CU_TEST(tracefs_instance_file_write_number(instance, TRACE_ON, (size_t)res) == 0);
 
+	CU_TEST(tracefs_instance_file_read_number(instance, TRACE_ON, &res2) == 0);
+	CU_TEST(res2 == res);
+	fd = tracefs_instance_file_open(instance, TRACE_ON, O_RDONLY);
+	CU_TEST(fd >= 0);
+	CU_TEST(read(fd, &rd, 1) == 1);
+	rd[1] = 0;
+	CU_TEST(res2 == atoi(rd));
+	close(fd);
+
+	/* Put back the result of tracing_on */
+	res ^= 1;
+
+	CU_TEST(tracefs_instance_file_write_number(instance, TRACE_ON, (size_t)res) == 0);
+
+	CU_TEST(tracefs_instance_file_read_number(instance, TRACE_ON, &res2) == 0);
+	CU_TEST(res2 == res);
+	fd = tracefs_instance_file_open(instance, TRACE_ON, O_RDONLY);
+	CU_TEST(fd >= 0);
+	CU_TEST(read(fd, &rd, 1) == 1);
+	rd[1] = 0;
+	CU_TEST(res2 == atoi(rd));
 	close(fd);
 }
 
@@ -2311,6 +3581,7 @@ static void test_custom_trace_dir(void)
 
 static int test_suite_destroy(void)
 {
+	tracefs_instance_reset(NULL);
 	tracefs_instance_destroy(test_instance);
 	tracefs_instance_free(test_instance);
 	tep_free(test_tep);
@@ -2319,15 +3590,22 @@ static int test_suite_destroy(void)
 
 static int test_suite_init(void)
 {
-	const char *systems[] = {"ftrace", NULL};
-
-	test_tep = tracefs_local_events_system(NULL, systems);
+	test_tep = tracefs_local_events(NULL);
 	if (test_tep == NULL)
 		return 1;
 	test_instance = tracefs_instance_create(TEST_INSTANCE_NAME);
 	if (!test_instance)
 		return 1;
 
+	mapping_is_supported = tracefs_mapped_is_supported();
+	if (mapping_is_supported)
+		printf("Testing mmapped buffers too\n");
+	else
+		printf("Memory mapped buffers not supported\n");
+
+	/* Start with a new slate */
+	tracefs_instance_reset(NULL);
+
 	return 0;
 }
 
@@ -2344,23 +3622,51 @@ void test_tracefs_lib(void)
 	CU_add_test(suite, "Test tracefs/debugfs mounting", test_mounting);
 	CU_add_test(suite, "trace cpu read",
 		    test_trace_cpu_read);
+	CU_add_test(suite, "trace cpu read_buf_percent",
+		    test_trace_cpu_read_buf_percent);
 	CU_add_test(suite, "trace cpu pipe",
 		    test_trace_cpu_pipe);
+	CU_add_test(suite, "trace pid events filter",
+		    test_trace_events_pid_filter);
+	CU_add_test(suite, "trace pid function filter",
+		    test_trace_function_pid_filter);
 	CU_add_test(suite, "trace sql",
 		    test_trace_sql);
+	CU_add_test(suite, "trace sql trace onmax",
+		    test_trace_sql_trace_onmax);
+	CU_add_test(suite, "trace sql trace onchange",
+		    test_trace_sql_trace_onchange);
+	CU_add_test(suite, "trace sql snapshot onmax",
+		    test_trace_sql_snapshot_onmax);
+	CU_add_test(suite, "trace sql snapshot onchange",
+		    test_trace_sql_snapshot_onchange);
+	CU_add_test(suite, "trace sql save onmax",
+		    test_trace_sql_save_onmax);
+	CU_add_test(suite, "trace sql save onchange",
+		    test_trace_sql_save_onchange);
+	CU_add_test(suite, "trace sql trace and snapshot onmax",
+		    test_trace_sql_trace_snapshot_onmax);
+	CU_add_test(suite, "trace sql trace and snapshot onchange",
+		    test_trace_sql_trace_snapshot_onchange);
 	CU_add_test(suite, "tracing file / directory APIs",
 		    test_trace_file);
 	CU_add_test(suite, "instance file / directory APIs",
 		    test_file_fd);
 	CU_add_test(suite, "instance file descriptor",
 		    test_instance_file);
+	CU_add_test(suite, "instance reset",
+		    test_instance_reset);
 	CU_add_test(suite, "systems and events APIs",
 		    test_system_event);
+	CU_add_test(suite, "tracefs_iterate_snapshot_events API",
+		    test_iter_snapshot_events);
+
 	CU_add_test(suite, "tracefs_iterate_raw_events API",
 		    test_iter_raw_events);
 
 	/* Follow events test must be after the iterate raw events above */
 	CU_add_test(suite, "Follow events", test_follow_events);
+	CU_add_test(suite, "Follow events clear", test_follow_events_clear);
 
 	CU_add_test(suite, "tracefs_tracers API",
 		    test_tracers);
```

