```diff
diff --git a/Documentation/install-docs.sh.in b/Documentation/install-docs.sh.in
new file mode 100644
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
diff --git a/Documentation/libtraceevent-event_find.txt b/Documentation/libtraceevent-event_find.txt
index 56d76b1..c7602f3 100644
--- a/Documentation/libtraceevent-event_find.txt
+++ b/Documentation/libtraceevent-event_find.txt
@@ -3,7 +3,7 @@ libtraceevent(3)
 
 NAME
 ----
-tep_find_event,tep_find_event_by_name,tep_find_event_by_record -
+tep_find_event,tep_find_event_by_name,tep_find_event_by_record, tep_record_is_event -
 Find events by given key.
 
 SYNOPSIS
@@ -15,6 +15,7 @@ SYNOPSIS
 struct tep_event pass:[*]*tep_find_event*(struct tep_handle pass:[*]_tep_, int _id_);
 struct tep_event pass:[*]*tep_find_event_by_name*(struct tep_handle pass:[*]_tep_, const char pass:[*]_sys_, const char pass:[*]_name_);
 struct tep_event pass:[*]*tep_find_event_by_record*(struct tep_handle pass:[*]_tep_, struct tep_record pass:[*]_record_);
+bool *tep_record_is_event*(struct tep_record pass:[*]record, struct tep_event pass:[*]event);
 --
 
 DESCRIPTION
@@ -31,12 +32,16 @@ The *tep_find_event_by_name()* function searches for an event by given
 event _name_, under the system _sys_. If the _sys_ is NULL (not specified),
 the first event with _name_ is returned.
 
-The tep_find_event_by_record()* function searches for an event from a given
+The *tep_find_event_by_record()* function searches for an event from a given
 _record_.
 
+The *tep_record_is_event()* function tests if the given _record_ is of the type
+of the _event_. This is normally used to know if the _record_ being processed is
+of an _event_ where further processing should be done.
+
 RETURN VALUE
 ------------
-All these functions return a pointer to the found event, or NULL if there is no
+All these functions except *tep_record_is_event()* return a pointer to the found event, or NULL if there is no
 such event.
 
 EXAMPLE
diff --git a/Documentation/libtraceevent-handle.txt b/Documentation/libtraceevent-handle.txt
index 64528eb..fd55712 100644
--- a/Documentation/libtraceevent-handle.txt
+++ b/Documentation/libtraceevent-handle.txt
@@ -17,6 +17,7 @@ void *tep_free*(struct tep_handle pass:[*]_tep_);
 void *tep_ref*(struct tep_handle pass:[*]_tep_);
 void *tep_unref*(struct tep_handle pass:[*]_tep_);
 int *tep_get_ref*(struct tep_handle pass:[*]_tep_);
+struct kbuffer pass:[*]*tep_kbuffer*(struct tep_handle pass:[*]_tep_);
 --
 
 DESCRIPTION
diff --git a/Documentation/libtraceevent-kbuffer-create.txt b/Documentation/libtraceevent-kbuffer-create.txt
index 12e5d6c..6f89de9 100644
--- a/Documentation/libtraceevent-kbuffer-create.txt
+++ b/Documentation/libtraceevent-kbuffer-create.txt
@@ -3,7 +3,8 @@ libtraceevent(3)
 
 NAME
 ----
-kbuffer_alloc, kbuffer_free, kbuffer_load_subbuffer, kbuffer_subbuffer_size, kbuffer_start_of_data - Creating of kbuffer element to parse
+kbuffer_alloc, kbuffer_dup, kbuffer_free, kbuffer_load_subbuffer, kbuffer_subbuffer,
+kbuffer_refresh, kbuffer_subbuffer_size, kbuffer_start_of_data - Creating of kbuffer element to parse
 the Linux kernel tracing ring buffer
 
 SYNOPSIS
@@ -28,10 +29,13 @@ struct kbuffer;
 struct tep_handle;
 
 struct kbuffer pass:[*]*kbuffer_alloc*(enum kbuffer_long_size _size_, enum kbuffer_endian _endian_);
+struct kbuffer pass:[*]*kbuffer_dup*(struct kbuffer pass:[*]_kbuf_);
 void *kbuffer_free*(struct kbuffer pass:[*]_kbuf_);
 int *kbuffer_load_subbuffer*(struct kbuffer pass:[*]_kbuf_, void pass:[*]_subbuffer_);
-int *kbuffer_subbuffer_size*(struct kbuffer pass:[*]_kbuf);
+int *kbuffer_subbuffer_size*(struct kbuffer pass:[*]_kbuf_);
+int *kbuffer_refresh*(struct kbuffer pass:[*]_kbuf_);
 int *kbuffer_start_of_data*(struct kbuffer pass:[*]_kbuf_);
+void pass:[*]*kbuffer_subbuffer*(struct kbuffer pass:[*]_kbuf);
 --
 
 DESCRIPTION
@@ -59,6 +63,11 @@ will then perform a *uname(2)* call, and if the _machine_ field has the string "
 in it, it will be set to 8 byte long size and not 4 byte. This is because the
 ring buffer long size is dependent on the kernel and not user space.
 
+The *kbuffer_dup()* function will duplicate an existing kbuffer structure with
+an allocated new one. It will have all the properties of the passed in _kbuf_,
+including pointing to the same subbuffer that was loaded in the _kbuf_.
+It must be freed with *kbuffer_free()*.
+
 The *kbuffer_free()* function will free the resources created by *kbuffer_alloc()*.
 
 The *kbuffer_load_subbuffer()* will take a _subbuffer_ which is a raw data blob
@@ -70,9 +79,20 @@ is what kbuffer uses to walk the events.
 The *kbuffer_subbuffer_size()* returns the location of the end of the last event
 on the sub-buffer. It does not return the size of the sub-buffer itself.
 
+The *kbuffer_refresh()* is to be used if more writes were done on the loaded kbuffer
+where the size of the kbuffer needs to be refreshed to be able to read the new
+events that were written since the last *kbuffer_load_subbuffer()* was called on it.
+
+Note, no memory barriers are implemented with this function and any synchronization
+with the writer is the responsibility of the application.
+
 The *kbuffer_start_of_data()* function returns the offset of where the actual
 data load of the sub-buffer begins.
 
+The *kbuffer_subbuffer()* function returns the pointer to the currently loaded
+subbuffer. That is, the last subbuffer that was loaded by *kbuffer_load_subbuffer()*.
+If no subbuffer was loaded NULL is returned.
+
 RETURN VALUE
 ------------
 *kbuffer_alloc()* returns an allocated kbuffer descriptor or NULL on error.
@@ -86,6 +106,12 @@ of the last event is located.
 *kbuffer_start_of_data()* returns the offset of where the data begins on the
 sub-buffer loaded in _kbuf_.
 
+*kbuffer_subbuffer()* returns the last loaded subbuffer to _kbuf_ that was loaded
+by *kbuffer_load_subbuffer()* or NULL if none was loaded.
+
+*kbuffer_refresh()* returns 0 on success and -1 if _kbuf_ is NULL or it does not
+have a subbuffer loaded via *kbuffer_load_subbuffer()*.
+
 EXAMPLE
 -------
 [source,c]
diff --git a/Documentation/libtraceevent-kbuffer-read.txt b/Documentation/libtraceevent-kbuffer-read.txt
index 68184ad..ade42f3 100644
--- a/Documentation/libtraceevent-kbuffer-read.txt
+++ b/Documentation/libtraceevent-kbuffer-read.txt
@@ -4,7 +4,7 @@ libtraceevent(3)
 NAME
 ----
 kbuffer_read_event, kbuffer_next_event, kbuffer_missed_events, kbuffer_event_size, kbuffer_curr_size,
-kbuffer_curr_offset, kbuffer_curr_index -
+kbuffer_curr_offset, kbuffer_curr_index, kbuffer_read_buffer -
 Functions to read through the kbuffer sub buffer.
 
 SYNOPSIS
@@ -21,6 +21,7 @@ int *kbuffer_event_size*(struct kbuffer pass:[*]_kbuf_);
 int *kbuffer_curr_size*(struct kbuffer pass:[*]_kbuf_);
 int *kbuffer_curr_offset*(struct kbuffer pass:[*]_kbuf_);
 int *kbuffer_curr_index*(struct kbuffer pass:[*]_kbuf_);
+int *kbuffer_read_buffer*(struct kbuffer pass:[*]_kbuf_, void pass:[*]_buffer_, int _len_);
 --
 
 DESCRIPTION
@@ -64,6 +65,18 @@ The *kbuffer_curr_index()* function returns the index from the beginning of the
 portion of the sub-buffer where the current evnet's meta data is located.
 The first event will likely be zero, but may not be if there's a timestamp attached to it.
 
+The *kbuffer_read_buffer()* function will fill the given _buffer_ from the _kbuf_ the same
+way the kernel would do a read system call. That is, if the length _len_ is less than the
+sub buffer size, or the kbuffer current index is non-zero, it will start copying from the
+_kbuf_ current event and create _buffer_ as a new sub buffer (with a timestamp
+and commit header) with that event that was found and including all events after that can
+fit within _len_. The _len_ must include the size of the sub buffer header as well as the
+events to include. That is, _len_ is the allocate size of _buffer_ that can be filled.
+The return from this function is the index of the end of the last event that was added.
+If there are no more events then zero is returned, and if the buffer can not
+copy any events because _len_ was too small, then -1 is returned.
+
+
 RETURN VALUE
 ------------
 *kbuffer_read_event()* returns the event that the _kbuf_ descriptor is currently at,
@@ -92,6 +105,10 @@ sub-buffer.
 *kbuf_curr_index()* returns the index of the current record from the beginning of the _kbuf_
 data section.
 
+*kbuf_read_buffer()* returns the index of the end of the last event that was filled in
+_buffer_. If there are no more events to copy from _start_ then 0 is returned. If _len_
+is not big enough to hold any events, then -1 is returned.
+
 EXAMPLE
 -------
 [source,c]
diff --git a/Documentation/libtraceevent-page_size.txt b/Documentation/libtraceevent-page_size.txt
index 6d0dd36..18fa5ae 100644
--- a/Documentation/libtraceevent-page_size.txt
+++ b/Documentation/libtraceevent-page_size.txt
@@ -3,7 +3,7 @@ libtraceevent(3)
 
 NAME
 ----
-tep_get_page_size, tep_set_page_size, tep_get_sub_buffer_size - Get / set the size of a memory page on
+tep_get_page_size, tep_set_page_size, tep_get_sub_buffer_data_size, tep_get_sub_buffer_size - Get / set the size of a memory page on
 the machine, where the trace is generated
 
 SYNOPSIS
@@ -15,6 +15,8 @@ SYNOPSIS
 int *tep_get_page_size*(struct tep_handle pass:[*]_tep_);
 void *tep_set_page_size*(struct tep_handle pass:[*]_tep_, int _page_size_);
 int *tep_get_sub_buffer_size*(struct tep_handle pass:[*]_tep_);
+int *tep_get_sub_buffer_data_size*(struct tep_handle pass:[*]_tep_);
+int *tep_get_sub_buffer_commit_offset*(struct tep_handle pass:[*]_tep_);
 --
 
 DESCRIPTION
@@ -32,6 +34,14 @@ The *tep_get_sub_buffer_size()* returns the size of each "sub buffer" of the
 ring buffer. The Linux kernel ring buffer is broken up into sections called
 sub buffers. This returns the size of those buffers.
 
+The *tep_get_sub_buffer_data_size()* returns the size of just the data portion
+of the sub buffers.
+
+The *tep_get_sub_buffer_commit_offset()* returns the offset on the sub buffer
+that holds the committed portion of data. This number contains the index from
+the data portion of the sub buffer that is the end of the last element on the
+sub buffer.
+
 RETURN VALUE
 ------------
 The *tep_get_page_size()* function returns size of the memory page, in bytes.
@@ -39,6 +49,9 @@ The *tep_get_page_size()* function returns size of the memory page, in bytes.
 The *tep_get_sub_buffer_size()* function returns the number of bytes each sub
 buffer is made up of.
 
+The *tep_get_sub_buffer_commit_offset()* function returns the location on the
+sub buffer that contains the index of the last element.
+
 EXAMPLE
 -------
 [source,c]
diff --git a/Documentation/libtraceevent.txt b/Documentation/libtraceevent.txt
index 0502769..9e77772 100644
--- a/Documentation/libtraceevent.txt
+++ b/Documentation/libtraceevent.txt
@@ -27,11 +27,13 @@ Management of tep handler data structure and access of its members:
 	int *tep_get_page_size*(struct tep_handle pass:[*]_tep_);
 	void *tep_set_page_size*(struct tep_handle pass:[*]_tep_, int _page_size_);
 	int *tep_get_sub_buffer_size*(struct tep_handle pass:[*]_tep_);
+	int *tep_get_sub_buffer_data_size*(struct tep_handle pass:[*]_tep_);
+	int *tep_get_sub_buffer_commit_offset*(struct tep_handle pass:[*]_tep_);
 	int *tep_get_header_page_size*(struct tep_handle pass:[*]_tep_);
 	int *tep_get_header_timestamp_size*(struct tep_handle pass:[*]_tep_);
 	bool *tep_is_old_format*(struct tep_handle pass:[*]_tep_);
 	int *tep_strerror*(struct tep_handle pass:[*]_tep_, enum tep_errno _errnum_, char pass:[*]_buf_, size_t _buflen_);
-	struct kbuffer pass:[*]*tep_kbuffer*(struct tep_handle pass:[*]:_tep_);
+	struct kbuffer pass:[*]*tep_kbuffer*(struct tep_handle pass:[*]_tep_);
 
 Register / unregister APIs:
 	int *tep_register_function*(struct tep_handle pass:[*]_tep_, char pass:[*]_name_, unsigned long long _addr_, char pass:[*]_mod_);
@@ -83,6 +85,7 @@ Event finding:
 	struct tep_event pass:[*]*tep_find_event*(struct tep_handle pass:[*]_tep_, int _id_);
 	struct tep_event pass:[*]*tep_find_event_by_name*(struct tep_handle pass:[*]_tep_, const char pass:[*]_sys_, const char pass:[*]_name_);
 	struct tep_event pass:[*]*tep_find_event_by_record*(struct tep_handle pass:[*]_tep_, struct tep_record pass:[*]_record_);
+	bool *tep_record_is_event*(struct tep_record pass:[*]record, struct tep_event pass:[*]event);
 
 Parsing of event files:
 	int *tep_parse_header_page*(struct tep_handle pass:[*]_tep_, char pass:[*]_buf_, unsigned long _size_, int _long_size_);
@@ -179,9 +182,12 @@ Trace sequences:
 kbuffer parsing:
 #include <kbuffer.h>
 	struct kbuffer pass:[*]*kbuffer_alloc*(enum kbuffer_long_size _size_, enum kbuffer_endian _endian_);
+	struct kbuffer pass:[*]*kbuffer_dup*(struct kbuffer pass:[*]_kbuf_);
 	void *kbuffer_free*(struct kbuffer pass:[*]_kbuf_);
 	int *kbuffer_load_subbuffer*(struct kbuffer pass:[*]_kbuf_, void pass:[*]_subbuffer_);
 	int *kbuffer_subbuffer_size*(struct kbuffer pass:[*]_kbuf);
+	void pass:[*]*kbuffer_subbuffer*(struct kbuffer pass:[*]_kbuf);
+	int *kbuffer_refresh*(struct kbuffer pass:[*]_kbuf_);
 	int *kbuffer_start_of_data*(struct kbuffer pass:[*]_kbuf_);
 	unsigned long long *kbuffer_timestamp*(struct kbuffer pass:[*]_kbuf_);
 	unsigned long long *kbuffer_subbuf_timestamp*(struct kbuffer pass:[*]_kbuf_, void pass:[*]_subbuf_);
@@ -193,6 +199,7 @@ kbuffer parsing:
 	int *kbuffer_curr_size*(struct kbuffer pass:[*]_kbuf_);
 	int *kbuffer_curr_offset*(struct kbuffer pass:[*]_kbuf_);
 	int *kbuffer_curr_index*(struct kbuffer pass:[*]_kbuf_);
+	int *kbuffer_read_buffer*(struct kbuffer pass:[*]_kbuf_, void pass:[*]_buffer_, int _start_, int _len_);
 --
 
 DESCRIPTION
diff --git a/Documentation/meson.build b/Documentation/meson.build
new file mode 100644
index 0000000..b0d3a88
--- /dev/null
+++ b/Documentation/meson.build
@@ -0,0 +1,196 @@
+# SPDX-License-Identifier: LGPL-2.1
+#
+# Copyright (c) 2023 Daniel Wagner, SUSE LLC
+
+# input text file: man page section
+sources = {
+    'libtraceevent.txt': '3',
+    'libtraceevent-func_apis.txt': '3',
+    'libtraceevent-commands.txt': '3',
+    'libtraceevent-cpus.txt': '3',
+    'libtraceevent-debug.txt': '3',
+    'libtraceevent-endian_read.txt': '3',
+    'libtraceevent-event_find.txt': '3',
+    'libtraceevent-event_get.txt': '3',
+    'libtraceevent-event_list.txt': '3',
+    'libtraceevent-event_print.txt': '3',
+    'libtraceevent-field_find.txt': '3',
+    'libtraceevent-field_get_val.txt': '3',
+    'libtraceevent-field_print.txt': '3',
+    'libtraceevent-field_read.txt': '3',
+    'libtraceevent-fields.txt': '3',
+    'libtraceevent-file_endian.txt': '3',
+    'libtraceevent-filter.txt': '3',
+    'libtraceevent-func_find.txt': '3',
+    'libtraceevent-handle.txt': '3',
+    'libtraceevent-header_page.txt': '3',
+    'libtraceevent-host_endian.txt': '3',
+    'libtraceevent-kbuffer-create.txt': '3',
+    'libtraceevent-kbuffer-read.txt': '3',
+    'libtraceevent-kbuffer-timestamp.txt': '3',
+    'libtraceevent-kvm-plugin.txt': '3',
+    'libtraceevent-log.txt': '3',
+    'libtraceevent-long_size.txt': '3',
+    'libtraceevent-page_size.txt': '3',
+    'libtraceevent-parse_event.txt': '3',
+    'libtraceevent-parse-files.txt': '3',
+    'libtraceevent-parse_head.txt': '3',
+    'libtraceevent-plugins.txt': '3',
+    'libtraceevent-record_parse.txt': '3',
+    'libtraceevent-reg_event_handler.txt': '3',
+    'libtraceevent-reg_print_func.txt': '3',
+    'libtraceevent-set_flag.txt': '3',
+    'libtraceevent-strerror.txt': '3',
+    'libtraceevent-tseq.txt': '3',
+}
+
+conf_dir = meson.current_source_dir() + '/'
+top_source_dir = meson.current_source_dir() + '/../'
+
+#
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
index 764071d..9e90af6 100644
--- a/METADATA
+++ b/METADATA
@@ -1,19 +1,19 @@
 # This project was upgraded with external_updater.
-# Usage: tools/external_updater/updater.sh update libtraceevent
-# For more info, check https://cs.android.com/android/platform/superproject/+/master:tools/external_updater/README.md
+# Usage: tools/external_updater/updater.sh update external/libtraceevent
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
 name: "libtraceevent"
 description: "libtraceevent is a library that provides APIs to access and configure kernel trace events through the tracefs filesystem."
 third_party {
-  url {
-    type: GIT
-    value: "https://git.kernel.org/pub/scm/libs/libtrace/libtraceevent.git"
-  }
-  version: "libtraceevent-1.7.1"
   license_type: RESTRICTED
   last_upgrade_date {
-    year: 2023
-    month: 1
-    day: 18
+    year: 2024
+    month: 8
+    day: 15
+  }
+  identifier {
+    type: "Git"
+    value: "https://git.kernel.org/pub/scm/libs/libtrace/libtraceevent.git"
+    version: "libtraceevent-1.8.3"
   }
 }
diff --git a/Makefile b/Makefile
index 20d90be..fbb4422 100644
--- a/Makefile
+++ b/Makefile
@@ -1,8 +1,8 @@
 # SPDX-License-Identifier: GPL-2.0
 # libtraceevent version
 EP_VERSION = 1
-EP_PATCHLEVEL = 7
-EP_EXTRAVERSION = 1
+EP_PATCHLEVEL = 8
+EP_EXTRAVERSION = 3
 EVENT_PARSE_VERSION = $(EP_VERSION).$(EP_PATCHLEVEL).$(EP_EXTRAVERSION)
 
 MAKEFLAGS += --no-print-directory
@@ -352,7 +352,7 @@ install_headers:
 
 install: install_libs
 
-clean: clean_plugins clean_src
+clean: clean_plugins clean_src clean_meson
 	$(Q)$(call do_clean,\
 	    $(VERSION_FILE) $(obj)/tags $(obj)/TAGS $(PKG_CONFIG_FILE) \
 	    $(LIBTRACEEVENT_STATIC) $(LIBTRACEEVENT_SHARED) \
@@ -436,6 +436,19 @@ PHONY += clean_src
 clean_src:
 	$(Q)$(call descend_clean,src)
 
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
 force:
 
 # Declare the contents of the .PHONY variable as phony.  We keep that
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
diff --git a/include/traceevent/event-parse.h b/include/traceevent/event-parse.h
index 2171ad7..c03f459 100644
--- a/include/traceevent/event-parse.h
+++ b/include/traceevent/event-parse.h
@@ -554,6 +554,8 @@ struct tep_cmdline *tep_data_pid_from_comm(struct tep_handle *tep, const char *c
 					   struct tep_cmdline *next);
 int tep_cmdline_pid(struct tep_handle *tep, struct tep_cmdline *cmdline);
 
+bool tep_record_is_event(struct tep_record *record, struct tep_event *event);
+
 void tep_print_field_content(struct trace_seq *s, void *data, int size,
 			     struct tep_format_field *field);
 void tep_record_print_fields(struct trace_seq *s,
@@ -586,6 +588,8 @@ int tep_get_long_size(struct tep_handle *tep);
 void tep_set_long_size(struct tep_handle *tep, int long_size);
 int tep_get_page_size(struct tep_handle *tep);
 int tep_get_sub_buffer_size(struct tep_handle *tep);
+int tep_get_sub_buffer_data_size(struct tep_handle *tep);
+int tep_get_sub_buffer_commit_offset(struct tep_handle *tep);
 void tep_set_page_size(struct tep_handle *tep, int _page_size);
 bool tep_is_file_bigendian(struct tep_handle *tep);
 void tep_set_file_bigendian(struct tep_handle *tep, enum tep_endian endian);
diff --git a/include/traceevent/kbuffer.h b/include/traceevent/kbuffer.h
index ca638bc..31a8c62 100644
--- a/include/traceevent/kbuffer.h
+++ b/include/traceevent/kbuffer.h
@@ -31,8 +31,10 @@ enum {
 struct kbuffer;
 
 struct kbuffer *kbuffer_alloc(enum kbuffer_long_size size, enum kbuffer_endian endian);
+struct kbuffer *kbuffer_dup(struct kbuffer *kbuf);
 void kbuffer_free(struct kbuffer *kbuf);
 int kbuffer_load_subbuffer(struct kbuffer *kbuf, void *subbuffer);
+int kbuffer_refresh(struct kbuffer *kbuf);
 void *kbuffer_read_event(struct kbuffer *kbuf, unsigned long long *ts);
 void *kbuffer_next_event(struct kbuffer *kbuf, unsigned long long *ts);
 unsigned long long kbuffer_timestamp(struct kbuffer *kbuf);
@@ -42,6 +44,7 @@ unsigned int kbuffer_ptr_delta(struct kbuffer *kbuf, void *ptr);
 void *kbuffer_translate_data(int swap, void *data, unsigned int *size);
 
 void *kbuffer_read_at_offset(struct kbuffer *kbuf, int offset, unsigned long long *ts);
+int kbuffer_read_buffer(struct kbuffer *kbuf, void *buffer, int len);
 
 int kbuffer_curr_index(struct kbuffer *kbuf);
 
@@ -50,6 +53,7 @@ int kbuffer_curr_size(struct kbuffer *kbuf);
 int kbuffer_event_size(struct kbuffer *kbuf);
 int kbuffer_missed_events(struct kbuffer *kbuf);
 int kbuffer_subbuffer_size(struct kbuffer *kbuf);
+void *kbuffer_subbuffer(struct kbuffer *kbuf);
 
 void kbuffer_set_old_format(struct kbuffer *kbuf);
 int kbuffer_start_of_data(struct kbuffer *kbuf);
diff --git a/include/traceevent/meson.build b/include/traceevent/meson.build
new file mode 100644
index 0000000..d3512ca
--- /dev/null
+++ b/include/traceevent/meson.build
@@ -0,0 +1,14 @@
+# SPDX-License-Identifier: LGPL-2.1
+#
+# Copyright (c) 2023 Daniel Wagner, SUSE LLC
+
+headers = [
+   'event-parse.h',
+   'event-utils.h',
+   'kbuffer.h',
+   'trace-seq.h',
+]
+
+foreach h : headers
+    install_headers(h, subdir : 'traceevent')
+endforeach
diff --git a/meson.build b/meson.build
new file mode 100644
index 0000000..f4aeed1
--- /dev/null
+++ b/meson.build
@@ -0,0 +1,57 @@
+# SPDX-License-Identifier: LGPL-2.1
+#
+# Copyright (c) 2023 Daniel Wagner, SUSE LLC
+
+project(
+    'libtraceevent', ['c'],
+    meson_version: '>= 0.58.0',
+    license: 'LGPL-2.1',
+    version: '1.8.3',
+    default_options: [
+        'c_std=gnu99',
+        'buildtype=debug',
+        'default_library=both',
+        'prefix=/usr/local',
+        'warning_level=1',
+    ])
+
+library_version = meson.project_version()
+
+cunit_dep = dependency('cunit', required : false)
+
+prefixdir = get_option('prefix')
+mandir = join_paths(prefixdir, get_option('mandir'))
+htmldir = join_paths(prefixdir, get_option('htmldir'))
+libdir = join_paths(prefixdir, get_option('libdir'))
+plugindir = get_option('plugindir')
+if plugindir == ''
+    plugindir = join_paths(libdir, 'traceevent/plugins')
+endif
+
+add_project_arguments(
+    [
+        '-D_GNU_SOURCE',
+        '-DPLUGIN_DIR="@0@"'.format(plugindir),
+    ],
+    language : 'c',
+)
+
+incdir = include_directories(['include', 'include/traceevent'])
+
+subdir('src')
+subdir('include/traceevent')
+subdir('plugins')
+if cunit_dep.found()
+    subdir('utest')
+endif
+subdir('samples')
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
index 0000000..9a40dad
--- /dev/null
+++ b/meson_options.txt
@@ -0,0 +1,20 @@
+# SPDX-License-Identifier: LGPL-2.1
+#
+# Copyright (c) 2023 Daniel Wagner, SUSE LLC
+
+option('plugindir', type : 'string',
+       description : 'set the plugin dir')
+option('htmldir', type : 'string', value : 'share/doc/libtraceevent-doc',
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
diff --git a/plugins/dynamic_list.sh b/plugins/dynamic_list.sh
new file mode 100755
index 0000000..66bb0fa
--- /dev/null
+++ b/plugins/dynamic_list.sh
@@ -0,0 +1,11 @@
+#!/bin/sh
+# SPDX-License-Identifier: LGPL-2.1
+
+symbol_type=$(nm -u -D $@ | awk 'NF>1 {print $1}' | xargs echo "U w W" |
+              tr 'w ' 'W\n' | sort -u | xargs echo)
+
+if [ "$symbol_type" = "U W" ]; then
+    echo '{'
+    nm -u -D $@ | awk 'NF>1 {sub("@.*", "", $2); print "\t"$2";"}' | sort -u
+    echo '};'
+fi
diff --git a/plugins/meson.build b/plugins/meson.build
new file mode 100644
index 0000000..4919be4
--- /dev/null
+++ b/plugins/meson.build
@@ -0,0 +1,43 @@
+# SPDX-License-Identifier: LGPL-2.1
+#
+# Copyright (c) 2023 Daniel Wagner, SUSE LLC
+
+plugins = [
+    'plugin_cfg80211.c',
+    'plugin_function.c',
+    'plugin_futex.c',
+    'plugin_hrtimer.c',
+    'plugin_jbd2.c',
+    'plugin_kmem.c',
+    'plugin_kvm.c',
+    'plugin_mac80211.c',
+    'plugin_sched_switch.c',
+    'plugin_scsi.c',
+    'plugin_tlb.c',
+    'plugin_xen.c',
+]
+
+pdeps = []
+foreach plugin : plugins
+    pdeps += shared_module(
+        plugin.replace('.c', ''),
+        plugin,
+        name_prefix: '',
+        dependencies: [libtraceevent_dep],
+        include_directories: [incdir],
+        install: true,
+        install_dir: plugindir)
+endforeach
+
+# perf needs the exported symbol list
+dynamic_list_file = find_program('dynamic_list.sh')
+custom_target(
+    'dynamic_list',
+    depends: pdeps,
+    input: pdeps,
+    output: 'libtraceevent-dynamic-list',
+    command: [dynamic_list_file, '@INPUT@'],
+    capture: true,
+    build_by_default: true,
+    install: true,
+    install_dir: plugindir)
diff --git a/plugins/plugin_sched_switch.c b/plugins/plugin_sched_switch.c
index 8752cae..d00a34b 100644
--- a/plugins/plugin_sched_switch.c
+++ b/plugins/plugin_sched_switch.c
@@ -9,13 +9,143 @@
 #include "event-parse.h"
 #include "trace-seq.h"
 
-static void write_state(struct trace_seq *s, int val)
+/*
+ * prev_state is of size long, which is 32 bits on 32 bit architectures.
+ * As it needs to have the same bits for both 32 bit and 64 bit architectures
+ * we can just assume that the flags we care about will all be within
+ * the 32 bits.
+ */
+#define MAX_STATE_BITS	32
+
+static const char *convert_sym(struct tep_print_flag_sym *sym)
+{
+	static char save_states[MAX_STATE_BITS + 1];
+
+	memset(save_states, 0, sizeof(save_states));
+
+	/* This is the flags for the prev_state_field, now make them into a string */
+	for (; sym; sym = sym->next) {
+		long bitmask = strtoul(sym->value, NULL, 0);
+		int i;
+
+		for (i = 0; !(bitmask & 1); i++)
+			bitmask >>= 1;
+
+		if (i >= MAX_STATE_BITS)
+			continue;
+
+		save_states[i] = sym->str[0];
+	}
+
+	return save_states;
+}
+
+static struct tep_print_arg_field *
+find_arg_field(struct tep_format_field *prev_state_field, struct tep_print_arg *arg)
+{
+	struct tep_print_arg_field *field;
+
+	if (!arg)
+		return NULL;
+
+	if (arg->type == TEP_PRINT_FIELD)
+		return &arg->field;
+
+	if (arg->type == TEP_PRINT_OP) {
+		field = find_arg_field(prev_state_field, arg->op.left);
+		if (field && field->field == prev_state_field)
+			return field;
+		field = find_arg_field(prev_state_field, arg->op.right);
+		if (field && field->field == prev_state_field)
+			return field;
+	}
+	return NULL;
+}
+
+static struct tep_print_flag_sym *
+test_flags(struct tep_format_field *prev_state_field, struct tep_print_arg *arg)
+{
+	struct tep_print_arg_field *field;
+
+	field = find_arg_field(prev_state_field, arg->flags.field);
+	if (!field)
+		return NULL;
+
+	return arg->flags.flags;
+}
+
+static struct tep_print_flag_sym *
+search_op(struct tep_format_field *prev_state_field, struct tep_print_arg *arg)
+{
+	struct tep_print_flag_sym *sym = NULL;
+
+	if (!arg)
+		return NULL;
+
+	if (arg->type == TEP_PRINT_OP) {
+		sym = search_op(prev_state_field, arg->op.left);
+		if (sym)
+			return sym;
+
+		sym = search_op(prev_state_field, arg->op.right);
+		if (sym)
+			return sym;
+	} else if (arg->type == TEP_PRINT_FLAGS) {
+		sym = test_flags(prev_state_field, arg);
+	}
+
+	return sym;
+}
+
+static const char *get_states(struct tep_format_field *prev_state_field)
+{
+	struct tep_print_flag_sym *sym;
+	struct tep_print_arg *arg;
+	struct tep_event *event;
+
+	event = prev_state_field->event;
+
+	/*
+	 * Look at the event format fields, and search for where
+	 * the prev_state is parsed via the format flags.
+	 */
+	for (arg = event->print_fmt.args; arg; arg = arg->next) {
+		/*
+		 * Currently, the __print_flags() for the prev_state
+		 * is embedded in operations, so they too must be
+		 * searched.
+		 */
+		sym = search_op(prev_state_field, arg);
+		if (sym)
+			return convert_sym(sym);
+	}
+	return NULL;
+}
+
+static void write_state(struct trace_seq *s, struct tep_format_field *field,
+			struct tep_record *record)
 {
-	const char states[] = "SDTtZXxW";
+	static struct tep_format_field *prev_state_field;
+	static const char *states;
+	unsigned long long val;
 	int found = 0;
+	int len;
 	int i;
 
-	for (i = 0; i < (sizeof(states) - 1); i++) {
+	if (!field)
+		return;
+
+	if (!states || field != prev_state_field) {
+		states = get_states(field);
+		if (!states)
+			states = "SDTtXZPI";
+		prev_state_field = field;
+	}
+
+	tep_read_number_field(field, record->data, &val);
+
+	len = strlen(states);
+	for (i = 0; i < len; i++) {
 		if (!(val & (1 << i)))
 			continue;
 
@@ -99,8 +229,8 @@ static int sched_switch_handler(struct trace_seq *s,
 	if (tep_get_field_val(s, event, "prev_prio", record, &val, 1) == 0)
 		trace_seq_printf(s, "[%d] ", (int) val);
 
-	if (tep_get_field_val(s,  event, "prev_state", record, &val, 1) == 0)
-		write_state(s, val);
+	field = tep_find_any_field(event, "prev_state");
+	write_state(s, field, record);
 
 	trace_seq_puts(s, " ==> ");
 
diff --git a/samples/meson.build b/samples/meson.build
new file mode 100644
index 0000000..e62ff83
--- /dev/null
+++ b/samples/meson.build
@@ -0,0 +1,9 @@
+# SPDX-License-Identifier: LGPL-2.1
+#
+# Copyright (c) 2023 Daniel Wagner, SUSE LLC
+
+executable(
+    'test-event',
+    ['test-event.c'],
+    dependencies: libtraceevent_dep,
+    include_directories: [incdir])
diff --git a/src/event-parse-api.c b/src/event-parse-api.c
index 268a586..fd03daf 100644
--- a/src/event-parse-api.c
+++ b/src/event-parse-api.c
@@ -262,6 +262,20 @@ void tep_set_page_size(struct tep_handle *tep, int _page_size)
 		tep->page_size = _page_size;
 }
 
+/**
+ * tep_get_sub_buffer_data_size - get the size of the data portion
+ * @tep: The handle to the tep to get the data size from
+ *
+ * Returns the size of the data portion of the sub buffer
+ */
+int tep_get_sub_buffer_data_size(struct tep_handle *tep)
+{
+	if (!tep)
+		return -1;
+
+	return tep->header_page_data_size;
+}
+
 /**
  * tep_get_sub_buffer_size - get the size of a trace buffer page
  * @tep: a handle to the tep_handle
@@ -277,6 +291,21 @@ int tep_get_sub_buffer_size(struct tep_handle *tep)
 	return tep->header_page_data_size + tep->header_page_data_offset;
 }
 
+/**
+ * tep_get_sub_buffer_commit_offset - return offset of the commit location
+ * @tep: the handle to the tep_handle
+ *
+ * Returns the offset of where to find the "commit" field of the offset.
+ * Use tep_get_header_page_size() to find the size of the commit field.
+ */
+int tep_get_sub_buffer_commit_offset(struct tep_handle *tep)
+{
+	if (!tep)
+		return -1;
+
+	return tep->header_page_size_offset;
+}
+
 /**
  * tep_is_file_bigendian - return the endian of the file
  * @tep: a handle to the tep_handle
diff --git a/src/event-parse.c b/src/event-parse.c
index e655087..ba4a153 100644
--- a/src/event-parse.c
+++ b/src/event-parse.c
@@ -1232,9 +1232,11 @@ static enum tep_event_type __read_token(struct tep_handle *tep, char **tok)
 	switch (type) {
 	case TEP_EVENT_NEWLINE:
 	case TEP_EVENT_DELIM:
-		if (asprintf(tok, "%c", ch) < 0)
+		*tok = malloc(2);
+		if (!*tok)
 			return TEP_EVENT_ERROR;
-
+		(*tok)[0] = ch;
+		(*tok)[1] = '\0';
 		return type;
 
 	case TEP_EVENT_OP:
@@ -2195,21 +2197,24 @@ static int set_op_prio(struct tep_print_arg *arg)
 	return arg->op.prio;
 }
 
-static int consolidate_op_arg(struct tep_print_arg *arg)
+static int consolidate_op_arg(enum tep_event_type type, struct tep_print_arg *arg)
 {
 	unsigned long long val, left, right;
 	int ret = 0;
 
+	if (type == TEP_EVENT_ERROR)
+		return -1;
+
 	if (arg->type != TEP_PRINT_OP)
 		return 0;
 
 	if (arg->op.left)
-		ret = consolidate_op_arg(arg->op.left);
+		ret = consolidate_op_arg(type, arg->op.left);
 	if (ret < 0)
 		return ret;
 
 	if (arg->op.right)
-		ret = consolidate_op_arg(arg->op.right);
+		ret = consolidate_op_arg(type, arg->op.right);
 	if (ret < 0)
 		return ret;
 
@@ -2583,7 +2588,7 @@ static int alloc_and_process_delim(struct tep_event *event, char *next_token,
 	if (type == TEP_EVENT_OP) {
 		type = process_op(event, field, &token);
 
-		if (consolidate_op_arg(field) < 0)
+		if (consolidate_op_arg(type, field) < 0)
 			type = TEP_EVENT_ERROR;
 
 		if (type == TEP_EVENT_ERROR)
@@ -2959,7 +2964,7 @@ process_fields(struct tep_event *event, struct tep_print_flag_sym **list, char *
 		free_arg(arg);
 		arg = alloc_arg();
 		if (!arg)
-			goto out_free;
+			goto out_free_field;
 
 		free_token(token);
 		type = process_arg(event, arg, &token);
@@ -3522,7 +3527,7 @@ process_sizeof(struct tep_event *event, struct tep_print_arg *arg, char **tok)
 	struct tep_format_field *field;
 	enum tep_event_type type;
 	char *token = NULL;
-	bool ok = false;
+	bool token_has_paren = false;
 	int ret;
 
 	type = read_token_item(event->tep, &token);
@@ -3537,11 +3542,12 @@ process_sizeof(struct tep_event *event, struct tep_print_arg *arg, char **tok)
 		if (type == TEP_EVENT_ERROR)
 			goto error;
 
+		/* If it's not an item (like "long") then do not process more */
 		if (type != TEP_EVENT_ITEM)
-			ok = true;
+			token_has_paren = true;
 	}
 
-	if (ok || strcmp(token, "int") == 0) {
+	if (token_has_paren || strcmp(token, "int") == 0) {
 		arg->atom.atom = strdup("4");
 
 	} else if (strcmp(token, "long") == 0) {
@@ -3563,7 +3569,7 @@ process_sizeof(struct tep_event *event, struct tep_print_arg *arg, char **tok)
 				goto error;
 			}
 			/* The token is the next token */
-			ok = true;
+			token_has_paren = true;
 		}
 	} else if (strcmp(token, "REC") == 0) {
 
@@ -3586,13 +3592,14 @@ process_sizeof(struct tep_event *event, struct tep_print_arg *arg, char **tok)
 		if (ret < 0)
 			goto error;
 
-	} else if (!ok) {
+	} else {
 		goto error;
 	}
 
-	if (!ok) {
+	if (!token_has_paren) {
+		/* The token contains the last item before the parenthesis */
 		free_token(token);
-		type = read_token_item(event->tep, tok);
+		type = read_token_item(event->tep, &token);
 	}
 	if (test_type_token(type, token,  TEP_EVENT_DELIM, ")"))
 		goto error;
@@ -3730,8 +3737,19 @@ process_arg_token(struct tep_event *event, struct tep_print_arg *arg,
 		arg->atom.atom = atom;
 		break;
 
-	case TEP_EVENT_DQUOTE:
 	case TEP_EVENT_SQUOTE:
+		arg->type = TEP_PRINT_ATOM;
+		/* Make characters into numbers */
+		if (asprintf(&arg->atom.atom, "%d", token[0]) < 0) {
+			free_token(token);
+			*tok = NULL;
+			arg->atom.atom = NULL;
+			return TEP_EVENT_ERROR;
+		}
+		free_token(token);
+		type = read_token_item(event->tep, &token);
+		break;
+	case TEP_EVENT_DQUOTE:
 		arg->type = TEP_PRINT_ATOM;
 		arg->atom.atom = token;
 		type = read_token_item(event->tep, &token);
@@ -3801,7 +3819,7 @@ static int event_read_print_args(struct tep_event *event, struct tep_print_arg *
 			type = process_op(event, arg, &token);
 			free_token(token);
 
-			if (consolidate_op_arg(arg) < 0)
+			if (consolidate_op_arg(type, arg) < 0)
 				type = TEP_EVENT_ERROR;
 
 			if (type == TEP_EVENT_ERROR) {
@@ -5177,10 +5195,9 @@ static struct tep_print_arg *make_bprint_args(char *fmt, void *data, int size, s
 				ls = 2;
 				goto process_again;
 			case '0' ... '9':
-				goto process_again;
 			case '.':
-				goto process_again;
 			case '#':
+			case '+':
 				goto process_again;
 			case 'z':
 			case 'Z':
@@ -6441,6 +6458,7 @@ static int parse_arg_format(struct tep_print_parse **parse,
 		case '.':
 		case '0' ... '9':
 		case '-':
+		case '+':
 			break;
 		case '*':
 			/* The argument is the length. */
@@ -6484,6 +6502,7 @@ static int parse_arg_format(struct tep_print_parse **parse,
 			*arg = (*arg)->next;
 			ret++;
 			return ret;
+		case 'c':
 		case 'd':
 		case 'u':
 		case 'i':
@@ -6869,6 +6888,21 @@ const char *tep_data_comm_from_pid(struct tep_handle *tep, int pid)
 	return comm;
 }
 
+/**
+ * tep_record_is_event - return true if the given record is the given event
+ * @record: The record to see is the @event
+ * @event: The event to test against @record
+ *
+ * Returns true if the record is of the given event, false otherwise
+ */
+bool tep_record_is_event(struct tep_record *record, struct tep_event *event)
+{
+	int type;
+
+	type = tep_data_type(event->tep, record);
+	return event->id == type;
+}
+
 static struct tep_cmdline *
 pid_from_cmdlist(struct tep_handle *tep, const char *comm, struct tep_cmdline *next)
 {
diff --git a/src/event-plugin.c b/src/event-plugin.c
index f42243f..c944204 100644
--- a/src/event-plugin.c
+++ b/src/event-plugin.c
@@ -327,7 +327,7 @@ int tep_plugin_add_option(const char *name, const char *val)
 		return -ENOMEM;
 
 	if (parse_option_name(&option_str, &plugin) < 0)
-		return -ENOMEM;
+		goto out_free;
 
 	/* If the option exists, update the val */
 	for (op = trace_plugin_options; op; op = op->next) {
@@ -474,7 +474,7 @@ load_plugin(struct tep_handle *tep, const char *path,
 		while (options->name) {
 			ret = update_option(alias, options);
 			if (ret < 0)
-				goto out_free;
+				goto out_close;
 			options++;
 		}
 	}
@@ -483,13 +483,13 @@ load_plugin(struct tep_handle *tep, const char *path,
 	if (!func) {
 		tep_warning("could not find func '%s' in plugin '%s'\n%s\n",
 			    TEP_PLUGIN_LOADER_NAME, plugin, dlerror());
-		goto out_free;
+		goto out_close;
 	}
 
 	list = malloc(sizeof(*list));
 	if (!list) {
 		tep_warning("could not allocate plugin memory\n");
-		goto out_free;
+		goto out_close;
 	}
 
 	list->next = *plugin_list;
@@ -501,6 +501,8 @@ load_plugin(struct tep_handle *tep, const char *path,
 	func(tep);
 	return;
 
+out_close:
+	dlclose(handle);
  out_free:
 	free(plugin);
 }
diff --git a/src/kbuffer-parse.c b/src/kbuffer-parse.c
index 390a789..9b72780 100644
--- a/src/kbuffer-parse.c
+++ b/src/kbuffer-parse.c
@@ -86,6 +86,42 @@ static int do_swap(struct kbuffer *kbuf)
 		ENDIAN_MASK;
 }
 
+static unsigned long long swap_8(unsigned long data)
+{
+	return ((data & 0xffULL) << 56) |
+		((data & (0xffULL << 8)) << 40) |
+		((data & (0xffULL << 16)) << 24) |
+		((data & (0xffULL << 24)) << 8) |
+		((data & (0xffULL << 32)) >> 8) |
+		((data & (0xffULL << 40)) >> 24) |
+		((data & (0xffULL << 48)) >> 40) |
+		((data & (0xffULL << 56)) >> 56);
+}
+
+static unsigned int swap_4(unsigned int data)
+{
+	return ((data & 0xffULL) << 24) |
+		((data & (0xffULL << 8)) << 8) |
+		((data & (0xffULL << 16)) >> 8) |
+		((data & (0xffULL << 24)) >> 24);
+}
+
+static void write_8(bool do_swap, void *ptr, unsigned long long data)
+{
+	if (do_swap)
+		*(unsigned long long *)ptr = swap_8(data);
+	else
+		*(unsigned long long *)ptr = data;
+}
+
+static void write_4(bool do_swap, void *ptr, unsigned int data)
+{
+	if (do_swap)
+		*(unsigned int *)ptr = swap_4(data);
+	else
+		*(unsigned int *)ptr = data;
+}
+
 static unsigned long long __read_8(void *ptr)
 {
 	unsigned long long data = *(unsigned long long *)ptr;
@@ -96,18 +132,8 @@ static unsigned long long __read_8(void *ptr)
 static unsigned long long __read_8_sw(void *ptr)
 {
 	unsigned long long data = *(unsigned long long *)ptr;
-	unsigned long long swap;
-
-	swap = ((data & 0xffULL) << 56) |
-		((data & (0xffULL << 8)) << 40) |
-		((data & (0xffULL << 16)) << 24) |
-		((data & (0xffULL << 24)) << 8) |
-		((data & (0xffULL << 32)) >> 8) |
-		((data & (0xffULL << 40)) >> 24) |
-		((data & (0xffULL << 48)) >> 40) |
-		((data & (0xffULL << 56)) >> 56);
 
-	return swap;
+	return swap_8(data);
 }
 
 static unsigned int __read_4(void *ptr)
@@ -120,14 +146,8 @@ static unsigned int __read_4(void *ptr)
 static unsigned int __read_4_sw(void *ptr)
 {
 	unsigned int data = *(unsigned int *)ptr;
-	unsigned int swap;
-
-	swap = ((data & 0xffULL) << 24) |
-		((data & (0xffULL << 8)) << 8) |
-		((data & (0xffULL << 16)) >> 8) |
-		((data & (0xffULL << 24)) >> 24);
 
-	return swap;
+	return swap_4(data);
 }
 
 static unsigned long long read_8(struct kbuffer *kbuf, void *ptr)
@@ -160,6 +180,7 @@ static int calc_index(struct kbuffer *kbuf, void *ptr)
 	return (unsigned long)ptr - (unsigned long)kbuf->data;
 }
 
+static int next_event(struct kbuffer *kbuf);
 static int __next_event(struct kbuffer *kbuf);
 
 /*
@@ -249,6 +270,26 @@ kbuffer_alloc(enum kbuffer_long_size size, enum kbuffer_endian endian)
 	return kbuf;
 }
 
+/**
+ * kbuffer_dup - duplicate a given kbuffer
+ * @kbuf_orig; The kbuffer to duplicate
+ *
+ * Allocates a new kbuffer based off of anothe kbuffer.
+ * Returns the duplicate on success or NULL on error.
+ */
+struct kbuffer *kbuffer_dup(struct kbuffer *kbuf_orig)
+{
+	struct kbuffer *kbuf;
+
+	kbuf = malloc(sizeof(*kbuf));
+	if (!kbuf)
+		return NULL;
+
+	*kbuf = *kbuf_orig;
+
+	return kbuf;
+}
+
 /** kbuffer_free - free an allocated kbuffer
  * @kbuf:	The kbuffer to free
  *
@@ -259,6 +300,33 @@ void kbuffer_free(struct kbuffer *kbuf)
 	free(kbuf);
 }
 
+/**
+ * kbuffer_refresh - update the meta data from the subbuffer
+ * @kbuf; The kbuffer to update
+ *
+ * If the loaded subbuffer changed its meta data (the commit)
+ * then update the pointers for it.
+ */
+int kbuffer_refresh(struct kbuffer *kbuf)
+{
+	unsigned long long flags;
+	unsigned int old_size;
+
+	if (!kbuf || !kbuf->subbuffer)
+		return -1;
+
+	old_size = kbuf->size;
+
+	flags = read_long(kbuf, kbuf->subbuffer + 8);
+	kbuf->size = (unsigned int)flags & COMMIT_MASK;
+
+	/* Update next to be the next element */
+	if (kbuf->size != old_size && kbuf->curr == kbuf->next)
+		next_event(kbuf);
+
+	return 0;
+}
+
 static unsigned int type4host(struct kbuffer *kbuf,
 			      unsigned int type_len_ts)
 {
@@ -295,6 +363,13 @@ static unsigned int ts4host(struct kbuffer *kbuf,
 		return type_len_ts >> 5;
 }
 
+static void set_curr_to_end(struct kbuffer *kbuf)
+{
+	kbuf->curr = kbuf->size;
+	kbuf->next = kbuf->size;
+	kbuf->index = kbuf->size;
+}
+
 /*
  * Linux 2.6.30 and earlier (not much ealier) had a different
  * ring buffer format. It should be obsolete, but we handle it anyway.
@@ -339,9 +414,7 @@ static unsigned int old_update_pointers(struct kbuffer *kbuf)
 
 	case OLD_RINGBUF_TYPE_TIME_STAMP:
 		/* should never happen! */
-		kbuf->curr = kbuf->size;
-		kbuf->next = kbuf->size;
-		kbuf->index = kbuf->size;
+		set_curr_to_end(kbuf);
 		return -1;
 	default:
 		if (len)
@@ -702,6 +775,17 @@ int kbuffer_subbuffer_size(struct kbuffer *kbuf)
 	return kbuf->size;
 }
 
+/**
+ * kbuffer_subbuffer - the currently loaded subbuffer
+ * @kbuf:	The kbuffer to read from
+ *
+ * Returns the currently loaded subbuffer.
+ */
+void *kbuffer_subbuffer(struct kbuffer *kbuf)
+{
+	return kbuf->subbuffer;
+}
+
 /**
  * kbuffer_curr_index - Return the index of the record
  * @kbuf:	The kbuffer to read from
@@ -846,3 +930,90 @@ kbuffer_raw_get(struct kbuffer *kbuf, void *subbuf, struct kbuffer_raw_info *inf
 
 	return info;
 }
+
+/**
+ * kbuffer_read_buffer - read a buffer like the kernel would perform a read
+ * @kbuf: the kbuffer handle
+ * @buffer: where to write the data into
+ * @len; The length of @buffer
+ *
+ * This will read the saved sub buffer within @kbuf like the systemcall
+ * of read() to the trace_pipe_raw would do. That is, if either @len
+ * can not fit the entire buffer, or if the current index in @kbuf
+ * is non-zero, it will write to @buffer a new subbuffer that could be
+ * loaded into kbuffer_load_subbuffer(). That is, it will write into
+ * @buffer a  legitimate sub-buffer with a header and all that has the
+ * proper timestamp and commit fields.
+ *
+ * Returns the index after the last element written.
+ * 0 if nothing was copied.
+ * -1 on error (which includes not having enough space in len to
+ *   copy the subbuffer header or any of its content. In otherwords,
+ *   do not try again!
+ *
+ * @kbuf current index will be set to the next element to read.
+ */
+int kbuffer_read_buffer(struct kbuffer *kbuf, void *buffer, int len)
+{
+	unsigned long long ts;
+	unsigned int type_len_ts;
+	bool do_swap = false;
+	int last_next;
+	int save_curr;
+
+	/* Are we at the end of the buffer */
+	if (kbuf->curr >= kbuf->size)
+		return 0;
+
+	/* If we can not copy anyting, return -1 */
+	if (len < kbuf->start)
+		return -1;
+
+	/* Check if the first event can fit */
+	if (len < (kbuf->next - kbuf->curr) + kbuf->start)
+		return -1;
+
+	if (kbuf->read_8 ==  __read_8_sw)
+		do_swap = true;
+
+	/* Have this subbuffer timestamp be the current timestamp */
+	write_8(do_swap, buffer, kbuf->timestamp);
+
+	len -= kbuf->start;
+
+	save_curr = kbuf->curr;
+
+	/* Due to timestamps, we must save the current next to use */
+	last_next = kbuf->next;
+
+	while (len >= kbuf->next - save_curr) {
+		last_next = kbuf->next;
+		if (!kbuffer_next_event(kbuf, &ts))
+			break;
+	}
+
+	len = last_next - save_curr;
+	/* No event was found? */
+	if (!len)
+		return 0;
+
+	memcpy(buffer + kbuf->start, kbuf->data + save_curr, len);
+
+	/* Zero out the delta, as the sub-buffer has the timestamp */
+	type_len_ts = read_4(kbuf, buffer + kbuf->start);
+
+	if (kbuf->flags & KBUFFER_FL_BIG_ENDIAN)
+		type_len_ts &= ~(((1 << 27) - 1));
+	else
+		type_len_ts &= ((1 << 5) - 1);
+
+	write_4(do_swap, buffer + kbuf->start, type_len_ts);
+
+	/* Update the size */
+	if (kbuf->read_long == __read_long_8)
+		write_8(do_swap, buffer + 8, len);
+	else
+		write_4(do_swap, buffer + 8, len);
+
+	return last_next;
+}
diff --git a/src/meson.build b/src/meson.build
new file mode 100644
index 0000000..cd48de7
--- /dev/null
+++ b/src/meson.build
@@ -0,0 +1,39 @@
+# SPDX-License-Identifier: LGPL-2.1
+#
+# Copyright (c) 2023 Daniel Wagner, SUSE LLC
+
+sources= [
+   'event-parse-api.c',
+   'event-parse.c',
+   'event-plugin.c',
+   'kbuffer-parse.c',
+   'parse-filter.c',
+   'parse-utils.c',
+   'tep_strerror.c',
+   'trace-seq.c',
+]
+
+cc = meson.get_compiler('c')
+dl_dep = cc.find_library('dl')
+
+libtraceevent = library(
+    'traceevent',
+    sources,
+    version: library_version,
+    dependencies: [dl_dep],
+    include_directories: [incdir],
+    install: true)
+
+pkg = import('pkgconfig')
+pkg.generate(
+    libtraceevent,
+    subdirs: 'traceevent',
+    filebase: meson.project_name(),
+    name: meson.project_name(),
+    version: meson.project_version(),
+    description: 'Manage trace event',
+    url: 'https://git.kernel.org/pub/scm/libs/libtrace/libtraceevent.git/')
+
+libtraceevent_dep = declare_dependency(
+    include_directories: ['.'],
+    link_with: libtraceevent)
diff --git a/src/parse-filter.c b/src/parse-filter.c
index e448ee2..75b84a0 100644
--- a/src/parse-filter.c
+++ b/src/parse-filter.c
@@ -1704,8 +1704,8 @@ static const char *get_field_str(struct tep_filter_arg *arg, struct tep_record *
 	struct tep_handle *tep;
 	unsigned long long addr;
 	const char *val = NULL;
+	static char hex[64];
 	unsigned int size;
-	char hex[64];
 
 	/* If the field is not a string convert it */
 	if (arg->str.field->flags & TEP_FIELD_IS_STRING) {
diff --git a/src/parse-utils.c b/src/parse-utils.c
index 9c38e1e..b434e24 100644
--- a/src/parse-utils.c
+++ b/src/parse-utils.c
@@ -137,6 +137,11 @@ struct kbuffer *tep_kbuffer(struct tep_handle *tep)
 	int long_size;
 
 	long_size = tep_get_long_size(tep);
+
+	/* If the long_size is not set, then use the commit size */
+	if (!long_size)
+		long_size = tep_get_header_page_size(tep);
+
 	if (long_size == 8)
 		long_size = KBUFFER_LSIZE_8;
 	else
diff --git a/utest/meson.build b/utest/meson.build
new file mode 100644
index 0000000..d819a6c
--- /dev/null
+++ b/utest/meson.build
@@ -0,0 +1,16 @@
+# SPDX-License-Identifier: LGPL-2.1
+#
+# Copyright (c) 2023 Daniel Wagner, SUSE LLC
+
+source = [
+    'trace-utest.c',
+    'traceevent-utest.c',
+]
+
+e = executable(
+   'trace-utest',
+   source,
+   include_directories: [incdir],
+   dependencies: [libtraceevent_dep, cunit_dep])
+
+test('trace-utest', e)
diff --git a/utest/trace-utest.c b/utest/trace-utest.c
index 1403c86..7c4b9b6 100644
--- a/utest/trace-utest.c
+++ b/utest/trace-utest.c
@@ -6,6 +6,7 @@
  *   Copyright (C) 2021, VMware, Steven Rostedt <rostedt@goodmis.org>
  *
  */
+#include <libgen.h>
 #include <stdio.h>
 #include <unistd.h>
 #include <getopt.h>
@@ -36,6 +37,7 @@ int main(int argc, char **argv)
 {
 	CU_BasicRunMode verbose = CU_BRM_VERBOSE;
 	enum unit_tests tests = RUN_NONE;
+	int failed_tests;
 
 	for (;;) {
 		int c;
@@ -81,6 +83,7 @@ int main(int argc, char **argv)
 
 	CU_basic_set_mode(verbose);
 	CU_basic_run_tests();
+	failed_tests = CU_get_number_of_tests_failed();
 	CU_cleanup_registry();
-	return 0;
+	return failed_tests != 0;
 }
diff --git a/utest/traceevent-utest.c b/utest/traceevent-utest.c
index ebd5eb9..b95e478 100644
--- a/utest/traceevent-utest.c
+++ b/utest/traceevent-utest.c
@@ -45,7 +45,7 @@ static char dyn_str_data[] = {
 #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
 	/* common type */		1, 0x00,
 #else
-	/* common type */		0x00, 1
+	/* common type */		0x00, 1,
 #endif
 	/* common flags */		0x00,
 	/* common_preempt_count */	0x00,
@@ -82,7 +82,7 @@ static char dyn_str_old_data[] = {
 #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
 	/* common type */		2, 0x00,
 #else
-	/* common type */		0x00, 2
+	/* common type */		0x00, 2,
 #endif
 	/* common flags */		0x00,
 	/* common_preempt_count */	0x00,
@@ -166,7 +166,7 @@ static char sizeof_data[] = {
 #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
 	/* common type */		23, 0x00,
 #else
-	/* common type */		0x00, 23
+	/* common type */		0x00, 23,
 #endif
 	/* common flags */		0x00,
 	/* common_preempt_count */	0x00,
@@ -216,7 +216,7 @@ DECL_CPUMASK_EVENT_DATA(bytep2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x01);
 #define CPUMASK_BYTEP2_FMT "cpumask=0,23"
 
 DECL_CPUMASK_EVENT_DATA(bytepn, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01);
-#define CPUMASK_BYTEPN     "ARRAY[80, 00, 00, 00, 00, 00, 80, 01]"
+#define CPUMASK_BYTEPN     "ARRAY[80, 00, 00, 00, 00, 00, 00, 01]"
 #define CPUMASK_BYTEPN_FMT "cpumask=0,63"
 #endif
 
@@ -392,6 +392,9 @@ static int test_suite_init(void)
 	test_tep = tep_alloc();
 	if (!test_tep)
 		return 1;
+#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
+	tep_set_file_bigendian(test_tep, TEP_BIG_ENDIAN);
+#endif
 	return 0;
 }
 
```

