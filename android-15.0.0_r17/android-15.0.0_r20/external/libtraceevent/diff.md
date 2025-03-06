```diff
diff --git a/METADATA b/METADATA
index 9e90af6..5d419b3 100644
--- a/METADATA
+++ b/METADATA
@@ -8,12 +8,12 @@ third_party {
   license_type: RESTRICTED
   last_upgrade_date {
     year: 2024
-    month: 8
-    day: 15
+    month: 12
+    day: 3
   }
   identifier {
     type: "Git"
     value: "https://git.kernel.org/pub/scm/libs/libtrace/libtraceevent.git"
-    version: "libtraceevent-1.8.3"
+    version: "libtraceevent-1.8.4"
   }
 }
diff --git a/Makefile b/Makefile
index fbb4422..5f3e372 100644
--- a/Makefile
+++ b/Makefile
@@ -2,7 +2,7 @@
 # libtraceevent version
 EP_VERSION = 1
 EP_PATCHLEVEL = 8
-EP_EXTRAVERSION = 3
+EP_EXTRAVERSION = 4
 EVENT_PARSE_VERSION = $(EP_VERSION).$(EP_PATCHLEVEL).$(EP_EXTRAVERSION)
 
 MAKEFLAGS += --no-print-directory
diff --git a/meson.build b/meson.build
index f4aeed1..24c0605 100644
--- a/meson.build
+++ b/meson.build
@@ -6,7 +6,7 @@ project(
     'libtraceevent', ['c'],
     meson_version: '>= 0.58.0',
     license: 'LGPL-2.1',
-    version: '1.8.3',
+    version: '1.8.4',
     default_options: [
         'c_std=gnu99',
         'buildtype=debug',
diff --git a/src/event-parse.c b/src/event-parse.c
index ba4a153..0427061 100644
--- a/src/event-parse.c
+++ b/src/event-parse.c
@@ -3571,6 +3571,23 @@ process_sizeof(struct tep_event *event, struct tep_print_arg *arg, char **tok)
 			/* The token is the next token */
 			token_has_paren = true;
 		}
+
+	} else if (strcmp(token, "__u64") == 0 || strcmp(token, "u64") == 0 ||
+		   strcmp(token, "__s64") == 0 || strcmp(token, "s64") == 0) {
+		arg->atom.atom = strdup("8");
+
+	} else if (strcmp(token, "__u32") == 0 || strcmp(token, "u32") == 0 ||
+		   strcmp(token, "__s32") == 0 || strcmp(token, "s32") == 0) {
+		arg->atom.atom = strdup("4");
+
+	} else if (strcmp(token, "__u16") == 0 || strcmp(token, "u16") == 0 ||
+		   strcmp(token, "__s16") == 0 || strcmp(token, "s16") == 0) {
+		arg->atom.atom = strdup("2");
+
+	} else if (strcmp(token, "__u8") == 0 || strcmp(token, "u8") == 0 ||
+		   strcmp(token, "__8") == 0 || strcmp(token, "s8") == 0) {
+		arg->atom.atom = strdup("1");
+
 	} else if (strcmp(token, "REC") == 0) {
 
 		free_token(token);
@@ -4938,18 +4955,19 @@ static void print_str_arg(struct trace_seq *s, void *data, int size,
 		len = eval_num_arg(data, size, event, arg->int_array.count);
 		el_size = eval_num_arg(data, size, event,
 				       arg->int_array.el_size);
+		trace_seq_putc(s, '{');
 		for (i = 0; i < len; i++) {
 			if (i)
-				trace_seq_putc(s, ' ');
+				trace_seq_putc(s, ',');
 
 			if (el_size == 1) {
-				trace_seq_printf(s, "%u", *(uint8_t *)num);
+				trace_seq_printf(s, "0x%x", *(uint8_t *)num);
 			} else if (el_size == 2) {
-				trace_seq_printf(s, "%u", *(uint16_t *)num);
+				trace_seq_printf(s, "0x%x", *(uint16_t *)num);
 			} else if (el_size == 4) {
-				trace_seq_printf(s, "%u", *(uint32_t *)num);
+				trace_seq_printf(s, "0x%x", *(uint32_t *)num);
 			} else if (el_size == 8) {
-				trace_seq_printf(s, "%"PRIu64, *(uint64_t *)num);
+				trace_seq_printf(s, "0x%"PRIx64, *(uint64_t *)num);
 			} else {
 				trace_seq_printf(s, "BAD SIZE:%d 0x%x",
 						 el_size, *(uint8_t *)num);
@@ -4958,6 +4976,7 @@ static void print_str_arg(struct trace_seq *s, void *data, int size,
 
 			num += el_size;
 		}
+		trace_seq_putc(s, '}');
 		break;
 	}
 	case TEP_PRINT_TYPE:
@@ -6001,11 +6020,11 @@ static void print_field_raw(struct trace_seq *s, void *data, int size,
 }
 
 static int print_parse_data(struct tep_print_parse *parse, struct trace_seq *s,
-			    void *data, int size, struct tep_event *event);
+			    void *data, int size, struct tep_event *event, bool raw);
 
 static inline void print_field(struct trace_seq *s, void *data, int size,
 				    struct tep_format_field *field,
-				    struct tep_print_parse **parse_ptr)
+				    struct tep_print_parse **parse_ptr, bool raw)
 {
 	struct tep_event *event = field->event;
 	struct tep_print_parse *start_parse;
@@ -6049,7 +6068,7 @@ static inline void print_field(struct trace_seq *s, void *data, int size,
 		if (has_0x)
 			trace_seq_puts(s, "0x");
 
-		print_parse_data(parse, s, data, size, event);
+		print_parse_data(parse, s, data, size, event, raw);
 
 		if (parse_ptr)
 			*parse_ptr = parse->next;
@@ -6081,7 +6100,7 @@ static inline void print_field(struct trace_seq *s, void *data, int size,
 void tep_print_field_content(struct trace_seq *s, void *data, int size,
 			     struct tep_format_field *field)
 {
-	print_field(s, data, size, field, NULL);
+	print_field(s, data, size, field, NULL, false);
 }
 
 /** DEPRECATED **/
@@ -6089,13 +6108,13 @@ void tep_print_field(struct trace_seq *s, void *data,
 		     struct tep_format_field *field)
 {
 	/* unsafe to use, should pass in size */
-	print_field(s, data, 4096, field, NULL);
+	print_field(s, data, 4096, field, NULL, false);
 }
 
 static inline void
 print_selected_fields(struct trace_seq *s, void *data, int size,
 		      struct tep_event *event,
-		      unsigned long long ignore_mask)
+		      unsigned long long ignore_mask, bool raw)
 {
 	struct tep_print_parse *parse = event->print_fmt.print_cache;
 	struct tep_format_field *field;
@@ -6107,14 +6126,14 @@ print_selected_fields(struct trace_seq *s, void *data, int size,
 			continue;
 
 		trace_seq_printf(s, " %s=", field->name);
-		print_field(s, data, size, field, &parse);
+		print_field(s, data, size, field, &parse, raw);
 	}
 }
 
 void tep_print_fields(struct trace_seq *s, void *data,
 		      int size, struct tep_event *event)
 {
-	print_selected_fields(s, data, size, event, 0);
+	print_selected_fields(s, data, size, event, 0, false);
 }
 
 /**
@@ -6128,7 +6147,7 @@ void tep_record_print_fields(struct trace_seq *s,
 			     struct tep_record *record,
 			     struct tep_event *event)
 {
-	print_selected_fields(s, record->data, record->size, event, 0);
+	print_selected_fields(s, record->data, record->size, event, 0, false);
 }
 
 /**
@@ -6146,12 +6165,12 @@ void tep_record_print_selected_fields(struct trace_seq *s,
 {
 	unsigned long long ignore_mask = ~select_mask;
 
-	print_selected_fields(s, record->data, record->size, event, ignore_mask);
+	print_selected_fields(s, record->data, record->size, event, ignore_mask, false);
 }
 
 static int print_function(struct trace_seq *s, const char *format,
 			  void *data, int size, struct tep_event *event,
-			  struct tep_print_arg *arg)
+			  struct tep_print_arg *arg, bool raw)
 {
 	struct func_map *func;
 	unsigned long long val;
@@ -6162,11 +6181,17 @@ static int print_function(struct trace_seq *s, const char *format,
 		trace_seq_puts(s, func->func);
 		if (*format == 'F' || *format == 'S')
 			trace_seq_printf(s, "+0x%llx", val - func->addr);
-	} else {
+	}
+
+	if (!func || raw) {
+		if (raw)
+			trace_seq_puts(s, " (");
 		if (event->tep->long_size == 4)
 			trace_seq_printf(s, "0x%lx", (long)val);
 		else
 			trace_seq_printf(s, "0x%llx", (long long)val);
+		if (raw)
+			trace_seq_puts(s, ")");
 	}
 
 	return 0;
@@ -6174,7 +6199,8 @@ static int print_function(struct trace_seq *s, const char *format,
 
 static int print_arg_pointer(struct trace_seq *s, const char *format, int plen,
 			     void *data, int size,
-			     struct tep_event *event, struct tep_print_arg *arg)
+			     struct tep_event *event, struct tep_print_arg *arg,
+			     bool raw)
 {
 	unsigned long long val;
 	int ret = 1;
@@ -6196,7 +6222,7 @@ static int print_arg_pointer(struct trace_seq *s, const char *format, int plen,
 	case 'f':
 	case 'S':
 	case 's':
-		ret += print_function(s, format, data, size, event, arg);
+		ret += print_function(s, format, data, size, event, arg, raw);
 		break;
 	case 'M':
 	case 'm':
@@ -6660,7 +6686,7 @@ parse_args(struct tep_event *event, const char *format, struct tep_print_arg *ar
 }
 
 static int print_parse_data(struct tep_print_parse *parse, struct trace_seq *s,
-			    void *data, int size, struct tep_event *event)
+			    void *data, int size, struct tep_event *event, bool raw)
 {
 	int len_arg;
 
@@ -6676,7 +6702,7 @@ static int print_parse_data(struct tep_print_parse *parse, struct trace_seq *s,
 	case PRINT_FMT_ARG_POINTER:
 		print_arg_pointer(s, parse->format,
 				  parse->len_as_arg ? len_arg : 1,
-				  data, size, event, parse->arg);
+				  data, size, event, parse->arg, raw);
 		break;
 	case PRINT_FMT_ARG_STRING:
 		print_arg_string(s, parse->format,
@@ -6697,7 +6723,7 @@ static void print_event_cache(struct tep_print_parse *parse, struct trace_seq *s
 			      void *data, int size, struct tep_event *event)
 {
 	while (parse) {
-		print_parse_data(parse, s, data, size, event);
+		print_parse_data(parse, s, data, size, event, false);
 		parse = parse->next;
 	}
 }
@@ -7004,7 +7030,7 @@ static void print_event_info(struct trace_seq *s, char *format, bool raw,
 	int print_pretty = 1;
 
 	if (raw || (event->flags & TEP_EVENT_FL_PRINTRAW))
-		tep_print_fields(s, record->data, record->size, event);
+		print_selected_fields(s, record->data, record->size, event, 0, true);
 	else {
 
 		if (event->handler && !(event->flags & TEP_EVENT_FL_NOHANDLE))
```

