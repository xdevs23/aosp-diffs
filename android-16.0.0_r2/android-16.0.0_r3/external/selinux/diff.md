```diff
diff --git a/checkpolicy/checkmodule.8 b/checkpolicy/checkmodule.8
index 93c9b537..519d6c34 100644
--- a/checkpolicy/checkmodule.8
+++ b/checkpolicy/checkmodule.8
@@ -3,7 +3,7 @@
 checkmodule \- SELinux policy module compiler
 .SH SYNOPSIS
 .B checkmodule
-.I "[\-h] [\-b] [\-c policy_version] [\-C] [\-E] [\-m] [\-M] [\-N] [\-U handle_unknown] [\-V] [\-o output_file] [input_file]"
+.I "[\-h] [\-b] [\-c policy_version] [\-C] [\-E] [\-m] [\-M] [\-N] [\-L] [\-U handle_unknown] [\-V] [\-o output_file] [input_file]"
 .SH "DESCRIPTION"
 This manual page describes the
 .BR checkmodule
@@ -46,6 +46,11 @@ Enable the MLS/MCS support when checking and compiling the policy module.
 .B \-N,\-\-disable-neverallow
 Do not check neverallow rules.
 .TP
+.B \-L,\-\-line-marker-for-allow
+Output line markers for allow rules, in addition to neverallow rules. This option increases the size
+of the output CIL policy file, but the additional line markers helps debugging, especially
+neverallow failure reports. Can only be used when writing a CIL policy file.
+.TP
 .B \-V,\-\-version
 Show policy versions created by this program.
 .TP
diff --git a/checkpolicy/checkmodule.c b/checkpolicy/checkmodule.c
index 2d6f2399..c9ff80cc 100644
--- a/checkpolicy/checkmodule.c
+++ b/checkpolicy/checkmodule.c
@@ -119,7 +119,7 @@ static int write_binary_policy(policydb_t * p, FILE *outfp, unsigned int policy_
 
 static __attribute__((__noreturn__)) void usage(const char *progname)
 {
-	printf("usage:  %s [-h] [-V] [-b] [-C] [-E] [-U handle_unknown] [-m] [-M] [-N] [-o FILE] [-c VERSION] [INPUT]\n", progname);
+	printf("usage:  %s [-h] [-V] [-b] [-C] [-E] [-U handle_unknown] [-m] [-M] [-N] [-L] [-o FILE] [-c VERSION] [INPUT]\n", progname);
 	printf("Build base and policy modules.\n");
 	printf("Options:\n");
 	printf("  INPUT      build module from INPUT (else read from \"%s\")\n",
@@ -136,6 +136,7 @@ static __attribute__((__noreturn__)) void usage(const char *progname)
 	printf("  -m         build a policy module instead of a base module\n");
 	printf("  -M         enable MLS policy\n");
 	printf("  -N         do not check neverallow rules\n");
+	printf("  -L         output line markers for allow rules\n");
 	printf("  -o FILE    write module to FILE (else just check syntax)\n");
 	printf("  -c VERSION build a policy module targeting a modular policy version (%d-%d)\n",
 	       MOD_POLICYDB_VERSION_MIN, MOD_POLICYDB_VERSION_MAX);
@@ -146,6 +147,7 @@ int main(int argc, char **argv)
 {
 	const char *file = txtfile, *outfile = NULL;
 	unsigned int binary = 0, cil = 0, disable_neverallow = 0;
+	unsigned int line_marker_for_allow = 0;
 	unsigned int policy_type = POLICY_BASE;
 	unsigned int policyvers = MOD_POLICYDB_VERSION_MAX;
 	int ch;
@@ -159,12 +161,13 @@ int main(int argc, char **argv)
 		{"handle-unknown", required_argument, NULL, 'U'},
 		{"mls", no_argument, NULL, 'M'},
 		{"disable-neverallow", no_argument, NULL, 'N'},
+		{"line-marker-for-allow", no_argument, NULL, 'L'},
 		{"cil", no_argument, NULL, 'C'},
 		{"werror", no_argument, NULL, 'E'},
 		{NULL, 0, NULL, 0}
 	};
 
-	while ((ch = getopt_long(argc, argv, "ho:bVEU:mMNCc:", long_options, NULL)) != -1) {
+	while ((ch = getopt_long(argc, argv, "ho:bVEU:mMNCc:L", long_options, NULL)) != -1) {
 		switch (ch) {
 		case 'h':
 			usage(argv[0]);
@@ -231,6 +234,9 @@ int main(int argc, char **argv)
 			policyvers = n;
 			break;
 		}
+		case 'L':
+			line_marker_for_allow = 1;
+			break;
 		default:
 			usage(argv[0]);
 		}
@@ -252,6 +258,11 @@ int main(int argc, char **argv)
 		exit(1);
 	}
 
+	if (line_marker_for_allow && !cil) {
+		fprintf(stderr, "%s:  -L must be used along with -C.\n", argv[0]);
+		exit(1);
+	}
+
 	if (optind != argc) {
 		file = argv[optind++];
 		if (optind != argc)
@@ -347,6 +358,9 @@ int main(int argc, char **argv)
 				exit(1);
 			}
 		} else {
+			if (line_marker_for_allow) {
+				modpolicydb.line_marker_avrules |= AVRULE_ALLOWED | AVRULE_XPERMS_ALLOWED;
+			}
 			if (sepol_module_policydb_to_cil(outfp, &modpolicydb, 0) != 0) {
 				fprintf(stderr, "%s:  error writing %s\n", argv[0], outfile);
 				exit(1);
diff --git a/checkpolicy/checkpolicy.8 b/checkpolicy/checkpolicy.8
index 81a3647d..caaaf675 100644
--- a/checkpolicy/checkpolicy.8
+++ b/checkpolicy/checkpolicy.8
@@ -3,7 +3,7 @@
 checkpolicy \- SELinux policy compiler
 .SH SYNOPSIS
 .B checkpolicy
-.I "[\-b[F]] [\-C] [\-d] [\-U handle_unknown (allow,deny,reject)] [\-M] [\-N] [\-c policyvers] [\-o output_file|\-] [\-S] [\-t target_platform (selinux,xen)] [\-O] [\-E] [\-V] [input_file]"
+.I "[\-b[F]] [\-C] [\-d] [\-U handle_unknown (allow,deny,reject)] [\-M] [\-N] [\-L] [\-c policyvers] [\-o output_file|\-] [\-S] [\-t target_platform (selinux,xen)] [\-O] [\-E] [\-V] [input_file]"
 .br
 .SH "DESCRIPTION"
 This manual page describes the
@@ -41,6 +41,11 @@ Enable the MLS policy when checking and compiling the policy.
 .B \-N,\-\-disable-neverallow
 Do not check neverallow rules.
 .TP
+.B \-L,\-\-line-marker-for-allow
+Output line markers for allow rules, in addition to neverallow rules. This option increases the size
+of the output CIL policy file, but the additional line markers helps debugging, especially
+neverallow failure reports. Can only be used when writing a CIL policy file.
+.TP
 .B \-c policyvers
 Specify the policy version, defaults to the latest.
 .TP
diff --git a/checkpolicy/checkpolicy.c b/checkpolicy/checkpolicy.c
index 164d9ff6..ed7296e3 100644
--- a/checkpolicy/checkpolicy.c
+++ b/checkpolicy/checkpolicy.c
@@ -112,7 +112,7 @@ static __attribute__((__noreturn__)) void usage(const char *progname)
 	printf
 	    ("usage:  %s [-b[F]] [-C] [-d] [-U handle_unknown (allow,deny,reject)] [-M] "
 	     "[-N] [-c policyvers (%d-%d)] [-o output_file|-] [-S] [-O] "
-	     "[-t target_platform (selinux,xen)] [-E] [-V] [input_file]\n",
+	     "[-t target_platform (selinux,xen)] [-E] [-V] [-L] [input_file]\n",
 	     progname, POLICYDB_VERSION_MIN, POLICYDB_VERSION_MAX);
 	exit(1);
 }
@@ -395,6 +395,7 @@ int main(int argc, char **argv)
 	unsigned int i;
 	unsigned int protocol, port;
 	unsigned int binary = 0, debug = 0, sort = 0, cil = 0, conf = 0, optimize = 0, disable_neverallow = 0;
+	unsigned int line_marker_for_allow = 0;
 	struct val_to_name v;
 	int ret, ch, fd, target = SEPOL_TARGET_SELINUX;
 	unsigned int policyvers = 0;
@@ -423,11 +424,12 @@ int main(int argc, char **argv)
 		{"sort", no_argument, NULL, 'S'},
 		{"optimize", no_argument, NULL, 'O'},
 		{"werror", no_argument, NULL, 'E'},
+		{"line-marker-for-allow", no_argument, NULL, 'L'},
 		{"help", no_argument, NULL, 'h'},
 		{NULL, 0, NULL, 0}
 	};
 
-	while ((ch = getopt_long(argc, argv, "o:t:dbU:MNCFSVc:OEh", long_options, NULL)) != -1) {
+	while ((ch = getopt_long(argc, argv, "o:t:dbU:MNCFSVc:OELh", long_options, NULL)) != -1) {
 		switch (ch) {
 		case 'o':
 			outfile = optarg;
@@ -511,6 +513,9 @@ int main(int argc, char **argv)
 		case 'E':
 			 werror = 1;
 			 break;
+		case 'L':
+			line_marker_for_allow = 1;
+			break;
 		case 'h':
 		default:
 			usage(argv[0]);
@@ -540,6 +545,11 @@ int main(int argc, char **argv)
 		exit(1);
 	}
 
+	if (line_marker_for_allow && !cil) {
+		fprintf(stderr, "Must convert to CIL for line markers to be printed\n");
+		exit(1);
+	}
+
 	if (binary) {
 		fd = open(file, O_RDONLY);
 		if (fd < 0) {
@@ -695,6 +705,9 @@ int main(int argc, char **argv)
 				exit(1);
 			}
 		} else {
+			if (line_marker_for_allow) {
+				policydbp->line_marker_avrules |= AVRULE_ALLOWED | AVRULE_XPERMS_ALLOWED;
+			}
 			if (binary) {
 				ret = sepol_kernel_policydb_to_cil(outfp, policydbp);
 			} else {
diff --git a/checkpolicy/policy_scan.l b/checkpolicy/policy_scan.l
index 5fb9ff37..c9670b11 100644
--- a/checkpolicy/policy_scan.l
+++ b/checkpolicy/policy_scan.l
@@ -57,6 +57,7 @@ void yyfatal(const char *msg)
 #endif
 
 void set_source_file(const char *name);
+static void set_source_line_and_file(const char *line);
 
 char source_file[PATH_MAX];
 unsigned long source_lineno = 1;
@@ -297,7 +298,7 @@ GLBLUB				{ return(GLBLUB); }
 {hexval}{0,4}":"{hexval}{0,4}":"({hexval}|[:.])*  { return(IPV6_ADDR); }
 {hexval}{0,4}":"{hexval}{0,4}":"({hexval}|[:.])*"/"{digit}{1,3}	{ return(IPV6_CIDR); }
 {digit}+(\.({alnum}|[_.])*)?    { return(VERSION_IDENTIFIER); }
-#line[ ]1[ ]\"[^\n]*\"		{ set_source_file(yytext+9); }
+#line[ ]{digit}+[ ]\"[^\n]*\"	{ set_source_line_and_file(yytext+6); }
 #line[ ]{digit}+	        {
 				  errno = 0;
 				  source_lineno = strtoul(yytext+6, NULL, 10) - 1;
@@ -390,8 +391,26 @@ int yywarn(const char *msg)
 void set_source_file(const char *name)
 {
 	source_lineno = 1;
-	strncpy(source_file, name, sizeof(source_file)-1); 
+	strncpy(source_file, name, sizeof(source_file)-1);
 	source_file[sizeof(source_file)-1] = '\0';
 	if (strlen(source_file) && source_file[strlen(source_file)-1] == '"')
 		source_file[strlen(source_file)-1] = '\0';
 }
+
+void set_source_line_and_file(const char *line)
+{
+	char *name;
+	unsigned long lineno;
+	errno = 0;
+	lineno = strtoul(line, &name, 10) - 1;
+	if (errno) {
+		yywarn("source line number too big");
+	}
+	set_source_file(name + 2 /* skip a space and a quote */ );
+
+	/*
+	 * set_source_file sets source_lineno to 1.
+	 * Assign source_lineno after calling set_source_file.
+	 */
+	source_lineno = lineno;
+}
diff --git a/libsepol/cil/src/cil_binary.c b/libsepol/cil/src/cil_binary.c
index 3d920182..90745110 100644
--- a/libsepol/cil/src/cil_binary.c
+++ b/libsepol/cil/src/cil_binary.c
@@ -2121,6 +2121,7 @@ static int __cil_cond_to_policydb_helper(struct cil_tree_node *node, __attribute
 		break;
 	case CIL_CALL:
 	case CIL_TUNABLEIF:
+	case CIL_SRC_INFO:
 		break;
 	default:
 		cil_tree_log(node, CIL_ERR, "Invalid statement within booleanif");
diff --git a/libsepol/cil/src/cil_build_ast.c b/libsepol/cil/src/cil_build_ast.c
index 19fbb04e..619cd894 100644
--- a/libsepol/cil/src/cil_build_ast.c
+++ b/libsepol/cil/src/cil_build_ast.c
@@ -6158,6 +6158,7 @@ static int check_for_illegal_statement(struct cil_tree_node *parse_current, stru
 			parse_current->data != CIL_KEY_AUDITALLOW &&
 			parse_current->data != CIL_KEY_TYPETRANSITION &&
 			parse_current->data != CIL_KEY_TYPECHANGE &&
+			parse_current->data != CIL_KEY_SRC_INFO &&
 			parse_current->data != CIL_KEY_TYPEMEMBER) {
 			if (((struct cil_booleanif*)args->boolif->data)->preserved_tunable) {
 				cil_tree_log(parse_current, CIL_ERR, "%s is not allowed in tunableif being treated as a booleanif", (char *)parse_current->data);
diff --git a/libsepol/cil/src/cil_resolve_ast.c b/libsepol/cil/src/cil_resolve_ast.c
index da8863c4..5eec7035 100644
--- a/libsepol/cil/src/cil_resolve_ast.c
+++ b/libsepol/cil/src/cil_resolve_ast.c
@@ -3848,6 +3848,7 @@ static int __cil_resolve_ast_node_helper(struct cil_tree_node *node, uint32_t *f
 			node->flavor != CIL_CONDBLOCK &&
 			node->flavor != CIL_AVRULE &&
 			node->flavor != CIL_TYPE_RULE &&
+			node->flavor != CIL_SRC_INFO &&
 			node->flavor != CIL_NAMETYPETRANSITION) {
 			rc = SEPOL_ERR;
 		} else if (node->flavor == CIL_AVRULE) {
diff --git a/libsepol/cil/src/cil_verify.c b/libsepol/cil/src/cil_verify.c
index 9621a247..0b740c85 100644
--- a/libsepol/cil/src/cil_verify.c
+++ b/libsepol/cil/src/cil_verify.c
@@ -1175,6 +1175,9 @@ static int __cil_verify_booleanif_helper(struct cil_tree_node *node, __attribute
 		   booleanif statements if they don't have "*" as the file. We
 		   can't check that here. Or at least we won't right now. */
 		break;
+	case CIL_SRC_INFO:
+		//Fall through
+		break;
 	default: {
 		const char * flavor = cil_node_to_string(node);
 		if (bif->preserved_tunable) {
diff --git a/libsepol/cil/src/cil_write_ast.c b/libsepol/cil/src/cil_write_ast.c
index cd1b6e6c..f9edadba 100644
--- a/libsepol/cil/src/cil_write_ast.c
+++ b/libsepol/cil/src/cil_write_ast.c
@@ -556,7 +556,6 @@ static const char *macro_param_flavor_to_string(enum cil_flavor flavor)
 	return str;
 }
 
-/* ANDROID: not used.
 static void cil_write_src_info_node(FILE *out, struct cil_tree_node *node)
 {
 	struct cil_src_info *info = node->data;
@@ -568,7 +567,6 @@ static void cil_write_src_info_node(FILE *out, struct cil_tree_node *node)
 		fprintf(out, ";;* <?SRC_INFO_KIND> %u %s\n", info->hll_line, info->path);
 	}
 }
-*/
 
 void cil_write_ast_node(FILE *out, struct cil_tree_node *node)
 {
@@ -1625,10 +1623,11 @@ static int __write_cil_ast_node_helper(struct cil_tree_node *node, uint32_t *fin
 	struct cil_write_ast_args *args = extra_args;
 
 	if (node->flavor == CIL_SRC_INFO) {
-		// ANDROID: The generated cil may be split/merged later on. Do not output
-		// source information to avoid issues when loading the resulting policy with
-		// libsepol.
-		// cil_write_src_info_node(args->out, node);
+		cil_write_src_info_node(args->out, node);
+
+		if (node->cl_head == NULL) {
+			fprintf(args->out, ";;* lme\n");
+		}
 		return SEPOL_OK;
 	}
 
@@ -1663,10 +1662,7 @@ static int __write_cil_ast_last_child_helper(struct cil_tree_node *node, void *e
 	if (parent->flavor == CIL_ROOT) {
 		return SEPOL_OK;
 	} else if (parent->flavor == CIL_SRC_INFO) {
-		// ANDROID: The generated cil may be split/merged later on. Do not output
-		// source information to avoid issues when loading the resulting policy with
-		// libsepol.
-		// fprintf(args->out, ";;* lme\n");
+		fprintf(args->out, ";;* lme\n");
 		return SEPOL_OK;
 	}
 
diff --git a/libsepol/include/sepol/policydb/policydb.h b/libsepol/include/sepol/policydb/policydb.h
index 104a7dc8..efdc759a 100644
--- a/libsepol/include/sepol/policydb/policydb.h
+++ b/libsepol/include/sepol/policydb/policydb.h
@@ -615,6 +615,10 @@ typedef struct policydb {
 	sepol_security_class_t dir_class;
 	sepol_access_vector_t process_trans;
 	sepol_access_vector_t process_trans_dyntrans;
+
+	/* avrules whose line markes will be printed. Defaults to neverallow and
+	   neverallowxperm */
+	uint32_t line_marker_avrules;
 } policydb_t;
 
 struct sepol_policydb {
diff --git a/libsepol/src/module_to_cil.c b/libsepol/src/module_to_cil.c
index 79636897..aa12653e 100644
--- a/libsepol/src/module_to_cil.c
+++ b/libsepol/src/module_to_cil.c
@@ -1196,8 +1196,7 @@ static int avrule_list_to_cil(int indent, struct policydb *pdb, struct avrule *a
 	struct type_set *ts;
 
 	for (avrule = avrule_list; avrule != NULL; avrule = avrule->next) {
-		if ((avrule->specified & (AVRULE_NEVERALLOW|AVRULE_XPERMS_NEVERALLOW)) &&
-		    avrule->source_filename) {
+		if ((avrule->specified & pdb->line_marker_avrules) && avrule->source_filename) {
 			cil_println(0, ";;* lmx %lu %s\n",avrule->source_line, avrule->source_filename);
 		}
 
@@ -1264,8 +1263,7 @@ static int avrule_list_to_cil(int indent, struct policydb *pdb, struct avrule *a
 		names_destroy(&snames, &num_snames);
 		names_destroy(&tnames, &num_tnames);
 
-		if ((avrule->specified & (AVRULE_NEVERALLOW|AVRULE_XPERMS_NEVERALLOW)) &&
-		    avrule->source_filename) {
+		if ((avrule->specified & pdb->line_marker_avrules) && avrule->source_filename) {
 			cil_println(0, ";;* lme\n");
 		}
 	}
diff --git a/libsepol/src/policydb.c b/libsepol/src/policydb.c
index e90ccca1..92822e2b 100644
--- a/libsepol/src/policydb.c
+++ b/libsepol/src/policydb.c
@@ -924,6 +924,8 @@ int policydb_init(policydb_t * p)
 	ebitmap_init(&p->policycaps);
 	ebitmap_init(&p->permissive_map);
 
+	p->line_marker_avrules = AVRULE_NEVERALLOW|AVRULE_XPERMS_NEVERALLOW;
+
 	return 0;
 err:
 	hashtab_destroy(p->filename_trans);
```

