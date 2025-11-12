```diff
diff --git a/METADATA b/METADATA
index cc9bf53d..5f1c71e6 100644
--- a/METADATA
+++ b/METADATA
@@ -9,13 +9,13 @@ third_party {
   license_note: "would be NOTICE save for scripts/image_signing/lib/shflags/shflags"
   last_upgrade_date {
     year: 2025
-    month: 2
-    day: 19
+    month: 4
+    day: 3
   }
   identifier {
     type: "Git"
     value: "https://chromium.googlesource.com/chromiumos/platform/vboot_reference"
-    version: "ae6ceb20d5e2938a366e22c2a550a02772788825"
+    version: "3f36817a50e36a75f5d550e4224985d602dbdc2a"
     primary_source: true
   }
 }
diff --git a/cgpt/cgpt.c b/cgpt/cgpt.c
index 1ba3fc8e..b84caa6f 100644
--- a/cgpt/cgpt.c
+++ b/cgpt/cgpt.c
@@ -14,85 +14,86 @@
 #include "cgpt.h"
 #include "vboot_host.h"
 
-const char* progname;
+const char *progname;
 
 int GenerateGuid(Guid *newguid)
 {
-  /* From libuuid */
-  uuid_generate(newguid->u.raw);
-  return CGPT_OK;
+	/* From libuuid */
+	uuid_generate(newguid->u.raw);
+	return CGPT_OK;
 }
 
 struct {
-  const char *name;
-  int (*fp)(int argc, char *argv[]);
-  const char *comment;
+	const char *name;
+	int (*fp)(int argc, char *argv[]);
+	const char *comment;
 } cmds[] = {
-  {"create", cmd_create, "Create or reset GPT headers and tables"},
-  {"add", cmd_add, "Add, edit or remove a partition entry"},
-  {"show", cmd_show, "Show partition table and entries"},
-  {"repair", cmd_repair, "Repair damaged GPT headers and tables"},
-  {"boot", cmd_boot, "Edit the PMBR sector for legacy BIOSes"},
-  {"find", cmd_find, "Locate a partition by its GUID"},
-  {"edit", cmd_edit, "Edit a drive entry"},
-  {"prioritize", cmd_prioritize,
-   "Reorder the priority of all kernel partitions"},
-  {"legacy", cmd_legacy, "Switch between GPT and Legacy GPT"},
+	{"create", cmd_create, "Create or reset GPT headers and tables"},
+	{"add", cmd_add, "Add, edit or remove a partition entry"},
+	{"show", cmd_show, "Show partition table and entries"},
+	{"repair", cmd_repair, "Repair damaged GPT headers and tables"},
+	{"boot", cmd_boot, "Edit the PMBR sector for legacy BIOSes"},
+	{"find", cmd_find, "Locate a partition by its GUID"},
+	{"edit", cmd_edit, "Edit a drive entry"},
+	{"prioritize", cmd_prioritize, "Reorder the priority of all kernel partitions"},
+	{"legacy", cmd_legacy, "Switch between GPT and Legacy GPT"},
 };
 
-static void Usage(void) {
-  int i;
+static void Usage(void)
+{
+	int i;
 
-  printf("\nUsage: %s COMMAND [OPTIONS] DRIVE\n\n"
-         "Supported COMMANDs:\n\n",
-         progname);
+	printf("\nUsage: %s COMMAND [OPTIONS] DRIVE\n\n"
+	       "Supported COMMANDs:\n\n",
+	       progname);
 
-  for (i = 0; i < sizeof(cmds)/sizeof(cmds[0]); ++i) {
-    printf("    %-15s  %s\n", cmds[i].name, cmds[i].comment);
-  }
-  printf("\nFor more detailed usage, use %s COMMAND -h\n\n", progname);
+	for (i = 0; i < sizeof(cmds) / sizeof(cmds[0]); ++i) {
+		printf("    %-15s  %s\n", cmds[i].name, cmds[i].comment);
+	}
+	printf("\nFor more detailed usage, use %s COMMAND -h\n\n", progname);
 }
 
-int main(int argc, char *argv[]) {
-  int i;
-  int match_count = 0;
-  int match_index = 0;
-  char* command;
-
-  progname = strrchr(argv[0], '/');
-  if (progname)
-    progname++;
-  else
-    progname = argv[0];
-
-  if (argc < 2) {
-    Usage();
-    return CGPT_FAILED;
-  }
-
-  // increment optind now, so that getopt skips argv[0] in command function
-  command = argv[optind++];
-
-  // Find the command to invoke.
-  for (i = 0; command && i < sizeof(cmds)/sizeof(cmds[0]); ++i) {
-    // exact match?
-    if (0 == strcmp(cmds[i].name, command)) {
-      match_index = i;
-      match_count = 1;
-      break;
-    }
-    // unique match?
-    else if (0 == strncmp(cmds[i].name, command, strlen(command))) {
-      match_index = i;
-      match_count++;
-    }
-  }
-
-  if (match_count == 1)
-    return cmds[match_index].fp(argc, argv);
-
-  // Couldn't find a single matching command.
-  Usage();
-
-  return CGPT_FAILED;
+int main(int argc, char *argv[])
+{
+	int i;
+	int match_count = 0;
+	int match_index = 0;
+	char *command;
+
+	progname = strrchr(argv[0], '/');
+	if (progname)
+		progname++;
+	else
+		progname = argv[0];
+
+	if (argc < 2) {
+		Usage();
+		return CGPT_FAILED;
+	}
+
+	// increment optind now, so that getopt skips argv[0] in command function
+	command = argv[optind++];
+
+	// Find the command to invoke.
+	for (i = 0; command && i < sizeof(cmds) / sizeof(cmds[0]); ++i) {
+		// exact match?
+		if (0 == strcmp(cmds[i].name, command)) {
+			match_index = i;
+			match_count = 1;
+			break;
+		}
+		// unique match?
+		else if (0 == strncmp(cmds[i].name, command, strlen(command))) {
+			match_index = i;
+			match_count++;
+		}
+	}
+
+	if (match_count == 1)
+		return cmds[match_index].fp(argc, argv);
+
+	// Couldn't find a single matching command.
+	Usage();
+
+	return CGPT_FAILED;
 }
diff --git a/cgpt/cgpt.h b/cgpt/cgpt.h
index 7f9276fc..c0f9ae31 100644
--- a/cgpt/cgpt.h
+++ b/cgpt/cgpt.h
@@ -95,16 +95,6 @@ int Save(struct drive *drive, const uint8_t *buf,
                 const uint64_t sector_count);
 
 
-/* Constant global type values to compare against */
-extern const Guid guid_chromeos_firmware;
-extern const Guid guid_chromeos_kernel;
-extern const Guid guid_chromeos_rootfs;
-extern const Guid guid_android_vbmeta;
-extern const Guid guid_linux_data;
-extern const Guid guid_chromeos_reserved;
-extern const Guid guid_efi;
-extern const Guid guid_unused;
-
 int ReadPMBR(struct drive *drive);
 int WritePMBR(struct drive *drive);
 
diff --git a/cgpt/cgpt_add.c b/cgpt/cgpt_add.c
index 362288ca..9cf3897d 100644
--- a/cgpt/cgpt_add.c
+++ b/cgpt/cgpt_add.c
@@ -11,303 +11,302 @@
 #include "cgpt_params.h"
 #include "vboot_host.h"
 
-static void PrintCgptAddParams(const CgptAddParams *params) {
-  char tmp[64];
-
-  fprintf(stderr, "-i %d ", params->partition);
-  if (params->label)
-    fprintf(stderr, "-l %s ", params->label);
-  if (params->set_begin)
-    fprintf(stderr, "-b %llu ", (unsigned long long)params->begin);
-  if (params->set_size)
-    fprintf(stderr, "-s %llu ", (unsigned long long)params->size);
-  if (params->set_type) {
-    GuidToStr(&params->type_guid, tmp, sizeof(tmp));
-    fprintf(stderr, "-t %s ", tmp);
-  }
-  if (params->set_unique) {
-    GuidToStr(&params->unique_guid, tmp, sizeof(tmp));
-    fprintf(stderr, "-u %s ", tmp);
-  }
-  if (params->set_error_counter)
-    fprintf(stderr, "-E %d ", params->error_counter);
-  if (params->set_successful)
-    fprintf(stderr, "-S %d ", params->successful);
-  if (params->set_tries)
-    fprintf(stderr, "-T %d ", params->tries);
-  if (params->set_priority)
-    fprintf(stderr, "-P %d ", params->priority);
-  if (params->set_required)
-    fprintf(stderr, "-R %d ", params->required);
-  if (params->set_legacy_boot)
-    fprintf(stderr, "-B %d ", params->legacy_boot);
-  if (params->set_raw)
-    fprintf(stderr, "-A %#x ", params->raw_value);
-
-  fprintf(stderr, "\n");
+static void PrintCgptAddParams(const CgptAddParams *params)
+{
+	char tmp[64];
+
+	fprintf(stderr, "-i %d ", params->partition);
+	if (params->label)
+		fprintf(stderr, "-l %s ", params->label);
+	if (params->set_begin)
+		fprintf(stderr, "-b %llu ", (unsigned long long)params->begin);
+	if (params->set_size)
+		fprintf(stderr, "-s %llu ", (unsigned long long)params->size);
+	if (params->set_type) {
+		GptGuidToStr(&params->type_guid, tmp, sizeof(tmp), GPT_GUID_UPPERCASE);
+		fprintf(stderr, "-t %s ", tmp);
+	}
+	if (params->set_unique) {
+		GptGuidToStr(&params->unique_guid, tmp, sizeof(tmp), GPT_GUID_UPPERCASE);
+		fprintf(stderr, "-u %s ", tmp);
+	}
+	if (params->set_error_counter)
+		fprintf(stderr, "-E %d ", params->error_counter);
+	if (params->set_successful)
+		fprintf(stderr, "-S %d ", params->successful);
+	if (params->set_tries)
+		fprintf(stderr, "-T %d ", params->tries);
+	if (params->set_priority)
+		fprintf(stderr, "-P %d ", params->priority);
+	if (params->set_required)
+		fprintf(stderr, "-R %d ", params->required);
+	if (params->set_legacy_boot)
+		fprintf(stderr, "-B %d ", params->legacy_boot);
+	if (params->set_raw)
+		fprintf(stderr, "-A %#x ", params->raw_value);
+
+	fprintf(stderr, "\n");
 }
 
 // This is the implementation-specific helper function.
-static int GptSetEntryAttributes(struct drive *drive,
-                                 uint32_t index,
-                                 CgptAddParams *params) {
-  GptEntry *entry;
-
-  entry = GetEntry(&drive->gpt, PRIMARY, index);
-  if (params->set_begin)
-    entry->starting_lba = params->begin;
-  if (params->set_size)
-    entry->ending_lba = entry->starting_lba + params->size - 1;
-  if (params->set_unique) {
-    memcpy(&entry->unique, &params->unique_guid, sizeof(Guid));
-  } else if (GuidIsZero(&entry->type)) {
-	  if (CGPT_OK != GenerateGuid(&entry->unique)) {
-		  Error("Unable to generate new GUID.\n");
-		  return -1;
-    }
-  }
-  if (params->set_type)
-    memcpy(&entry->type, &params->type_guid, sizeof(Guid));
-  if (params->label) {
-    if (CGPT_OK != UTF8ToUTF16((const uint8_t *)params->label, entry->name,
-                               sizeof(entry->name) / sizeof(entry->name[0]))) {
-      Error("The label cannot be converted to UTF16.\n");
-      return -1;
-    }
-  }
-  return 0;
+static int GptSetEntryAttributes(struct drive *drive, uint32_t index, CgptAddParams *params)
+{
+	GptEntry *entry;
+
+	entry = GetEntry(&drive->gpt, PRIMARY, index);
+	if (params->set_begin)
+		entry->starting_lba = params->begin;
+	if (params->set_size)
+		entry->ending_lba = entry->starting_lba + params->size - 1;
+	if (params->set_unique) {
+		memcpy(&entry->unique, &params->unique_guid, sizeof(Guid));
+	} else if (GuidIsZero(&entry->type)) {
+		if (CGPT_OK != GenerateGuid(&entry->unique)) {
+			Error("Unable to generate new GUID.\n");
+			return -1;
+		}
+	}
+	if (params->set_type)
+		memcpy(&entry->type, &params->type_guid, sizeof(Guid));
+	if (params->label) {
+		if (CGPT_OK != UTF8ToUTF16((const uint8_t *)params->label, entry->name,
+					   sizeof(entry->name) / sizeof(entry->name[0]))) {
+			Error("The label cannot be converted to UTF16.\n");
+			return -1;
+		}
+	}
+	return 0;
 }
 
 // This is an internal helper function which assumes no NULL args are passed.
 // It sets the given attribute values for a single entry at the given index.
-static int SetEntryAttributes(struct drive *drive,
-                              uint32_t index,
-                              CgptAddParams *params) {
-  if (params->set_raw) {
-    SetRaw(drive, PRIMARY, index, params->raw_value);
-  } else {
-    if (params->set_error_counter)
-      SetErrorCounter(drive, PRIMARY, index, params->error_counter);
-    if (params->set_successful)
-      SetSuccessful(drive, PRIMARY, index, params->successful);
-    if (params->set_tries)
-      SetTries(drive, PRIMARY, index, params->tries);
-    if (params->set_priority)
-      SetPriority(drive, PRIMARY, index, params->priority);
-    if (params->set_legacy_boot)
-      SetLegacyBoot(drive, PRIMARY, index, params->legacy_boot);
-    if (params->set_required)
-      SetRequired(drive, PRIMARY, index, params->required);
-  }
-
-  // New partitions must specify type, begin, and size.
-  if (IsUnused(drive, PRIMARY, index)) {
-    if (!params->set_begin || !params->set_size || !params->set_type) {
-      Error("-t, -b, and -s options are required for new partitions\n");
-      return -1;
-    }
-    if (GuidIsZero(&params->type_guid)) {
-      Error("New partitions must have a type other than \"unused\"\n");
-      return -1;
-    }
-  }
-
-  return 0;
+static int SetEntryAttributes(struct drive *drive, uint32_t index, CgptAddParams *params)
+{
+	if (params->set_raw) {
+		SetRaw(drive, PRIMARY, index, params->raw_value);
+	} else {
+		if (params->set_error_counter)
+			SetErrorCounter(drive, PRIMARY, index, params->error_counter);
+		if (params->set_successful)
+			SetSuccessful(drive, PRIMARY, index, params->successful);
+		if (params->set_tries)
+			SetTries(drive, PRIMARY, index, params->tries);
+		if (params->set_priority)
+			SetPriority(drive, PRIMARY, index, params->priority);
+		if (params->set_legacy_boot)
+			SetLegacyBoot(drive, PRIMARY, index, params->legacy_boot);
+		if (params->set_required)
+			SetRequired(drive, PRIMARY, index, params->required);
+	}
+
+	// New partitions must specify type, begin, and size.
+	if (IsUnused(drive, PRIMARY, index)) {
+		if (!params->set_begin || !params->set_size || !params->set_type) {
+			Error("-t, -b, and -s options are required for new partitions\n");
+			return -1;
+		}
+		if (GuidIsZero(&params->type_guid)) {
+			Error("New partitions must have a type other than \"unused\"\n");
+			return -1;
+		}
+	}
+
+	return 0;
 }
 
-static int CgptCheckAddValidity(struct drive *drive) {
-  int gpt_retval;
-  if (GPT_SUCCESS != (gpt_retval = GptValidityCheck(&drive->gpt))) {
-    Error("GptValidityCheck() returned %d: %s\n",
-          gpt_retval, GptError(gpt_retval));
-    return -1;
-  }
+static int CgptCheckAddValidity(struct drive *drive)
+{
+	int gpt_retval;
+	if (GPT_SUCCESS != (gpt_retval = GptValidityCheck(&drive->gpt))) {
+		Error("GptValidityCheck() returned %d: %s\n", gpt_retval, GptError(gpt_retval));
+		return -1;
+	}
 
-  if (CGPT_OK != CheckValid(drive)) {
-    Error("please run 'cgpt repair' before adding anything.\n");
-    return -1;
-  }
+	if (CGPT_OK != CheckValid(drive)) {
+		Error("please run 'cgpt repair' before adding anything.\n");
+		return -1;
+	}
 
-  return 0;
+	return 0;
 }
 
-static int CgptGetUnusedPartition(struct drive *drive, uint32_t *index,
-                                  CgptAddParams *params) {
-  uint32_t i;
-  uint32_t max_part = GetNumberOfEntries(drive);
-  if (params->partition) {
-    if (params->partition > max_part) {
-      Error("invalid partition number: %d\n", params->partition);
-      return -1;
-    }
-    *index = params->partition - 1;
-    return 0;
-  } else {
-    // Find next empty partition.
-    for (i = 0; i < max_part; i++) {
-      if (IsUnused(drive, PRIMARY, i)) {
-        params->partition = i + 1;
-        *index = i;
-        return 0;
-      }
-    }
-    Error("no unused partitions available\n");
-    return -1;
-  }
+static int CgptGetUnusedPartition(struct drive *drive, uint32_t *index, CgptAddParams *params)
+{
+	uint32_t i;
+	uint32_t max_part = GetNumberOfEntries(drive);
+	if (params->partition) {
+		if (params->partition > max_part) {
+			Error("invalid partition number: %d\n", params->partition);
+			return -1;
+		}
+		*index = params->partition - 1;
+		return 0;
+	} else {
+		// Find next empty partition.
+		for (i = 0; i < max_part; i++) {
+			if (IsUnused(drive, PRIMARY, i)) {
+				params->partition = i + 1;
+				*index = i;
+				return 0;
+			}
+		}
+		Error("no unused partitions available\n");
+		return -1;
+	}
 }
 
-int CgptSetAttributes(CgptAddParams *params) {
-  struct drive drive;
+int CgptSetAttributes(CgptAddParams *params)
+{
+	struct drive drive;
 
-  if (params == NULL)
-    return CGPT_FAILED;
+	if (params == NULL)
+		return CGPT_FAILED;
 
-  if (CGPT_OK != DriveOpen(params->drive_name, &drive, O_RDWR,
-                           params->drive_size))
-    return CGPT_FAILED;
+	if (CGPT_OK != DriveOpen(params->drive_name, &drive, O_RDWR, params->drive_size))
+		return CGPT_FAILED;
 
-  if (CgptCheckAddValidity(&drive)) {
-    goto bad;
-  }
+	if (CgptCheckAddValidity(&drive)) {
+		goto bad;
+	}
 
-  if (params->partition == 0 ||
-      params->partition >= GetNumberOfEntries(&drive)) {
-    Error("invalid partition number: %d\n", params->partition);
-    goto bad;
-  }
+	if (params->partition == 0 || params->partition >= GetNumberOfEntries(&drive)) {
+		Error("invalid partition number: %d\n", params->partition);
+		goto bad;
+	}
 
-  SetEntryAttributes(&drive, params->partition - 1, params);
+	SetEntryAttributes(&drive, params->partition - 1, params);
 
-  UpdateAllEntries(&drive);
+	UpdateAllEntries(&drive);
 
-  // Write it all out.
-  return DriveClose(&drive, 1);
+	// Write it all out.
+	return DriveClose(&drive, 1);
 
 bad:
-  DriveClose(&drive, 0);
-  return CGPT_FAILED;
+	DriveClose(&drive, 0);
+	return CGPT_FAILED;
 }
 
 // This method gets the partition details such as the attributes, the
 // guids of the partitions, etc. Input is the partition number or the
 // unique id of the partition. Output is populated in the respective
 // fields of params.
-int CgptGetPartitionDetails(CgptAddParams *params) {
-  struct drive drive;
-  int result = CGPT_FAILED;
-  int index;
-
-  if (params == NULL)
-    return CGPT_FAILED;
-
-  if (CGPT_OK != DriveOpen(params->drive_name, &drive, O_RDONLY,
-                           params->drive_size))
-    return CGPT_FAILED;
-
-  if (CgptCheckAddValidity(&drive)) {
-    goto bad;
-  }
-
-  int max_part = GetNumberOfEntries(&drive);
-  if (params->partition > 0) {
-    if (params->partition >= max_part) {
-      Error("invalid partition number: %d\n", params->partition);
-      goto bad;
-    }
-  } else {
-    if (!params->set_unique) {
-      Error("either partition or unique_id must be specified\n");
-      goto bad;
-    }
-    for (index = 0; index < max_part; index++) {
-      GptEntry *entry = GetEntry(&drive.gpt, PRIMARY, index);
-      if (GuidEqual(&entry->unique, &params->unique_guid)) {
-        params->partition = index + 1;
-        break;
-      }
-    }
-    if (index >= max_part) {
-      Error("no partitions with the given unique id available\n");
-      goto bad;
-    }
-  }
-  index = params->partition - 1;
-
-  // GPT-specific code
-  GptEntry *entry = GetEntry(&drive.gpt, PRIMARY, index);
-  params->begin = entry->starting_lba;
-  params->size =  entry->ending_lba - entry->starting_lba + 1;
-  memcpy(&params->type_guid, &entry->type, sizeof(Guid));
-  memcpy(&params->unique_guid, &entry->unique, sizeof(Guid));
-  params->raw_value = entry->attrs.fields.gpt_att;
-
-  params->error_counter = GetErrorCounter(&drive, PRIMARY, index);
-  params->successful = GetSuccessful(&drive, PRIMARY, index);
-  params->tries = GetTries(&drive, PRIMARY, index);
-  params->priority = GetPriority(&drive, PRIMARY, index);
-  result = CGPT_OK;
+int CgptGetPartitionDetails(CgptAddParams *params)
+{
+	struct drive drive;
+	int result = CGPT_FAILED;
+	int index;
+
+	if (params == NULL)
+		return CGPT_FAILED;
+
+	if (CGPT_OK != DriveOpen(params->drive_name, &drive, O_RDONLY, params->drive_size))
+		return CGPT_FAILED;
+
+	if (CgptCheckAddValidity(&drive)) {
+		goto bad;
+	}
+
+	int max_part = GetNumberOfEntries(&drive);
+	if (params->partition > 0) {
+		if (params->partition >= max_part) {
+			Error("invalid partition number: %d\n", params->partition);
+			goto bad;
+		}
+	} else {
+		if (!params->set_unique) {
+			Error("either partition or unique_id must be specified\n");
+			goto bad;
+		}
+		for (index = 0; index < max_part; index++) {
+			GptEntry *entry = GetEntry(&drive.gpt, PRIMARY, index);
+			if (GuidEqual(&entry->unique, &params->unique_guid)) {
+				params->partition = index + 1;
+				break;
+			}
+		}
+		if (index >= max_part) {
+			Error("no partitions with the given unique id available\n");
+			goto bad;
+		}
+	}
+	index = params->partition - 1;
+
+	// GPT-specific code
+	GptEntry *entry = GetEntry(&drive.gpt, PRIMARY, index);
+	params->begin = entry->starting_lba;
+	params->size = entry->ending_lba - entry->starting_lba + 1;
+	memcpy(&params->type_guid, &entry->type, sizeof(Guid));
+	memcpy(&params->unique_guid, &entry->unique, sizeof(Guid));
+	params->raw_value = entry->attrs.fields.gpt_att;
+
+	params->error_counter = GetErrorCounter(&drive, PRIMARY, index);
+	params->successful = GetSuccessful(&drive, PRIMARY, index);
+	params->tries = GetTries(&drive, PRIMARY, index);
+	params->priority = GetPriority(&drive, PRIMARY, index);
+	result = CGPT_OK;
 
 bad:
-  DriveClose(&drive, 0);
-  return result;
+	DriveClose(&drive, 0);
+	return result;
 }
 
-static int GptAdd(struct drive *drive, CgptAddParams *params, uint32_t index) {
-  GptEntry *entry, backup;
-  int rv;
+static int GptAdd(struct drive *drive, CgptAddParams *params, uint32_t index)
+{
+	GptEntry *entry, backup;
+	int rv;
 
-  entry = GetEntry(&drive->gpt, PRIMARY, index);
-  memcpy(&backup, entry, sizeof(backup));
+	entry = GetEntry(&drive->gpt, PRIMARY, index);
+	memcpy(&backup, entry, sizeof(backup));
 
-  if (SetEntryAttributes(drive, index, params) ||
-      GptSetEntryAttributes(drive, index, params)) {
-    memcpy(entry, &backup, sizeof(*entry));
-    return -1;
-  }
+	if (SetEntryAttributes(drive, index, params) ||
+	    GptSetEntryAttributes(drive, index, params)) {
+		memcpy(entry, &backup, sizeof(*entry));
+		return -1;
+	}
 
-  UpdateAllEntries(drive);
+	UpdateAllEntries(drive);
 
-  rv = CheckEntries((GptEntry*)drive->gpt.primary_entries,
-                    (GptHeader*)drive->gpt.primary_header);
+	rv = CheckEntries((GptEntry *)drive->gpt.primary_entries,
+			  (GptHeader *)drive->gpt.primary_header);
 
-  if (0 != rv) {
-    // If the modified entry is illegal, recover it and return error.
-    memcpy(entry, &backup, sizeof(*entry));
-    Error("%s\n", GptErrorText(rv));
-    Error("");
-    PrintCgptAddParams(params);
-    return -1;
-  }
+	if (0 != rv) {
+		// If the modified entry is illegal, recover it and return error.
+		memcpy(entry, &backup, sizeof(*entry));
+		Error("%s\n", GptErrorText(rv));
+		Error("");
+		PrintCgptAddParams(params);
+		return -1;
+	}
 
-  return 0;
+	return 0;
 }
 
-int CgptAdd(CgptAddParams *params) {
-  struct drive drive;
-  uint32_t index;
+int CgptAdd(CgptAddParams *params)
+{
+	struct drive drive;
+	uint32_t index;
 
-  if (params == NULL)
-    return CGPT_FAILED;
+	if (params == NULL)
+		return CGPT_FAILED;
 
-  if (CGPT_OK != DriveOpen(params->drive_name, &drive, O_RDWR,
-                           params->drive_size))
-    return CGPT_FAILED;
+	if (CGPT_OK != DriveOpen(params->drive_name, &drive, O_RDWR, params->drive_size))
+		return CGPT_FAILED;
 
-  if (CgptCheckAddValidity(&drive)) {
-    goto bad;
-  }
+	if (CgptCheckAddValidity(&drive)) {
+		goto bad;
+	}
 
-  if (CgptGetUnusedPartition(&drive, &index, params)) {
-    goto bad;
-  }
+	if (CgptGetUnusedPartition(&drive, &index, params)) {
+		goto bad;
+	}
 
-  if (GptAdd(&drive, params, index))
-    goto bad;
+	if (GptAdd(&drive, params, index))
+		goto bad;
 
-  // Write it all out.
-  return DriveClose(&drive, 1);
+	// Write it all out.
+	return DriveClose(&drive, 1);
 
 bad:
-  DriveClose(&drive, 0);
-  return CGPT_FAILED;
+	DriveClose(&drive, 0);
+	return CGPT_FAILED;
 }
diff --git a/cgpt/cgpt_boot.c b/cgpt/cgpt_boot.c
index cb4e7be5..990ceb4e 100644
--- a/cgpt/cgpt_boot.c
+++ b/cgpt/cgpt_boot.c
@@ -13,141 +13,139 @@
 #include "cgpt_params.h"
 #include "vboot_host.h"
 
-int CgptGetBootPartitionNumber(CgptBootParams *params) {
-  struct drive drive;
-  int gpt_retval= 0;
-  int retval;
-
-  if (params == NULL)
-    return CGPT_FAILED;
-
-  if (CGPT_OK != DriveOpen(params->drive_name, &drive, O_RDONLY,
-                           params->drive_size))
-    return CGPT_FAILED;
-
-  if (GPT_SUCCESS != (gpt_retval = GptValidityCheck(&drive.gpt))) {
-    Error("GptValidityCheck() returned %d: %s\n",
-          gpt_retval, GptError(gpt_retval));
-    retval = CGPT_FAILED;
-    goto done;
-  }
-
-  if (CGPT_OK != ReadPMBR(&drive)) {
-    Error("Unable to read PMBR\n");
-    retval = CGPT_FAILED;
-    goto done;
-  }
-
-  char buf[GUID_STRLEN];
-  GuidToStr(&drive.pmbr.boot_guid, buf, sizeof(buf));
-
-  int numEntries = GetNumberOfEntries(&drive);
-  int i;
-  for (i = 0; i < numEntries; i++) {
-      GptEntry *entry = GetEntry(&drive.gpt, ANY_VALID, i);
-
-      if (GuidEqual(&entry->unique, &drive.pmbr.boot_guid)) {
-        params->partition = i + 1;
-        retval = CGPT_OK;
-        goto done;
-      }
-  }
-
-  Error("Didn't find any boot partition\n");
-  params->partition = 0;
-  retval = CGPT_FAILED;
+int CgptGetBootPartitionNumber(CgptBootParams *params)
+{
+	struct drive drive;
+	int gpt_retval = 0;
+	int retval;
+
+	if (params == NULL)
+		return CGPT_FAILED;
+
+	if (CGPT_OK != DriveOpen(params->drive_name, &drive, O_RDONLY, params->drive_size))
+		return CGPT_FAILED;
+
+	if (GPT_SUCCESS != (gpt_retval = GptValidityCheck(&drive.gpt))) {
+		Error("GptValidityCheck() returned %d: %s\n", gpt_retval, GptError(gpt_retval));
+		retval = CGPT_FAILED;
+		goto done;
+	}
+
+	if (CGPT_OK != ReadPMBR(&drive)) {
+		Error("Unable to read PMBR\n");
+		retval = CGPT_FAILED;
+		goto done;
+	}
+
+	char buf[GUID_STRLEN];
+	GptGuidToStr(&drive.pmbr.boot_guid, buf, sizeof(buf), GPT_GUID_UPPERCASE);
+
+	int numEntries = GetNumberOfEntries(&drive);
+	int i;
+	for (i = 0; i < numEntries; i++) {
+		GptEntry *entry = GetEntry(&drive.gpt, ANY_VALID, i);
+
+		if (GuidEqual(&entry->unique, &drive.pmbr.boot_guid)) {
+			params->partition = i + 1;
+			retval = CGPT_OK;
+			goto done;
+		}
+	}
+
+	Error("Didn't find any boot partition\n");
+	params->partition = 0;
+	retval = CGPT_FAILED;
 
 done:
-  (void) DriveClose(&drive, 1);
-  return retval;
+	(void)DriveClose(&drive, 1);
+	return retval;
 }
 
-
-int CgptBoot(CgptBootParams *params) {
-  struct drive drive;
-  int retval = 1;
-  int gpt_retval= 0;
-  int mode = O_RDONLY;
-
-  if (params == NULL)
-    return CGPT_FAILED;
-
-  if (params->create_pmbr || params->partition || params->bootfile)
-    mode = O_RDWR;
-
-  if (CGPT_OK != DriveOpen(params->drive_name, &drive, mode,
-                           params->drive_size)) {
-    return CGPT_FAILED;
-  }
-
-  if (CGPT_OK != ReadPMBR(&drive)) {
-    Error("Unable to read PMBR\n");
-    goto done;
-  }
-
-  if (params->create_pmbr) {
-    drive.pmbr.magic[0] = 0x1d;
-    drive.pmbr.magic[1] = 0x9a;
-    drive.pmbr.sig[0] = 0x55;
-    drive.pmbr.sig[1] = 0xaa;
-    memset(&drive.pmbr.part, 0, sizeof(drive.pmbr.part));
-    drive.pmbr.part[0].f_head = 0x00;
-    drive.pmbr.part[0].f_sect = 0x02;
-    drive.pmbr.part[0].f_cyl = 0x00;
-    drive.pmbr.part[0].type = 0xee;
-    drive.pmbr.part[0].l_head = 0xff;
-    drive.pmbr.part[0].l_sect = 0xff;
-    drive.pmbr.part[0].l_cyl = 0xff;
-    drive.pmbr.part[0].f_lba = htole32(1);
-    uint32_t max = 0xffffffff;
-    if (drive.gpt.streaming_drive_sectors < 0xffffffff)
-      max = drive.gpt.streaming_drive_sectors - 1;
-    drive.pmbr.part[0].num_sect = htole32(max);
-  }
-
-  if (params->partition) {
-    if (GPT_SUCCESS != (gpt_retval = GptValidityCheck(&drive.gpt))) {
-      Error("GptValidityCheck() returned %d: %s\n",
-            gpt_retval, GptError(gpt_retval));
-      goto done;
-    }
-
-    if (params->partition > GetNumberOfEntries(&drive)) {
-      Error("invalid partition number: %d\n", params->partition);
-      goto done;
-    }
-
-    uint32_t index = params->partition - 1;
-    GptEntry *entry = GetEntry(&drive.gpt, ANY_VALID, index);
-    memcpy(&drive.pmbr.boot_guid, &entry->unique, sizeof(Guid));
-  }
-
-  if (params->bootfile) {
-    int fd = open(params->bootfile, O_RDONLY);
-    if (fd < 0) {
-      Error("Can't read %s: %s\n", params->bootfile, strerror(errno));
-      goto done;
-    }
-
-    int n = read(fd, drive.pmbr.bootcode, sizeof(drive.pmbr.bootcode));
-    if (n < 1) {
-      Error("problem reading %s: %s\n", params->bootfile, strerror(errno));
-      close(fd);
-      goto done;
-    }
-
-    close(fd);
-  }
-
-  char buf[GUID_STRLEN];
-  GuidToStr(&drive.pmbr.boot_guid, buf, sizeof(buf));
-  printf("%s\n", buf);
-
-  // Write it all out, if needed.
-  if (mode == O_RDONLY || CGPT_OK == WritePMBR(&drive))
-    retval = 0;
+int CgptBoot(CgptBootParams *params)
+{
+	struct drive drive;
+	int retval = 1;
+	int gpt_retval = 0;
+	int mode = O_RDONLY;
+
+	if (params == NULL)
+		return CGPT_FAILED;
+
+	if (params->create_pmbr || params->partition || params->bootfile)
+		mode = O_RDWR;
+
+	if (CGPT_OK != DriveOpen(params->drive_name, &drive, mode, params->drive_size)) {
+		return CGPT_FAILED;
+	}
+
+	if (CGPT_OK != ReadPMBR(&drive)) {
+		Error("Unable to read PMBR\n");
+		goto done;
+	}
+
+	if (params->create_pmbr) {
+		drive.pmbr.magic[0] = 0x1d;
+		drive.pmbr.magic[1] = 0x9a;
+		drive.pmbr.sig[0] = 0x55;
+		drive.pmbr.sig[1] = 0xaa;
+		memset(&drive.pmbr.part, 0, sizeof(drive.pmbr.part));
+		drive.pmbr.part[0].f_head = 0x00;
+		drive.pmbr.part[0].f_sect = 0x02;
+		drive.pmbr.part[0].f_cyl = 0x00;
+		drive.pmbr.part[0].type = 0xee;
+		drive.pmbr.part[0].l_head = 0xff;
+		drive.pmbr.part[0].l_sect = 0xff;
+		drive.pmbr.part[0].l_cyl = 0xff;
+		drive.pmbr.part[0].f_lba = htole32(1);
+		uint32_t max = 0xffffffff;
+		if (drive.gpt.streaming_drive_sectors < 0xffffffff)
+			max = drive.gpt.streaming_drive_sectors - 1;
+		drive.pmbr.part[0].num_sect = htole32(max);
+	}
+
+	if (params->partition) {
+		if (GPT_SUCCESS != (gpt_retval = GptValidityCheck(&drive.gpt))) {
+			Error("GptValidityCheck() returned %d: %s\n", gpt_retval,
+			      GptError(gpt_retval));
+			goto done;
+		}
+
+		if (params->partition > GetNumberOfEntries(&drive)) {
+			Error("invalid partition number: %d\n", params->partition);
+			goto done;
+		}
+
+		uint32_t index = params->partition - 1;
+		GptEntry *entry = GetEntry(&drive.gpt, ANY_VALID, index);
+		memcpy(&drive.pmbr.boot_guid, &entry->unique, sizeof(Guid));
+	}
+
+	if (params->bootfile) {
+		int fd = open(params->bootfile, O_RDONLY);
+		if (fd < 0) {
+			Error("Can't read %s: %s\n", params->bootfile, strerror(errno));
+			goto done;
+		}
+
+		int n = read(fd, drive.pmbr.bootcode, sizeof(drive.pmbr.bootcode));
+		if (n < 1) {
+			Error("problem reading %s: %s\n", params->bootfile, strerror(errno));
+			close(fd);
+			goto done;
+		}
+
+		close(fd);
+	}
+
+	char buf[GUID_STRLEN];
+	GptGuidToStr(&drive.pmbr.boot_guid, buf, sizeof(buf), GPT_GUID_UPPERCASE);
+	printf("%s\n", buf);
+
+	// Write it all out, if needed.
+	if (mode == O_RDONLY || CGPT_OK == WritePMBR(&drive))
+		retval = 0;
 
 done:
-  (void) DriveClose(&drive, 1);
-  return retval;
+	(void)DriveClose(&drive, 1);
+	return retval;
 }
diff --git a/cgpt/cgpt_common.c b/cgpt/cgpt_common.c
index e4629236..607c4c7f 100644
--- a/cgpt/cgpt_common.c
+++ b/cgpt/cgpt_common.c
@@ -32,374 +32,382 @@
 static const char kErrorTag[] = "ERROR";
 static const char kWarningTag[] = "WARNING";
 
-static void LogToStderr(const char *tag, const char *format, va_list ap) {
-  fprintf(stderr, "%s: ", tag);
-  vfprintf(stderr, format, ap);
+static void LogToStderr(const char *tag, const char *format, va_list ap)
+{
+	fprintf(stderr, "%s: ", tag);
+	vfprintf(stderr, format, ap);
 }
 
-void Error(const char *format, ...) {
-  va_list ap;
-  va_start(ap, format);
-  LogToStderr(kErrorTag, format, ap);
-  va_end(ap);
+void Error(const char *format, ...)
+{
+	va_list ap;
+	va_start(ap, format);
+	LogToStderr(kErrorTag, format, ap);
+	va_end(ap);
 }
 
-void Warning(const char *format, ...) {
-  va_list ap;
-  va_start(ap, format);
-  LogToStderr(kWarningTag, format, ap);
-  va_end(ap);
+void Warning(const char *format, ...)
+{
+	va_list ap;
+	va_start(ap, format);
+	LogToStderr(kWarningTag, format, ap);
+	va_end(ap);
 }
 
-int check_int_parse(char option, const char *buf) {
-  if (!*optarg || (buf && *buf)) {
-    Error("invalid argument to -%c: \"%s\"\n", option, optarg);
-    return 1;
-  }
-  return 0;
+int check_int_parse(char option, const char *buf)
+{
+	if (!*optarg || (buf && *buf)) {
+		Error("invalid argument to -%c: \"%s\"\n", option, optarg);
+		return 1;
+	}
+	return 0;
 }
 
-int check_int_limit(char option, int val, int low, int high) {
-  if (val < low || val > high) {
-    Error("value for -%c must be between %d and %d", option, low, high);
-    return 1;
-  }
-  return 0;
+int check_int_limit(char option, int val, int low, int high)
+{
+	if (val < low || val > high) {
+		Error("value for -%c must be between %d and %d", option, low, high);
+		return 1;
+	}
+	return 0;
 }
 
-int CheckValid(const struct drive *drive) {
-  if ((drive->gpt.valid_headers != MASK_BOTH) ||
-      (drive->gpt.valid_entries != MASK_BOTH)) {
-    Warning("One of the GPT headers/entries is invalid\n\n");
-    return CGPT_FAILED;
-  }
-  return CGPT_OK;
+int CheckValid(const struct drive *drive)
+{
+	if ((drive->gpt.valid_headers != MASK_BOTH) ||
+	    (drive->gpt.valid_entries != MASK_BOTH)) {
+		Warning("One of the GPT headers/entries is invalid\n\n");
+		return CGPT_FAILED;
+	}
+	return CGPT_OK;
 }
 
-int Load(struct drive *drive, uint8_t *buf,
-                const uint64_t sector,
-                const uint64_t sector_bytes,
-                const uint64_t sector_count) {
-  int count;  /* byte count to read */
-  int nread;
-
-  require(buf);
-  if (!sector_count || !sector_bytes) {
-    Error("%s() failed at line %d: sector_count=%" PRIu64 ", sector_bytes=%" PRIu64 "\n",
-          __FUNCTION__, __LINE__, sector_count, sector_bytes);
-    return CGPT_FAILED;
-  }
-  /* Make sure that sector_bytes * sector_count doesn't roll over. */
-  if (sector_bytes > (UINT64_MAX / sector_count)) {
-    Error("%s() failed at line %d: sector_count=%" PRIu64 ", sector_bytes=%" PRIu64 "\n",
-          __FUNCTION__, __LINE__, sector_count, sector_bytes);
-    return CGPT_FAILED;
-  }
-  count = sector_bytes * sector_count;
-
-  if (-1 == lseek(drive->fd, sector * sector_bytes, SEEK_SET)) {
-    Error("Can't seek: %s\n", strerror(errno));
-    return CGPT_FAILED;
-  }
-
-  nread = read(drive->fd, buf, count);
-  if (nread < count) {
-    Error("Can't read enough: %d, not %d\n", nread, count);
-    return CGPT_FAILED;
-  }
-
-  return CGPT_OK;
+int Load(struct drive *drive, uint8_t *buf, const uint64_t sector, const uint64_t sector_bytes,
+	 const uint64_t sector_count)
+{
+	int count; /* byte count to read */
+	int nread;
+
+	require(buf);
+	if (!sector_count || !sector_bytes) {
+		Error("%s() failed at line %d: sector_count=%" PRIu64 ", sector_bytes=%" PRIu64
+		      "\n",
+		      __FUNCTION__, __LINE__, sector_count, sector_bytes);
+		return CGPT_FAILED;
+	}
+	/* Make sure that sector_bytes * sector_count doesn't roll over. */
+	if (sector_bytes > (UINT64_MAX / sector_count)) {
+		Error("%s() failed at line %d: sector_count=%" PRIu64 ", sector_bytes=%" PRIu64
+		      "\n",
+		      __FUNCTION__, __LINE__, sector_count, sector_bytes);
+		return CGPT_FAILED;
+	}
+	count = sector_bytes * sector_count;
+
+	if (-1 == lseek(drive->fd, sector * sector_bytes, SEEK_SET)) {
+		Error("Can't seek: %s\n", strerror(errno));
+		return CGPT_FAILED;
+	}
+
+	nread = read(drive->fd, buf, count);
+	if (nread < count) {
+		Error("Can't read enough: %d, not %d\n", nread, count);
+		return CGPT_FAILED;
+	}
+
+	return CGPT_OK;
 }
 
+int ReadPMBR(struct drive *drive)
+{
+	if (-1 == lseek(drive->fd, 0, SEEK_SET))
+		return CGPT_FAILED;
 
-int ReadPMBR(struct drive *drive) {
-  if (-1 == lseek(drive->fd, 0, SEEK_SET))
-    return CGPT_FAILED;
-
-  int nread = read(drive->fd, &drive->pmbr, sizeof(struct pmbr));
-  if (nread != sizeof(struct pmbr))
-    return CGPT_FAILED;
+	int nread = read(drive->fd, &drive->pmbr, sizeof(struct pmbr));
+	if (nread != sizeof(struct pmbr))
+		return CGPT_FAILED;
 
-  return CGPT_OK;
+	return CGPT_OK;
 }
 
-int WritePMBR(struct drive *drive) {
-  if (-1 == lseek(drive->fd, 0, SEEK_SET))
-    return CGPT_FAILED;
+int WritePMBR(struct drive *drive)
+{
+	if (-1 == lseek(drive->fd, 0, SEEK_SET))
+		return CGPT_FAILED;
 
-  int nwrote = write(drive->fd, &drive->pmbr, sizeof(struct pmbr));
-  if (nwrote != sizeof(struct pmbr))
-    return CGPT_FAILED;
+	int nwrote = write(drive->fd, &drive->pmbr, sizeof(struct pmbr));
+	if (nwrote != sizeof(struct pmbr))
+		return CGPT_FAILED;
 
-  return CGPT_OK;
+	return CGPT_OK;
 }
 
-int Save(struct drive *drive, const uint8_t *buf,
-                const uint64_t sector,
-                const uint64_t sector_bytes,
-                const uint64_t sector_count) {
-  int count;  /* byte count to write */
-  int nwrote;
+int Save(struct drive *drive, const uint8_t *buf, const uint64_t sector,
+	 const uint64_t sector_bytes, const uint64_t sector_count)
+{
+	int count; /* byte count to write */
+	int nwrote;
 
-  require(buf);
-  count = sector_bytes * sector_count;
+	require(buf);
+	count = sector_bytes * sector_count;
 
-  if (-1 == lseek(drive->fd, sector * sector_bytes, SEEK_SET))
-    return CGPT_FAILED;
+	if (-1 == lseek(drive->fd, sector * sector_bytes, SEEK_SET))
+		return CGPT_FAILED;
 
-  nwrote = write(drive->fd, buf, count);
-  if (nwrote < count)
-    return CGPT_FAILED;
+	nwrote = write(drive->fd, buf, count);
+	if (nwrote < count)
+		return CGPT_FAILED;
 
-  return CGPT_OK;
+	return CGPT_OK;
 }
 
-static int GptLoad(struct drive *drive, uint32_t sector_bytes) {
-  drive->gpt.sector_bytes = sector_bytes;
-  if (drive->size % drive->gpt.sector_bytes) {
-    Error("Media size (%llu) is not a multiple of sector size(%d)\n",
-          (long long unsigned int)drive->size, drive->gpt.sector_bytes);
-    return -1;
-  }
-  drive->gpt.streaming_drive_sectors = drive->size / drive->gpt.sector_bytes;
-
-  drive->gpt.primary_header = malloc(drive->gpt.sector_bytes);
-  drive->gpt.secondary_header = malloc(drive->gpt.sector_bytes);
-  drive->gpt.primary_entries = malloc(GPT_ENTRIES_ALLOC_SIZE);
-  drive->gpt.secondary_entries = malloc(GPT_ENTRIES_ALLOC_SIZE);
-  if (!drive->gpt.primary_header || !drive->gpt.secondary_header ||
-      !drive->gpt.primary_entries || !drive->gpt.secondary_entries)
-    return -1;
-
-  /* TODO(namnguyen): Remove this and totally trust gpt_drive_sectors. */
-  if (!(drive->gpt.flags & GPT_FLAG_EXTERNAL)) {
-    drive->gpt.gpt_drive_sectors = drive->gpt.streaming_drive_sectors;
-  } /* Else, we trust gpt.gpt_drive_sectors. */
-
-  // Read the data.
-  if (CGPT_OK != Load(drive, drive->gpt.primary_header,
-                      GPT_PMBR_SECTORS,
-                      drive->gpt.sector_bytes, GPT_HEADER_SECTORS)) {
-    Error("Cannot read primary GPT header\n");
-    return -1;
-  }
-  if (CGPT_OK != Load(drive, drive->gpt.secondary_header,
-                      drive->gpt.gpt_drive_sectors - GPT_PMBR_SECTORS,
-                      drive->gpt.sector_bytes, GPT_HEADER_SECTORS)) {
-    Error("Cannot read secondary GPT header\n");
-    return -1;
-  }
-  GptHeader* primary_header = (GptHeader*)drive->gpt.primary_header;
-  if (CheckHeader(primary_header, 0, drive->gpt.streaming_drive_sectors,
-                  drive->gpt.gpt_drive_sectors,
-                  drive->gpt.flags,
-                  drive->gpt.sector_bytes) == 0) {
-    if (CGPT_OK != Load(drive, drive->gpt.primary_entries,
-                        primary_header->entries_lba,
-                        drive->gpt.sector_bytes,
-                        CalculateEntriesSectors(primary_header,
-                          drive->gpt.sector_bytes))) {
-      Error("Cannot read primary partition entry array\n");
-      return -1;
-    }
-  } else {
-    Warning("Primary GPT header is %s\n",
-      memcmp(primary_header->signature, GPT_HEADER_SIGNATURE_IGNORED,
-             GPT_HEADER_SIGNATURE_SIZE) ? "invalid" : "being ignored");
-  }
-  GptHeader* secondary_header = (GptHeader*)drive->gpt.secondary_header;
-  if (CheckHeader(secondary_header, 1, drive->gpt.streaming_drive_sectors,
-                  drive->gpt.gpt_drive_sectors,
-                  drive->gpt.flags,
-                  drive->gpt.sector_bytes) == 0) {
-    if (CGPT_OK != Load(drive, drive->gpt.secondary_entries,
-                        secondary_header->entries_lba,
-                        drive->gpt.sector_bytes,
-                        CalculateEntriesSectors(secondary_header,
-                          drive->gpt.sector_bytes))) {
-      Error("Cannot read secondary partition entry array\n");
-      return -1;
-    }
-  } else {
-    Warning("Secondary GPT header is %s\n",
-      memcmp(primary_header->signature, GPT_HEADER_SIGNATURE_IGNORED,
-             GPT_HEADER_SIGNATURE_SIZE) ? "invalid" : "being ignored");
-  }
-  return 0;
+static int GptLoad(struct drive *drive, uint32_t sector_bytes)
+{
+	drive->gpt.sector_bytes = sector_bytes;
+	if (drive->size % drive->gpt.sector_bytes) {
+		Error("Media size (%llu) is not a multiple of sector size(%d)\n",
+		      (long long unsigned int)drive->size, drive->gpt.sector_bytes);
+		return -1;
+	}
+	drive->gpt.streaming_drive_sectors = drive->size / drive->gpt.sector_bytes;
+
+	drive->gpt.primary_header = malloc(drive->gpt.sector_bytes);
+	drive->gpt.secondary_header = malloc(drive->gpt.sector_bytes);
+	drive->gpt.primary_entries = malloc(GPT_ENTRIES_ALLOC_SIZE);
+	drive->gpt.secondary_entries = malloc(GPT_ENTRIES_ALLOC_SIZE);
+	if (!drive->gpt.primary_header || !drive->gpt.secondary_header ||
+	    !drive->gpt.primary_entries || !drive->gpt.secondary_entries)
+		return -1;
+
+	/* TODO(namnguyen): Remove this and totally trust gpt_drive_sectors. */
+	if (!(drive->gpt.flags & GPT_FLAG_EXTERNAL)) {
+		drive->gpt.gpt_drive_sectors = drive->gpt.streaming_drive_sectors;
+	} /* Else, we trust gpt.gpt_drive_sectors. */
+
+	// Read the data.
+	if (CGPT_OK != Load(drive, drive->gpt.primary_header, GPT_PMBR_SECTORS,
+			    drive->gpt.sector_bytes, GPT_HEADER_SECTORS)) {
+		Error("Cannot read primary GPT header\n");
+		return -1;
+	}
+	if (CGPT_OK != Load(drive, drive->gpt.secondary_header,
+			    drive->gpt.gpt_drive_sectors - GPT_PMBR_SECTORS,
+			    drive->gpt.sector_bytes, GPT_HEADER_SECTORS)) {
+		Error("Cannot read secondary GPT header\n");
+		return -1;
+	}
+	GptHeader *primary_header = (GptHeader *)drive->gpt.primary_header;
+	if (CheckHeader(primary_header, 0, drive->gpt.streaming_drive_sectors,
+			drive->gpt.gpt_drive_sectors, drive->gpt.flags,
+			drive->gpt.sector_bytes) == 0) {
+		if (CGPT_OK !=
+		    Load(drive, drive->gpt.primary_entries, primary_header->entries_lba,
+			 drive->gpt.sector_bytes,
+			 CalculateEntriesSectors(primary_header, drive->gpt.sector_bytes))) {
+			Error("Cannot read primary partition entry array\n");
+			return -1;
+		}
+	} else {
+		Warning("Primary GPT header is %s\n",
+			memcmp(primary_header->signature, GPT_HEADER_SIGNATURE_IGNORED,
+			       GPT_HEADER_SIGNATURE_SIZE)
+				? "invalid"
+				: "being ignored");
+	}
+	GptHeader *secondary_header = (GptHeader *)drive->gpt.secondary_header;
+	if (CheckHeader(secondary_header, 1, drive->gpt.streaming_drive_sectors,
+			drive->gpt.gpt_drive_sectors, drive->gpt.flags,
+			drive->gpt.sector_bytes) == 0) {
+		if (CGPT_OK !=
+		    Load(drive, drive->gpt.secondary_entries, secondary_header->entries_lba,
+			 drive->gpt.sector_bytes,
+			 CalculateEntriesSectors(secondary_header, drive->gpt.sector_bytes))) {
+			Error("Cannot read secondary partition entry array\n");
+			return -1;
+		}
+	} else {
+		Warning("Secondary GPT header is %s\n",
+			memcmp(primary_header->signature, GPT_HEADER_SIGNATURE_IGNORED,
+			       GPT_HEADER_SIGNATURE_SIZE)
+				? "invalid"
+				: "being ignored");
+	}
+	return 0;
 }
 
-static int GptSave(struct drive *drive) {
-  int errors = 0;
-
-  if (!(drive->gpt.ignored & MASK_PRIMARY)) {
-    if (drive->gpt.modified & GPT_MODIFIED_HEADER1) {
-      if (CGPT_OK != Save(drive, drive->gpt.primary_header,
-                          GPT_PMBR_SECTORS,
-                          drive->gpt.sector_bytes, GPT_HEADER_SECTORS)) {
-        errors++;
-        Error("Cannot write primary header: %s\n", strerror(errno));
-      }
-    }
-    GptHeader* primary_header = (GptHeader*)drive->gpt.primary_header;
-    if (drive->gpt.modified & GPT_MODIFIED_ENTRIES1) {
-      if (CGPT_OK != Save(drive, drive->gpt.primary_entries,
-                          primary_header->entries_lba,
-                          drive->gpt.sector_bytes,
-                          CalculateEntriesSectors(primary_header,
-                            drive->gpt.sector_bytes))) {
-        errors++;
-        Error("Cannot write primary entries: %s\n", strerror(errno));
-      }
-    }
-
-    // Sync primary GPT before touching secondary so one is always valid.
-    if (drive->gpt.modified & (GPT_MODIFIED_HEADER1 | GPT_MODIFIED_ENTRIES1))
-      if (fsync(drive->fd) < 0 && errno == EIO) {
-        errors++;
-        Error("I/O error when trying to write primary GPT\n");
-      }
-  }
-
-  // Only start writing secondary GPT if primary was written correctly.
-  if (!errors && !(drive->gpt.ignored & MASK_SECONDARY)) {
-    if (drive->gpt.modified & GPT_MODIFIED_HEADER2) {
-      if (CGPT_OK != Save(drive, drive->gpt.secondary_header,
-                         drive->gpt.gpt_drive_sectors - GPT_PMBR_SECTORS,
-                         drive->gpt.sector_bytes, GPT_HEADER_SECTORS)) {
-        errors++;
-        Error("Cannot write secondary header: %s\n", strerror(errno));
-      }
-    }
-    GptHeader* secondary_header = (GptHeader*)drive->gpt.secondary_header;
-    if (drive->gpt.modified & GPT_MODIFIED_ENTRIES2) {
-      if (CGPT_OK != Save(drive, drive->gpt.secondary_entries,
-                          secondary_header->entries_lba,
-                          drive->gpt.sector_bytes,
-                          CalculateEntriesSectors(secondary_header,
-                            drive->gpt.sector_bytes))) {
-        errors++;
-        Error("Cannot write secondary entries: %s\n", strerror(errno));
-      }
-    }
-  }
-
-  return errors ? -1 : 0;
+static int GptSave(struct drive *drive)
+{
+	int errors = 0;
+
+	if (!(drive->gpt.ignored & MASK_PRIMARY)) {
+		if (drive->gpt.modified & GPT_MODIFIED_HEADER1) {
+			if (CGPT_OK != Save(drive, drive->gpt.primary_header, GPT_PMBR_SECTORS,
+					    drive->gpt.sector_bytes, GPT_HEADER_SECTORS)) {
+				errors++;
+				Error("Cannot write primary header: %s\n", strerror(errno));
+			}
+		}
+		GptHeader *primary_header = (GptHeader *)drive->gpt.primary_header;
+		if (drive->gpt.modified & GPT_MODIFIED_ENTRIES1) {
+			if (CGPT_OK != Save(drive, drive->gpt.primary_entries,
+					    primary_header->entries_lba,
+					    drive->gpt.sector_bytes,
+					    CalculateEntriesSectors(primary_header,
+								    drive->gpt.sector_bytes))) {
+				errors++;
+				Error("Cannot write primary entries: %s\n", strerror(errno));
+			}
+		}
+
+		// Sync primary GPT before touching secondary so one is always valid.
+		if (drive->gpt.modified & (GPT_MODIFIED_HEADER1 | GPT_MODIFIED_ENTRIES1))
+			if (fsync(drive->fd) < 0 && errno == EIO) {
+				errors++;
+				Error("I/O error when trying to write primary GPT\n");
+			}
+	}
+
+	// Only start writing secondary GPT if primary was written correctly.
+	if (!errors && !(drive->gpt.ignored & MASK_SECONDARY)) {
+		if (drive->gpt.modified & GPT_MODIFIED_HEADER2) {
+			if (CGPT_OK != Save(drive, drive->gpt.secondary_header,
+					    drive->gpt.gpt_drive_sectors - GPT_PMBR_SECTORS,
+					    drive->gpt.sector_bytes, GPT_HEADER_SECTORS)) {
+				errors++;
+				Error("Cannot write secondary header: %s\n", strerror(errno));
+			}
+		}
+		GptHeader *secondary_header = (GptHeader *)drive->gpt.secondary_header;
+		if (drive->gpt.modified & GPT_MODIFIED_ENTRIES2) {
+			if (CGPT_OK != Save(drive, drive->gpt.secondary_entries,
+					    secondary_header->entries_lba,
+					    drive->gpt.sector_bytes,
+					    CalculateEntriesSectors(secondary_header,
+								    drive->gpt.sector_bytes))) {
+				errors++;
+				Error("Cannot write secondary entries: %s\n", strerror(errno));
+			}
+		}
+	}
+
+	return errors ? -1 : 0;
 }
 
 /*
  * Query drive size and bytes per sector. Return zero on success. On error,
  * -1 is returned and errno is set appropriately.
  */
-static int ObtainDriveSize(int fd, uint64_t* size, uint32_t* sector_bytes) {
-  struct stat stat;
-  if (fstat(fd, &stat) == -1) {
-    return -1;
-  }
+static int ObtainDriveSize(int fd, uint64_t *size, uint32_t *sector_bytes)
+{
+	struct stat stat;
+	if (fstat(fd, &stat) == -1) {
+		return -1;
+	}
 #if !defined(HAVE_MACOS) && !defined(__FreeBSD__) && !defined(__OpenBSD__)
-  if ((stat.st_mode & S_IFMT) != S_IFREG) {
-    if (ioctl(fd, BLKGETSIZE64, size) < 0) {
-      return -1;
-    }
-    if (ioctl(fd, BLKSSZGET, sector_bytes) < 0) {
-      return -1;
-    }
-  } else {
-    *sector_bytes = 512;  /* bytes */
-    *size = stat.st_size;
-  }
+	if ((stat.st_mode & S_IFMT) != S_IFREG) {
+		if (ioctl(fd, BLKGETSIZE64, size) < 0) {
+			return -1;
+		}
+		if (ioctl(fd, BLKSSZGET, sector_bytes) < 0) {
+			return -1;
+		}
+	} else {
+		*sector_bytes = 512; /* bytes */
+		*size = stat.st_size;
+	}
 #else
-  *sector_bytes = 512;  /* bytes */
-  *size = stat.st_size;
+	*sector_bytes = 512; /* bytes */
+	*size = stat.st_size;
 #endif
-  return 0;
+	return 0;
 }
 
-int DriveOpen(const char *drive_path, struct drive *drive, int mode,
-              uint64_t drive_size) {
-  uint32_t sector_bytes;
+int DriveOpen(const char *drive_path, struct drive *drive, int mode, uint64_t drive_size)
+{
+	uint32_t sector_bytes;
 
-  require(drive_path);
-  require(drive);
+	require(drive_path);
+	require(drive);
 
-  // Clear struct for proper error handling.
-  memset(drive, 0, sizeof(struct drive));
+	// Clear struct for proper error handling.
+	memset(drive, 0, sizeof(struct drive));
 
-  drive->fd = open(drive_path, mode |
+	drive->fd = open(drive_path, mode |
 #if !defined(HAVE_MACOS) && !defined(__FreeBSD__) && !defined(__OpenBSD__)
-		               O_LARGEFILE |
+					     O_LARGEFILE |
 #endif
-			       O_NOFOLLOW);
-  if (drive->fd == -1) {
-    Error("Can't open %s: %s\n", drive_path, strerror(errno));
-    return CGPT_FAILED;
-  }
-
-  uint64_t gpt_drive_size;
-  if (ObtainDriveSize(drive->fd, &gpt_drive_size, &sector_bytes) != 0) {
-    Error("Can't get drive size and bytes per sector for %s: %s\n",
-          drive_path, strerror(errno));
-    goto error_close;
-  }
-
-  drive->gpt.gpt_drive_sectors = gpt_drive_size / sector_bytes;
-  if (drive_size == 0) {
-    drive->size = gpt_drive_size;
-    drive->gpt.flags = 0;
-  } else {
-    drive->size = drive_size;
-    drive->gpt.flags = GPT_FLAG_EXTERNAL;
-  }
-
-
-  if (GptLoad(drive, sector_bytes)) {
-    goto error_close;
-  }
-
-  // We just load the data. Caller must validate it.
-  return CGPT_OK;
+					     O_NOFOLLOW);
+	if (drive->fd == -1) {
+		Error("Can't open %s: %s\n", drive_path, strerror(errno));
+		return CGPT_FAILED;
+	}
+
+	uint64_t gpt_drive_size;
+	if (ObtainDriveSize(drive->fd, &gpt_drive_size, &sector_bytes) != 0) {
+		Error("Can't get drive size and bytes per sector for %s: %s\n", drive_path,
+		      strerror(errno));
+		goto error_close;
+	}
+
+	drive->gpt.gpt_drive_sectors = gpt_drive_size / sector_bytes;
+	if (drive_size == 0) {
+		drive->size = gpt_drive_size;
+		drive->gpt.flags = 0;
+	} else {
+		drive->size = drive_size;
+		drive->gpt.flags = GPT_FLAG_EXTERNAL;
+	}
+
+	if (GptLoad(drive, sector_bytes)) {
+		goto error_close;
+	}
+
+	// We just load the data. Caller must validate it.
+	return CGPT_OK;
 
 error_close:
-  (void) DriveClose(drive, 0);
-  return CGPT_FAILED;
+	(void)DriveClose(drive, 0);
+	return CGPT_FAILED;
 }
 
-
-int DriveClose(struct drive *drive, int update_as_needed) {
-  int errors = 0;
-
-  if (update_as_needed) {
-    if (GptSave(drive)) {
-        errors++;
-    }
-  }
-
-  free(drive->gpt.primary_header);
-  drive->gpt.primary_header = NULL;
-  free(drive->gpt.primary_entries);
-  drive->gpt.primary_entries = NULL;
-  free(drive->gpt.secondary_header);
-  drive->gpt.secondary_header = NULL;
-  free(drive->gpt.secondary_entries);
-  drive->gpt.secondary_entries = NULL;
-
-  // Sync early! Only sync file descriptor here, and leave the whole system sync
-  // outside cgpt because whole system sync would trigger tons of disk accesses
-  // and timeout tests.
-  fsync(drive->fd);
-
-  close(drive->fd);
-
-  return errors ? CGPT_FAILED : CGPT_OK;
+int DriveClose(struct drive *drive, int update_as_needed)
+{
+	int errors = 0;
+
+	if (update_as_needed) {
+		if (GptSave(drive)) {
+			errors++;
+		}
+	}
+
+	free(drive->gpt.primary_header);
+	drive->gpt.primary_header = NULL;
+	free(drive->gpt.primary_entries);
+	drive->gpt.primary_entries = NULL;
+	free(drive->gpt.secondary_header);
+	drive->gpt.secondary_header = NULL;
+	free(drive->gpt.secondary_entries);
+	drive->gpt.secondary_entries = NULL;
+
+	// Sync early! Only sync file descriptor here, and leave the whole system sync
+	// outside cgpt because whole system sync would trigger tons of disk accesses
+	// and timeout tests.
+	fsync(drive->fd);
+
+	close(drive->fd);
+
+	return errors ? CGPT_FAILED : CGPT_OK;
 }
 
-uint64_t DriveLastUsableLBA(const struct drive *drive) {
-  GptHeader *h = (GptHeader *)drive->gpt.primary_header;
+uint64_t DriveLastUsableLBA(const struct drive *drive)
+{
+	GptHeader *h = (GptHeader *)drive->gpt.primary_header;
 
-  if (!(drive->gpt.flags & GPT_FLAG_EXTERNAL))
-    return (drive->gpt.streaming_drive_sectors - GPT_HEADER_SECTORS
-            - CalculateEntriesSectors(h, drive->gpt.sector_bytes) - 1);
+	if (!(drive->gpt.flags & GPT_FLAG_EXTERNAL))
+		return (drive->gpt.streaming_drive_sectors - GPT_HEADER_SECTORS -
+			CalculateEntriesSectors(h, drive->gpt.sector_bytes) - 1);
 
-  return (drive->gpt.streaming_drive_sectors - 1);
+	return (drive->gpt.streaming_drive_sectors - 1);
 }
 
 /* GUID conversion functions. Accepted format:
@@ -408,59 +416,38 @@ uint64_t DriveLastUsableLBA(const struct drive *drive) {
  *
  * Returns CGPT_OK if parsing is successful; otherwise CGPT_FAILED.
  */
-int StrToGuid(const char *str, Guid *guid) {
-  uint32_t time_low;
-  uint16_t time_mid;
-  uint16_t time_high_and_version;
-  unsigned int chunk[11];
-
-  if (11 != sscanf(str, "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
-                   chunk+0,
-                   chunk+1,
-                   chunk+2,
-                   chunk+3,
-                   chunk+4,
-                   chunk+5,
-                   chunk+6,
-                   chunk+7,
-                   chunk+8,
-                   chunk+9,
-                   chunk+10)) {
-    printf("FAILED\n");
-    return CGPT_FAILED;
-  }
-
-  time_low = chunk[0] & 0xffffffff;
-  time_mid = chunk[1] & 0xffff;
-  time_high_and_version = chunk[2] & 0xffff;
-
-  guid->u.Uuid.time_low = htole32(time_low);
-  guid->u.Uuid.time_mid = htole16(time_mid);
-  guid->u.Uuid.time_high_and_version = htole16(time_high_and_version);
-
-  guid->u.Uuid.clock_seq_high_and_reserved = chunk[3] & 0xff;
-  guid->u.Uuid.clock_seq_low = chunk[4] & 0xff;
-  guid->u.Uuid.node[0] = chunk[5] & 0xff;
-  guid->u.Uuid.node[1] = chunk[6] & 0xff;
-  guid->u.Uuid.node[2] = chunk[7] & 0xff;
-  guid->u.Uuid.node[3] = chunk[8] & 0xff;
-  guid->u.Uuid.node[4] = chunk[9] & 0xff;
-  guid->u.Uuid.node[5] = chunk[10] & 0xff;
-
-  return CGPT_OK;
-}
-void GuidToStr(const Guid *guid, char *str, unsigned int buflen) {
-  require(buflen >= GUID_STRLEN);
-  require(snprintf(str, buflen,
-                  "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
-                  le32toh(guid->u.Uuid.time_low),
-                  le16toh(guid->u.Uuid.time_mid),
-                  le16toh(guid->u.Uuid.time_high_and_version),
-                  guid->u.Uuid.clock_seq_high_and_reserved,
-                  guid->u.Uuid.clock_seq_low,
-                  guid->u.Uuid.node[0], guid->u.Uuid.node[1],
-                  guid->u.Uuid.node[2], guid->u.Uuid.node[3],
-                  guid->u.Uuid.node[4], guid->u.Uuid.node[5]) == GUID_STRLEN-1);
+int GptStrToGuid(const char *str, Guid *guid)
+{
+	uint32_t time_low;
+	uint16_t time_mid;
+	uint16_t time_high_and_version;
+	unsigned int chunk[11];
+
+	if (11 != sscanf(str, "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X", chunk + 0,
+			 chunk + 1, chunk + 2, chunk + 3, chunk + 4, chunk + 5, chunk + 6,
+			 chunk + 7, chunk + 8, chunk + 9, chunk + 10)) {
+		printf("FAILED\n");
+		return CGPT_FAILED;
+	}
+
+	time_low = chunk[0] & 0xffffffff;
+	time_mid = chunk[1] & 0xffff;
+	time_high_and_version = chunk[2] & 0xffff;
+
+	guid->u.Uuid.time_low = htole32(time_low);
+	guid->u.Uuid.time_mid = htole16(time_mid);
+	guid->u.Uuid.time_high_and_version = htole16(time_high_and_version);
+
+	guid->u.Uuid.clock_seq_high_and_reserved = chunk[3] & 0xff;
+	guid->u.Uuid.clock_seq_low = chunk[4] & 0xff;
+	guid->u.Uuid.node[0] = chunk[5] & 0xff;
+	guid->u.Uuid.node[1] = chunk[6] & 0xff;
+	guid->u.Uuid.node[2] = chunk[7] & 0xff;
+	guid->u.Uuid.node[3] = chunk[8] & 0xff;
+	guid->u.Uuid.node[4] = chunk[9] & 0xff;
+	guid->u.Uuid.node[5] = chunk[10] & 0xff;
+
+	return CGPT_OK;
 }
 
 /* Convert possibly unterminated UTF16 string to UTF8.
@@ -481,76 +468,74 @@ void GuidToStr(const Guid *guid, char *str, unsigned int buflen) {
  * Return: CGPT_OK --- all character are converted successfully.
  *         CGPT_FAILED --- convert error, i.e. output buffer is too short.
  */
-int UTF16ToUTF8(const uint16_t *utf16, unsigned int maxinput,
-                uint8_t *utf8, unsigned int maxoutput)
+int UTF16ToUTF8(const uint16_t *utf16, unsigned int maxinput, uint8_t *utf8,
+		unsigned int maxoutput)
 {
-  size_t s16idx, s8idx;
-  uint32_t code_point = 0;
-  int code_point_ready = 1;  // code point is ready to output.
-  int retval = CGPT_OK;
-
-  if (!utf16 || !maxinput || !utf8 || !maxoutput)
-    return CGPT_FAILED;
-
-  maxoutput--;                             /* plan for termination now */
-
-  for (s16idx = s8idx = 0;
-       s16idx < maxinput && utf16[s16idx] && maxoutput;
-       s16idx++) {
-    uint16_t codeunit = le16toh(utf16[s16idx]);
-
-    if (code_point_ready) {
-      if (codeunit >= 0xD800 && codeunit <= 0xDBFF) {
-        /* high surrogate, need the low surrogate. */
-        code_point_ready = 0;
-        code_point = (codeunit & 0x03FF) + 0x0040;
-      } else {
-        /* BMP char, output it. */
-        code_point = codeunit;
-      }
-    } else {
-      /* expect the low surrogate */
-      if (codeunit >= 0xDC00 && codeunit <= 0xDFFF) {
-        code_point = (code_point << 10) | (codeunit & 0x03FF);
-        code_point_ready = 1;
-      } else {
-        /* the second code unit is NOT the low surrogate. Unexpected. */
-        code_point_ready = 0;
-        retval = CGPT_FAILED;
-        break;
-      }
-    }
-
-    /* If UTF code point is ready, output it. */
-    if (code_point_ready) {
-      require(code_point <= 0x10FFFF);
-      if (code_point <= 0x7F && maxoutput >= 1) {
-        maxoutput -= 1;
-        utf8[s8idx++] = code_point & 0x7F;
-      } else if (code_point <= 0x7FF && maxoutput >= 2) {
-        maxoutput -= 2;
-        utf8[s8idx++] = 0xC0 | (code_point >> 6);
-        utf8[s8idx++] = 0x80 | (code_point & 0x3F);
-      } else if (code_point <= 0xFFFF && maxoutput >= 3) {
-        maxoutput -= 3;
-        utf8[s8idx++] = 0xE0 | (code_point >> 12);
-        utf8[s8idx++] = 0x80 | ((code_point >> 6) & 0x3F);
-        utf8[s8idx++] = 0x80 | (code_point & 0x3F);
-      } else if (code_point <= 0x10FFFF && maxoutput >= 4) {
-        maxoutput -= 4;
-        utf8[s8idx++] = 0xF0 | (code_point >> 18);
-        utf8[s8idx++] = 0x80 | ((code_point >> 12) & 0x3F);
-        utf8[s8idx++] = 0x80 | ((code_point >> 6) & 0x3F);
-        utf8[s8idx++] = 0x80 | (code_point & 0x3F);
-      } else {
-        /* buffer underrun */
-        retval = CGPT_FAILED;
-        break;
-      }
-    }
-  }
-  utf8[s8idx++] = 0;
-  return retval;
+	size_t s16idx, s8idx;
+	uint32_t code_point = 0;
+	int code_point_ready = 1; // code point is ready to output.
+	int retval = CGPT_OK;
+
+	if (!utf16 || !maxinput || !utf8 || !maxoutput)
+		return CGPT_FAILED;
+
+	maxoutput--; /* plan for termination now */
+
+	for (s16idx = s8idx = 0; s16idx < maxinput && utf16[s16idx] && maxoutput; s16idx++) {
+		uint16_t codeunit = le16toh(utf16[s16idx]);
+
+		if (code_point_ready) {
+			if (codeunit >= 0xD800 && codeunit <= 0xDBFF) {
+				/* high surrogate, need the low surrogate. */
+				code_point_ready = 0;
+				code_point = (codeunit & 0x03FF) + 0x0040;
+			} else {
+				/* BMP char, output it. */
+				code_point = codeunit;
+			}
+		} else {
+			/* expect the low surrogate */
+			if (codeunit >= 0xDC00 && codeunit <= 0xDFFF) {
+				code_point = (code_point << 10) | (codeunit & 0x03FF);
+				code_point_ready = 1;
+			} else {
+				/* the second code unit is NOT the low surrogate. Unexpected. */
+				code_point_ready = 0;
+				retval = CGPT_FAILED;
+				break;
+			}
+		}
+
+		/* If UTF code point is ready, output it. */
+		if (code_point_ready) {
+			require(code_point <= 0x10FFFF);
+			if (code_point <= 0x7F && maxoutput >= 1) {
+				maxoutput -= 1;
+				utf8[s8idx++] = code_point & 0x7F;
+			} else if (code_point <= 0x7FF && maxoutput >= 2) {
+				maxoutput -= 2;
+				utf8[s8idx++] = 0xC0 | (code_point >> 6);
+				utf8[s8idx++] = 0x80 | (code_point & 0x3F);
+			} else if (code_point <= 0xFFFF && maxoutput >= 3) {
+				maxoutput -= 3;
+				utf8[s8idx++] = 0xE0 | (code_point >> 12);
+				utf8[s8idx++] = 0x80 | ((code_point >> 6) & 0x3F);
+				utf8[s8idx++] = 0x80 | (code_point & 0x3F);
+			} else if (code_point <= 0x10FFFF && maxoutput >= 4) {
+				maxoutput -= 4;
+				utf8[s8idx++] = 0xF0 | (code_point >> 18);
+				utf8[s8idx++] = 0x80 | ((code_point >> 12) & 0x3F);
+				utf8[s8idx++] = 0x80 | ((code_point >> 6) & 0x3F);
+				utf8[s8idx++] = 0x80 | (code_point & 0x3F);
+			} else {
+				/* buffer underrun */
+				retval = CGPT_FAILED;
+				break;
+			}
+		}
+	}
+	utf8[s8idx++] = 0;
+	return retval;
 }
 
 /* Convert UTF8 string to UTF16. The UTF8 string must be null-terminated.
@@ -572,375 +557,374 @@ int UTF16ToUTF8(const uint16_t *utf16, unsigned int maxinput,
  */
 int UTF8ToUTF16(const uint8_t *utf8, uint16_t *utf16, unsigned int maxoutput)
 {
-  size_t s16idx, s8idx;
-  uint32_t code_point = 0;
-  unsigned int expected_units = 1;
-  unsigned int decoded_units = 1;
-  int retval = CGPT_OK;
-
-  if (!utf8 || !utf16 || !maxoutput)
-    return CGPT_FAILED;
-
-  maxoutput--;                             /* plan for termination */
-
-  for (s8idx = s16idx = 0;
-       utf8[s8idx] && maxoutput;
-       s8idx++) {
-    uint8_t code_unit;
-    code_unit = utf8[s8idx];
-
-    if (expected_units != decoded_units) {
-      /* Trailing bytes of multi-byte character */
-      if ((code_unit & 0xC0) == 0x80) {
-        code_point = (code_point << 6) | (code_unit & 0x3F);
-        ++decoded_units;
-      } else {
-        /* Unexpected code unit. */
-        retval = CGPT_FAILED;
-        break;
-      }
-    } else {
-      /* parsing a new code point. */
-      decoded_units = 1;
-      if (code_unit <= 0x7F) {
-        code_point = code_unit;
-        expected_units = 1;
-      } else if (code_unit <= 0xBF) {
-        /* 0x80-0xBF must NOT be the heading byte unit of a new code point. */
-        retval = CGPT_FAILED;
-        break;
-      } else if (code_unit >= 0xC2 && code_unit <= 0xDF) {
-        code_point = code_unit & 0x1F;
-        expected_units = 2;
-      } else if (code_unit >= 0xE0 && code_unit <= 0xEF) {
-        code_point = code_unit & 0x0F;
-        expected_units = 3;
-      } else if (code_unit >= 0xF0 && code_unit <= 0xF4) {
-        code_point = code_unit & 0x07;
-        expected_units = 4;
-      } else {
-        /* illegal code unit: 0xC0-0xC1, 0xF5-0xFF */
-        retval = CGPT_FAILED;
-        break;
-      }
-    }
-
-    /* If no more unit is needed, output the UTF16 unit(s). */
-    if ((retval == CGPT_OK) &&
-        (expected_units == decoded_units)) {
-      /* Check if the encoding is the shortest possible UTF-8 sequence. */
-      switch (expected_units) {
-        case 2:
-          if (code_point <= 0x7F) retval = CGPT_FAILED;
-          break;
-        case 3:
-          if (code_point <= 0x7FF) retval = CGPT_FAILED;
-          break;
-        case 4:
-          if (code_point <= 0xFFFF) retval = CGPT_FAILED;
-          break;
-      }
-      if (retval == CGPT_FAILED) break;  /* leave immediately */
-
-      if ((code_point <= 0xD7FF) ||
-          (code_point >= 0xE000 && code_point <= 0xFFFF)) {
-        utf16[s16idx++] = code_point;
-        maxoutput -= 1;
-      } else if (code_point >= 0x10000 && code_point <= 0x10FFFF &&
-                 maxoutput >= 2) {
-        utf16[s16idx++] = 0xD800 | ((code_point >> 10) - 0x0040);
-        utf16[s16idx++] = 0xDC00 | (code_point & 0x03FF);
-        maxoutput -= 2;
-      } else {
-        /* Three possibilities fall into here. Both are failure cases.
-         *   a. surrogate pair (non-BMP characters; 0xD800~0xDFFF)
-         *   b. invalid code point > 0x10FFFF
-         *   c. buffer underrun
-         */
-        retval = CGPT_FAILED;
-        break;
-      }
-    }
-  }
-
-  /* A null-terminator shows up before the UTF8 sequence ends. */
-  if (expected_units != decoded_units) {
-    retval = CGPT_FAILED;
-  }
-
-  utf16[s16idx++] = 0;
-  return retval;
+	size_t s16idx, s8idx;
+	uint32_t code_point = 0;
+	unsigned int expected_units = 1;
+	unsigned int decoded_units = 1;
+	int retval = CGPT_OK;
+
+	if (!utf8 || !utf16 || !maxoutput)
+		return CGPT_FAILED;
+
+	maxoutput--; /* plan for termination */
+
+	for (s8idx = s16idx = 0; utf8[s8idx] && maxoutput; s8idx++) {
+		uint8_t code_unit;
+		code_unit = utf8[s8idx];
+
+		if (expected_units != decoded_units) {
+			/* Trailing bytes of multi-byte character */
+			if ((code_unit & 0xC0) == 0x80) {
+				code_point = (code_point << 6) | (code_unit & 0x3F);
+				++decoded_units;
+			} else {
+				/* Unexpected code unit. */
+				retval = CGPT_FAILED;
+				break;
+			}
+		} else {
+			/* parsing a new code point. */
+			decoded_units = 1;
+			if (code_unit <= 0x7F) {
+				code_point = code_unit;
+				expected_units = 1;
+			} else if (code_unit <= 0xBF) {
+				/* 0x80-0xBF must NOT be the heading byte unit of a new code
+				 * point. */
+				retval = CGPT_FAILED;
+				break;
+			} else if (code_unit >= 0xC2 && code_unit <= 0xDF) {
+				code_point = code_unit & 0x1F;
+				expected_units = 2;
+			} else if (code_unit >= 0xE0 && code_unit <= 0xEF) {
+				code_point = code_unit & 0x0F;
+				expected_units = 3;
+			} else if (code_unit >= 0xF0 && code_unit <= 0xF4) {
+				code_point = code_unit & 0x07;
+				expected_units = 4;
+			} else {
+				/* illegal code unit: 0xC0-0xC1, 0xF5-0xFF */
+				retval = CGPT_FAILED;
+				break;
+			}
+		}
+
+		/* If no more unit is needed, output the UTF16 unit(s). */
+		if ((retval == CGPT_OK) && (expected_units == decoded_units)) {
+			/* Check if the encoding is the shortest possible UTF-8 sequence. */
+			switch (expected_units) {
+			case 2:
+				if (code_point <= 0x7F)
+					retval = CGPT_FAILED;
+				break;
+			case 3:
+				if (code_point <= 0x7FF)
+					retval = CGPT_FAILED;
+				break;
+			case 4:
+				if (code_point <= 0xFFFF)
+					retval = CGPT_FAILED;
+				break;
+			}
+			if (retval == CGPT_FAILED)
+				break; /* leave immediately */
+
+			if ((code_point <= 0xD7FF) ||
+			    (code_point >= 0xE000 && code_point <= 0xFFFF)) {
+				utf16[s16idx++] = code_point;
+				maxoutput -= 1;
+			} else if (code_point >= 0x10000 && code_point <= 0x10FFFF &&
+				   maxoutput >= 2) {
+				utf16[s16idx++] = 0xD800 | ((code_point >> 10) - 0x0040);
+				utf16[s16idx++] = 0xDC00 | (code_point & 0x03FF);
+				maxoutput -= 2;
+			} else {
+				/* Three possibilities fall into here. Both are failure cases.
+				 *   a. surrogate pair (non-BMP characters; 0xD800~0xDFFF)
+				 *   b. invalid code point > 0x10FFFF
+				 *   c. buffer underrun
+				 */
+				retval = CGPT_FAILED;
+				break;
+			}
+		}
+	}
+
+	/* A null-terminator shows up before the UTF8 sequence ends. */
+	if (expected_units != decoded_units) {
+		retval = CGPT_FAILED;
+	}
+
+	utf16[s16idx++] = 0;
+	return retval;
 }
 
-/* global types to compare against */
-const Guid guid_chromeos_firmware = GPT_ENT_TYPE_CHROMEOS_FIRMWARE;
-const Guid guid_chromeos_kernel =   GPT_ENT_TYPE_CHROMEOS_KERNEL;
-const Guid guid_chromeos_rootfs =   GPT_ENT_TYPE_CHROMEOS_ROOTFS;
-const Guid guid_android_vbmeta =    GPT_ENT_TYPE_ANDROID_VBMETA;
-const Guid guid_basic_data =        GPT_ENT_TYPE_BASIC_DATA;
-const Guid guid_linux_data =        GPT_ENT_TYPE_LINUX_FS;
-const Guid guid_chromeos_reserved = GPT_ENT_TYPE_CHROMEOS_RESERVED;
-const Guid guid_efi =               GPT_ENT_TYPE_EFI;
-const Guid guid_unused =            GPT_ENT_TYPE_UNUSED;
-const Guid guid_chromeos_minios =   GPT_ENT_TYPE_CHROMEOS_MINIOS;
-const Guid guid_chromeos_hibernate = GPT_ENT_TYPE_CHROMEOS_HIBERNATE;
-
 static const struct {
-  const Guid *type;
-  const char *name;
-  const char *description;
+	const Guid *type;
+	const char *name;
+	const char *description;
 } supported_types[] = {
-  {&guid_chromeos_firmware, "firmware", "ChromeOS firmware"},
-  {&guid_chromeos_kernel, "kernel", "ChromeOS kernel"},
-  {&guid_chromeos_rootfs, "rootfs", "ChromeOS rootfs"},
-  {&guid_android_vbmeta, "vbmeta", "Android vbmeta"},
-  {&guid_linux_data, "data", "Linux data"},
-  {&guid_basic_data, "basicdata", "Basic data"},
-  {&guid_chromeos_reserved, "reserved", "ChromeOS reserved"},
-  {&guid_efi, "efi", "EFI System Partition"},
-  {&guid_unused, "unused", "Unused (nonexistent) partition"},
-  {&guid_chromeos_minios, "minios", "ChromeOS miniOS"},
-  {&guid_chromeos_hibernate, "hibernate", "ChromeOS hibernate"},
+	{&guid_chromeos_firmware, "firmware", "ChromeOS firmware"},
+	{&guid_chromeos_kernel, "kernel", "ChromeOS kernel"},
+	{&guid_chromeos_rootfs, "rootfs", "ChromeOS rootfs"},
+	{&guid_android_vbmeta, "vbmeta", "Android vbmeta"},
+	{&guid_linux_data, "data", "Linux data"},
+	{&guid_basic_data, "basicdata", "Basic data"},
+	{&guid_chromeos_reserved, "reserved", "ChromeOS reserved"},
+	{&guid_efi, "efi", "EFI System Partition"},
+	{&guid_unused, "unused", "Unused (nonexistent) partition"},
+	{&guid_chromeos_minios, "minios", "ChromeOS miniOS"},
+	{&guid_chromeos_hibernate, "hibernate", "ChromeOS hibernate"},
 };
 
 /* Resolves human-readable GPT type.
  * Returns CGPT_OK if found.
  * Returns CGPT_FAILED if no known type found. */
-int ResolveType(const Guid *type, char *buf) {
-  int i;
-  for (i = 0; i < ARRAY_COUNT(supported_types); ++i) {
-    if (!memcmp(type, supported_types[i].type, sizeof(Guid))) {
-      strcpy(buf, supported_types[i].description);
-      return CGPT_OK;
-    }
-  }
-  return CGPT_FAILED;
+int ResolveType(const Guid *type, char *buf)
+{
+	int i;
+	for (i = 0; i < ARRAY_COUNT(supported_types); ++i) {
+		if (!memcmp(type, supported_types[i].type, sizeof(Guid))) {
+			strcpy(buf, supported_types[i].description);
+			return CGPT_OK;
+		}
+	}
+	return CGPT_FAILED;
 }
 
-int SupportedType(const char *name, Guid *type) {
-  int i;
-  for (i = 0; i < ARRAY_COUNT(supported_types); ++i) {
-    if (!strcmp(name, supported_types[i].name)) {
-      memcpy(type, supported_types[i].type, sizeof(Guid));
-      return CGPT_OK;
-    }
-  }
-  return CGPT_FAILED;
+int SupportedType(const char *name, Guid *type)
+{
+	int i;
+	for (i = 0; i < ARRAY_COUNT(supported_types); ++i) {
+		if (!strcmp(name, supported_types[i].name)) {
+			memcpy(type, supported_types[i].type, sizeof(Guid));
+			return CGPT_OK;
+		}
+	}
+	return CGPT_FAILED;
 }
 
-void PrintTypes(void) {
-  int i;
-  printf("The partition type may also be given as one of these aliases:\n\n");
-  for (i = 0; i < ARRAY_COUNT(supported_types); ++i) {
-    printf("    %-10s  %s\n", supported_types[i].name,
-                          supported_types[i].description);
-  }
-  printf("\n");
+void PrintTypes(void)
+{
+	int i;
+	printf("The partition type may also be given as one of these aliases:\n\n");
+	for (i = 0; i < ARRAY_COUNT(supported_types); ++i) {
+		printf("    %-10s  %s\n", supported_types[i].name,
+		       supported_types[i].description);
+	}
+	printf("\n");
 }
 
-static GptHeader* GetGptHeader(const GptData *gpt) {
-  if (gpt->valid_headers & MASK_PRIMARY)
-    return (GptHeader*)gpt->primary_header;
-  else if (gpt->valid_headers & MASK_SECONDARY)
-    return (GptHeader*)gpt->secondary_header;
-  else
-    return 0;
+static GptHeader *GetGptHeader(const GptData *gpt)
+{
+	if (gpt->valid_headers & MASK_PRIMARY)
+		return (GptHeader *)gpt->primary_header;
+	else if (gpt->valid_headers & MASK_SECONDARY)
+		return (GptHeader *)gpt->secondary_header;
+	else
+		return 0;
 }
 
-uint32_t GetNumberOfEntries(const struct drive *drive) {
-  GptHeader *header = GetGptHeader(&drive->gpt);
-  if (!header)
-    return 0;
-  return header->number_of_entries;
+uint32_t GetNumberOfEntries(const struct drive *drive)
+{
+	GptHeader *header = GetGptHeader(&drive->gpt);
+	if (!header)
+		return 0;
+	return header->number_of_entries;
 }
 
-
-GptEntry *GetEntry(GptData *gpt, int secondary, uint32_t entry_index) {
-  GptHeader *header = GetGptHeader(gpt);
-  uint8_t *entries;
-  uint32_t stride = header->size_of_entry;
-  require(stride);
-  require(entry_index < header->number_of_entries);
-
-  if (secondary == PRIMARY) {
-    entries = gpt->primary_entries;
-  } else if (secondary == SECONDARY) {
-    entries = gpt->secondary_entries;
-  } else {  /* ANY_VALID */
-    require(secondary == ANY_VALID);
-    if (gpt->valid_entries & MASK_PRIMARY) {
-      entries = gpt->primary_entries;
-    } else {
-      require(gpt->valid_entries & MASK_SECONDARY);
-      entries = gpt->secondary_entries;
-    }
-  }
-
-  return (GptEntry*)(&entries[stride * entry_index]);
+GptEntry *GetEntry(GptData *gpt, int secondary, uint32_t entry_index)
+{
+	GptHeader *header = GetGptHeader(gpt);
+	uint8_t *entries;
+	uint32_t stride = header->size_of_entry;
+	require(stride);
+	require(entry_index < header->number_of_entries);
+
+	if (secondary == PRIMARY) {
+		entries = gpt->primary_entries;
+	} else if (secondary == SECONDARY) {
+		entries = gpt->secondary_entries;
+	} else { /* ANY_VALID */
+		require(secondary == ANY_VALID);
+		if (gpt->valid_entries & MASK_PRIMARY) {
+			entries = gpt->primary_entries;
+		} else {
+			require(gpt->valid_entries & MASK_SECONDARY);
+			entries = gpt->secondary_entries;
+		}
+	}
+
+	return (GptEntry *)(&entries[stride * entry_index]);
 }
 
-void SetRequired(struct drive *drive, int secondary, uint32_t entry_index,
-                 int required) {
-  require(required >= 0 && required <= CGPT_ATTRIBUTE_MAX_REQUIRED);
-  GptEntry *entry;
-  entry = GetEntry(&drive->gpt, secondary, entry_index);
-  SetEntryRequired(entry, required);
+void SetRequired(struct drive *drive, int secondary, uint32_t entry_index, int required)
+{
+	require(required >= 0 && required <= CGPT_ATTRIBUTE_MAX_REQUIRED);
+	GptEntry *entry;
+	entry = GetEntry(&drive->gpt, secondary, entry_index);
+	SetEntryRequired(entry, required);
 }
 
-int GetRequired(struct drive *drive, int secondary, uint32_t entry_index) {
-  GptEntry *entry;
-  entry = GetEntry(&drive->gpt, secondary, entry_index);
-  return GetEntryRequired(entry);
+int GetRequired(struct drive *drive, int secondary, uint32_t entry_index)
+{
+	GptEntry *entry;
+	entry = GetEntry(&drive->gpt, secondary, entry_index);
+	return GetEntryRequired(entry);
 }
 
-void SetLegacyBoot(struct drive *drive, int secondary, uint32_t entry_index,
-                   int legacy_boot) {
-  require(legacy_boot >= 0 && legacy_boot <= CGPT_ATTRIBUTE_MAX_LEGACY_BOOT);
-  GptEntry *entry;
-  entry = GetEntry(&drive->gpt, secondary, entry_index);
-  SetEntryLegacyBoot(entry, legacy_boot);
+void SetLegacyBoot(struct drive *drive, int secondary, uint32_t entry_index, int legacy_boot)
+{
+	require(legacy_boot >= 0 && legacy_boot <= CGPT_ATTRIBUTE_MAX_LEGACY_BOOT);
+	GptEntry *entry;
+	entry = GetEntry(&drive->gpt, secondary, entry_index);
+	SetEntryLegacyBoot(entry, legacy_boot);
 }
 
-int GetLegacyBoot(struct drive *drive, int secondary, uint32_t entry_index) {
-  GptEntry *entry;
-  entry = GetEntry(&drive->gpt, secondary, entry_index);
-  return GetEntryLegacyBoot(entry);
+int GetLegacyBoot(struct drive *drive, int secondary, uint32_t entry_index)
+{
+	GptEntry *entry;
+	entry = GetEntry(&drive->gpt, secondary, entry_index);
+	return GetEntryLegacyBoot(entry);
 }
 
-void SetPriority(struct drive *drive, int secondary, uint32_t entry_index,
-                 int priority) {
-  require(priority >= 0 && priority <= CGPT_ATTRIBUTE_MAX_PRIORITY);
-  GptEntry *entry;
-  entry = GetEntry(&drive->gpt, secondary, entry_index);
-  SetEntryPriority(entry, priority);
+void SetPriority(struct drive *drive, int secondary, uint32_t entry_index, int priority)
+{
+	require(priority >= 0 && priority <= CGPT_ATTRIBUTE_MAX_PRIORITY);
+	GptEntry *entry;
+	entry = GetEntry(&drive->gpt, secondary, entry_index);
+	SetEntryPriority(entry, priority);
 }
 
-int GetPriority(struct drive *drive, int secondary, uint32_t entry_index) {
-  GptEntry *entry;
-  entry = GetEntry(&drive->gpt, secondary, entry_index);
-  return GetEntryPriority(entry);
+int GetPriority(struct drive *drive, int secondary, uint32_t entry_index)
+{
+	GptEntry *entry;
+	entry = GetEntry(&drive->gpt, secondary, entry_index);
+	return GetEntryPriority(entry);
 }
 
-void SetTries(struct drive *drive, int secondary, uint32_t entry_index,
-              int tries) {
-  require(tries >= 0 && tries <= CGPT_ATTRIBUTE_MAX_TRIES);
-  GptEntry *entry;
-  entry = GetEntry(&drive->gpt, secondary, entry_index);
-  SetEntryTries(entry, tries);
+void SetTries(struct drive *drive, int secondary, uint32_t entry_index, int tries)
+{
+	require(tries >= 0 && tries <= CGPT_ATTRIBUTE_MAX_TRIES);
+	GptEntry *entry;
+	entry = GetEntry(&drive->gpt, secondary, entry_index);
+	SetEntryTries(entry, tries);
 }
 
-int GetTries(struct drive *drive, int secondary, uint32_t entry_index) {
-  GptEntry *entry;
-  entry = GetEntry(&drive->gpt, secondary, entry_index);
-  return GetEntryTries(entry);
+int GetTries(struct drive *drive, int secondary, uint32_t entry_index)
+{
+	GptEntry *entry;
+	entry = GetEntry(&drive->gpt, secondary, entry_index);
+	return GetEntryTries(entry);
 }
 
-void SetSuccessful(struct drive *drive, int secondary, uint32_t entry_index,
-                   int success) {
-  require(success >= 0 && success <= CGPT_ATTRIBUTE_MAX_SUCCESSFUL);
-  GptEntry *entry;
-  entry = GetEntry(&drive->gpt, secondary, entry_index);
-  SetEntrySuccessful(entry, success);
+void SetSuccessful(struct drive *drive, int secondary, uint32_t entry_index, int success)
+{
+	require(success >= 0 && success <= CGPT_ATTRIBUTE_MAX_SUCCESSFUL);
+	GptEntry *entry;
+	entry = GetEntry(&drive->gpt, secondary, entry_index);
+	SetEntrySuccessful(entry, success);
 }
 
-int GetSuccessful(struct drive *drive, int secondary, uint32_t entry_index) {
-  GptEntry *entry;
-  entry = GetEntry(&drive->gpt, secondary, entry_index);
-  return GetEntrySuccessful(entry);
+int GetSuccessful(struct drive *drive, int secondary, uint32_t entry_index)
+{
+	GptEntry *entry;
+	entry = GetEntry(&drive->gpt, secondary, entry_index);
+	return GetEntrySuccessful(entry);
 }
 
 void SetErrorCounter(struct drive *drive, int secondary, uint32_t entry_index,
-                     int error_counter) {
-  require(error_counter >= 0 &&
-          error_counter <= CGPT_ATTRIBUTE_MAX_ERROR_COUNTER);
-  GptEntry *entry;
-  entry = GetEntry(&drive->gpt, secondary, entry_index);
-  SetEntryErrorCounter(entry, error_counter);
+		     int error_counter)
+{
+	require(error_counter >= 0 && error_counter <= CGPT_ATTRIBUTE_MAX_ERROR_COUNTER);
+	GptEntry *entry;
+	entry = GetEntry(&drive->gpt, secondary, entry_index);
+	SetEntryErrorCounter(entry, error_counter);
 }
 
-int GetErrorCounter(struct drive *drive, int secondary, uint32_t entry_index) {
-  GptEntry *entry;
-  entry = GetEntry(&drive->gpt, secondary, entry_index);
-  return GetEntryErrorCounter(entry);
+int GetErrorCounter(struct drive *drive, int secondary, uint32_t entry_index)
+{
+	GptEntry *entry;
+	entry = GetEntry(&drive->gpt, secondary, entry_index);
+	return GetEntryErrorCounter(entry);
 }
 
-void SetRaw(struct drive *drive, int secondary, uint32_t entry_index,
-            uint32_t raw) {
-  GptEntry *entry;
-  entry = GetEntry(&drive->gpt, secondary, entry_index);
-  entry->attrs.fields.gpt_att = (uint16_t)raw;
+void SetRaw(struct drive *drive, int secondary, uint32_t entry_index, uint32_t raw)
+{
+	GptEntry *entry;
+	entry = GetEntry(&drive->gpt, secondary, entry_index);
+	entry->attrs.fields.gpt_att = (uint16_t)raw;
 }
 
-void UpdateAllEntries(struct drive *drive) {
-  RepairEntries(&drive->gpt, MASK_PRIMARY);
-  RepairHeader(&drive->gpt, MASK_PRIMARY);
+void UpdateAllEntries(struct drive *drive)
+{
+	RepairEntries(&drive->gpt, MASK_PRIMARY);
+	RepairHeader(&drive->gpt, MASK_PRIMARY);
 
-  drive->gpt.modified |= (GPT_MODIFIED_HEADER1 | GPT_MODIFIED_ENTRIES1 |
-                          GPT_MODIFIED_HEADER2 | GPT_MODIFIED_ENTRIES2);
-  UpdateCrc(&drive->gpt);
+	drive->gpt.modified |= (GPT_MODIFIED_HEADER1 | GPT_MODIFIED_ENTRIES1 |
+				GPT_MODIFIED_HEADER2 | GPT_MODIFIED_ENTRIES2);
+	UpdateCrc(&drive->gpt);
 }
 
-int IsUnused(struct drive *drive, int secondary, uint32_t index) {
-  GptEntry *entry;
-  entry = GetEntry(&drive->gpt, secondary, index);
-  return GuidIsZero(&entry->type);
+int IsUnused(struct drive *drive, int secondary, uint32_t index)
+{
+	GptEntry *entry;
+	entry = GetEntry(&drive->gpt, secondary, index);
+	return GuidIsZero(&entry->type);
 }
 
-int IsBootable(struct drive *drive, int secondary, uint32_t index) {
-  GptEntry *entry;
-  entry = GetEntry(&drive->gpt, secondary, index);
-  return (GuidEqual(&entry->type, &guid_chromeos_kernel) ||
-	  GuidEqual(&entry->type, &guid_android_vbmeta));
+int IsBootable(struct drive *drive, int secondary, uint32_t index)
+{
+	GptEntry *entry;
+	entry = GetEntry(&drive->gpt, secondary, index);
+	return (GuidEqual(&entry->type, &guid_chromeos_kernel) ||
+		GuidEqual(&entry->type, &guid_android_vbmeta));
 }
 
-
 #define TOSTRING(A) #A
-const char *GptError(int errnum) {
-  const char *error_string[] = {
-    TOSTRING(GPT_SUCCESS),
-    TOSTRING(GPT_ERROR_NO_VALID_KERNEL),
-    TOSTRING(GPT_ERROR_INVALID_HEADERS),
-    TOSTRING(GPT_ERROR_INVALID_ENTRIES),
-    TOSTRING(GPT_ERROR_INVALID_SECTOR_SIZE),
-    TOSTRING(GPT_ERROR_INVALID_SECTOR_NUMBER),
-    TOSTRING(GPT_ERROR_INVALID_UPDATE_TYPE)
-  };
-  if (errnum < 0 || errnum >= ARRAY_COUNT(error_string))
-    return "<illegal value>";
-  return error_string[errnum];
+const char *GptError(int errnum)
+{
+	const char *error_string[] = {TOSTRING(GPT_SUCCESS),
+				      TOSTRING(GPT_ERROR_NO_VALID_KERNEL),
+				      TOSTRING(GPT_ERROR_INVALID_HEADERS),
+				      TOSTRING(GPT_ERROR_INVALID_ENTRIES),
+				      TOSTRING(GPT_ERROR_INVALID_SECTOR_SIZE),
+				      TOSTRING(GPT_ERROR_INVALID_SECTOR_NUMBER),
+				      TOSTRING(GPT_ERROR_INVALID_UPDATE_TYPE)};
+	if (errnum < 0 || errnum >= ARRAY_COUNT(error_string))
+		return "<illegal value>";
+	return error_string[errnum];
 }
 
 /*  Update CRC value if necessary.  */
-void UpdateCrc(GptData *gpt) {
-  GptHeader *primary_header, *secondary_header;
-
-  primary_header = (GptHeader*)gpt->primary_header;
-  secondary_header = (GptHeader*)gpt->secondary_header;
-
-  if (gpt->modified & GPT_MODIFIED_ENTRIES1 &&
-      memcmp(primary_header, GPT_HEADER_SIGNATURE2,
-             GPT_HEADER_SIGNATURE_SIZE)) {
-    size_t entries_size = primary_header->size_of_entry *
-        primary_header->number_of_entries;
-    primary_header->entries_crc32 =
-        Crc32(gpt->primary_entries, entries_size);
-  }
-  if (gpt->modified & GPT_MODIFIED_ENTRIES2) {
-    size_t entries_size = secondary_header->size_of_entry *
-        secondary_header->number_of_entries;
-    secondary_header->entries_crc32 =
-        Crc32(gpt->secondary_entries, entries_size);
-  }
-  if (gpt->modified & GPT_MODIFIED_HEADER1) {
-    primary_header->header_crc32 = 0;
-    primary_header->header_crc32 = Crc32(
-        (const uint8_t *)primary_header, sizeof(GptHeader));
-  }
-  if (gpt->modified & GPT_MODIFIED_HEADER2) {
-    secondary_header->header_crc32 = 0;
-    secondary_header->header_crc32 = Crc32(
-        (const uint8_t *)secondary_header, sizeof(GptHeader));
-  }
+void UpdateCrc(GptData *gpt)
+{
+	GptHeader *primary_header, *secondary_header;
+
+	primary_header = (GptHeader *)gpt->primary_header;
+	secondary_header = (GptHeader *)gpt->secondary_header;
+
+	if (gpt->modified & GPT_MODIFIED_ENTRIES1 &&
+	    memcmp(primary_header, GPT_HEADER_SIGNATURE2, GPT_HEADER_SIGNATURE_SIZE)) {
+		size_t entries_size =
+			primary_header->size_of_entry * primary_header->number_of_entries;
+		primary_header->entries_crc32 = Crc32(gpt->primary_entries, entries_size);
+	}
+	if (gpt->modified & GPT_MODIFIED_ENTRIES2) {
+		size_t entries_size =
+			secondary_header->size_of_entry * secondary_header->number_of_entries;
+		secondary_header->entries_crc32 = Crc32(gpt->secondary_entries, entries_size);
+	}
+	if (gpt->modified & GPT_MODIFIED_HEADER1) {
+		primary_header->header_crc32 = 0;
+		primary_header->header_crc32 =
+			Crc32((const uint8_t *)primary_header, sizeof(GptHeader));
+	}
+	if (gpt->modified & GPT_MODIFIED_HEADER2) {
+		secondary_header->header_crc32 = 0;
+		secondary_header->header_crc32 =
+			Crc32((const uint8_t *)secondary_header, sizeof(GptHeader));
+	}
 }
 /* Two headers are NOT bitwise identical. For example, my_lba pointers to header
  * itself so that my_lba in primary and secondary is definitely different.
@@ -955,14 +939,15 @@ void UpdateCrc(GptData *gpt) {
  * If any of above field are not matched, overwrite secondary with primary since
  * we always trust primary.
  * If any one of header is invalid, copy from another. */
-int IsSynonymous(const GptHeader* a, const GptHeader* b) {
-  if ((a->first_usable_lba == b->first_usable_lba) &&
-      (a->last_usable_lba == b->last_usable_lba) &&
-      (a->number_of_entries == b->number_of_entries) &&
-      (a->size_of_entry == b->size_of_entry) &&
-      (!memcmp(&a->disk_uuid, &b->disk_uuid, sizeof(Guid))))
-    return 1;
-  return 0;
+int IsSynonymous(const GptHeader *a, const GptHeader *b)
+{
+	if ((a->first_usable_lba == b->first_usable_lba) &&
+	    (a->last_usable_lba == b->last_usable_lba) &&
+	    (a->number_of_entries == b->number_of_entries) &&
+	    (a->size_of_entry == b->size_of_entry) &&
+	    (!memcmp(&a->disk_uuid, &b->disk_uuid, sizeof(Guid))))
+		return 1;
+	return 0;
 }
 
 /* Primary entries and secondary entries should be bitwise identical.
@@ -974,49 +959,51 @@ int IsSynonymous(const GptHeader* a, const GptHeader* b) {
  * This function returns bit masks for GptData.modified field.
  * Note that CRC is NOT re-computed in this function.
  */
-uint8_t RepairEntries(GptData *gpt, const uint32_t valid_entries) {
-  /* If we have an alternate GPT header signature, don't overwrite
-   * the secondary GPT with the primary one as that might wipe the
-   * partition table. Also don't overwrite the primary one with the
-   * secondary one as that will stop Windows from booting. */
-  GptHeader* h = (GptHeader*)(gpt->primary_header);
-  if (!memcmp(h->signature, GPT_HEADER_SIGNATURE2, GPT_HEADER_SIGNATURE_SIZE))
-    return 0;
-
-  if (gpt->valid_headers & MASK_PRIMARY) {
-    h = (GptHeader*)gpt->primary_header;
-  } else if (gpt->valid_headers & MASK_SECONDARY) {
-    h = (GptHeader*)gpt->secondary_header;
-  } else {
-    /* We cannot trust any header, don't update entries. */
-    return 0;
-  }
-
-  size_t entries_size = h->number_of_entries * h->size_of_entry;
-  if (valid_entries == MASK_BOTH) {
-    if (memcmp(gpt->primary_entries, gpt->secondary_entries, entries_size)) {
-      memcpy(gpt->secondary_entries, gpt->primary_entries, entries_size);
-      return GPT_MODIFIED_ENTRIES2;
-    }
-  } else if (valid_entries == MASK_PRIMARY) {
-    memcpy(gpt->secondary_entries, gpt->primary_entries, entries_size);
-    return GPT_MODIFIED_ENTRIES2;
-  } else if (valid_entries == MASK_SECONDARY) {
-    memcpy(gpt->primary_entries, gpt->secondary_entries, entries_size);
-    return GPT_MODIFIED_ENTRIES1;
-  }
-
-  return 0;
+uint8_t RepairEntries(GptData *gpt, const uint32_t valid_entries)
+{
+	/* If we have an alternate GPT header signature, don't overwrite
+	 * the secondary GPT with the primary one as that might wipe the
+	 * partition table. Also don't overwrite the primary one with the
+	 * secondary one as that will stop Windows from booting. */
+	GptHeader *h = (GptHeader *)(gpt->primary_header);
+	if (!memcmp(h->signature, GPT_HEADER_SIGNATURE2, GPT_HEADER_SIGNATURE_SIZE))
+		return 0;
+
+	if (gpt->valid_headers & MASK_PRIMARY) {
+		h = (GptHeader *)gpt->primary_header;
+	} else if (gpt->valid_headers & MASK_SECONDARY) {
+		h = (GptHeader *)gpt->secondary_header;
+	} else {
+		/* We cannot trust any header, don't update entries. */
+		return 0;
+	}
+
+	size_t entries_size = h->number_of_entries * h->size_of_entry;
+	if (valid_entries == MASK_BOTH) {
+		if (memcmp(gpt->primary_entries, gpt->secondary_entries, entries_size)) {
+			memcpy(gpt->secondary_entries, gpt->primary_entries, entries_size);
+			return GPT_MODIFIED_ENTRIES2;
+		}
+	} else if (valid_entries == MASK_PRIMARY) {
+		memcpy(gpt->secondary_entries, gpt->primary_entries, entries_size);
+		return GPT_MODIFIED_ENTRIES2;
+	} else if (valid_entries == MASK_SECONDARY) {
+		memcpy(gpt->primary_entries, gpt->secondary_entries, entries_size);
+		return GPT_MODIFIED_ENTRIES1;
+	}
+
+	return 0;
 }
 
 /* The above five fields are shared between primary and secondary headers.
  * We can recover one header from another through copying those fields. */
-static void CopySynonymousParts(GptHeader* target, const GptHeader* source) {
-  target->first_usable_lba = source->first_usable_lba;
-  target->last_usable_lba = source->last_usable_lba;
-  target->number_of_entries = source->number_of_entries;
-  target->size_of_entry = source->size_of_entry;
-  memcpy(&target->disk_uuid, &source->disk_uuid, sizeof(Guid));
+static void CopySynonymousParts(GptHeader *target, const GptHeader *source)
+{
+	target->first_usable_lba = source->first_usable_lba;
+	target->last_usable_lba = source->last_usable_lba;
+	target->number_of_entries = source->number_of_entries;
+	target->size_of_entry = source->size_of_entry;
+	memcpy(&target->disk_uuid, &source->disk_uuid, sizeof(Guid));
 }
 
 /* This function repairs primary and secondary headers if possible.
@@ -1031,89 +1018,90 @@ static void CopySynonymousParts(GptHeader* target, const GptHeader* source) {
  * Note that CRC value is NOT re-computed in this function. UpdateCrc() will
  * do it later.
  */
-uint8_t RepairHeader(GptData *gpt, const uint32_t valid_headers) {
-  GptHeader *primary_header, *secondary_header;
-
-  primary_header = (GptHeader*)gpt->primary_header;
-  secondary_header = (GptHeader*)gpt->secondary_header;
-
-  if (valid_headers == MASK_BOTH) {
-    if (!IsSynonymous(primary_header, secondary_header)) {
-      CopySynonymousParts(secondary_header, primary_header);
-      return GPT_MODIFIED_HEADER2;
-    }
-  } else if (valid_headers == MASK_PRIMARY) {
-    memcpy(secondary_header, primary_header, sizeof(GptHeader));
-    secondary_header->my_lba = gpt->gpt_drive_sectors - 1;  /* the last sector */
-    secondary_header->alternate_lba = primary_header->my_lba;
-    secondary_header->entries_lba = secondary_header->my_lba -
-        CalculateEntriesSectors(primary_header, gpt->sector_bytes);
-    return GPT_MODIFIED_HEADER2;
-  } else if (valid_headers == MASK_SECONDARY) {
-    memcpy(primary_header, secondary_header, sizeof(GptHeader));
-    primary_header->my_lba = GPT_PMBR_SECTORS;  /* the second sector on drive */
-    primary_header->alternate_lba = secondary_header->my_lba;
-    /* TODO (namnguyen): Preserve (header, entries) padding space. */
-    primary_header->entries_lba = primary_header->my_lba + GPT_HEADER_SECTORS;
-    return GPT_MODIFIED_HEADER1;
-  }
-
-  return 0;
+uint8_t RepairHeader(GptData *gpt, const uint32_t valid_headers)
+{
+	GptHeader *primary_header, *secondary_header;
+
+	primary_header = (GptHeader *)gpt->primary_header;
+	secondary_header = (GptHeader *)gpt->secondary_header;
+
+	if (valid_headers == MASK_BOTH) {
+		if (!IsSynonymous(primary_header, secondary_header)) {
+			CopySynonymousParts(secondary_header, primary_header);
+			return GPT_MODIFIED_HEADER2;
+		}
+	} else if (valid_headers == MASK_PRIMARY) {
+		memcpy(secondary_header, primary_header, sizeof(GptHeader));
+		secondary_header->my_lba = gpt->gpt_drive_sectors - 1; /* the last sector */
+		secondary_header->alternate_lba = primary_header->my_lba;
+		secondary_header->entries_lba =
+			secondary_header->my_lba -
+			CalculateEntriesSectors(primary_header, gpt->sector_bytes);
+		return GPT_MODIFIED_HEADER2;
+	} else if (valid_headers == MASK_SECONDARY) {
+		memcpy(primary_header, secondary_header, sizeof(GptHeader));
+		primary_header->my_lba = GPT_PMBR_SECTORS; /* the second sector on drive */
+		primary_header->alternate_lba = secondary_header->my_lba;
+		/* TODO (namnguyen): Preserve (header, entries) padding space. */
+		primary_header->entries_lba = primary_header->my_lba + GPT_HEADER_SECTORS;
+		return GPT_MODIFIED_HEADER1;
+	}
+
+	return 0;
 }
 
-int CgptGetNumNonEmptyPartitions(CgptShowParams *params) {
-  struct drive drive;
-  int gpt_retval;
-  int retval;
+int CgptGetNumNonEmptyPartitions(CgptShowParams *params)
+{
+	struct drive drive;
+	int gpt_retval;
+	int retval;
 
-  if (params == NULL)
-    return CGPT_FAILED;
+	if (params == NULL)
+		return CGPT_FAILED;
 
-  if (CGPT_OK != DriveOpen(params->drive_name, &drive, O_RDONLY,
-                           params->drive_size))
-    return CGPT_FAILED;
+	if (CGPT_OK != DriveOpen(params->drive_name, &drive, O_RDONLY, params->drive_size))
+		return CGPT_FAILED;
 
-  if (GPT_SUCCESS != (gpt_retval = GptValidityCheck(&drive.gpt))) {
-    Error("GptValidityCheck() returned %d: %s\n",
-          gpt_retval, GptError(gpt_retval));
-    retval = CGPT_FAILED;
-    goto done;
-  }
+	if (GPT_SUCCESS != (gpt_retval = GptValidityCheck(&drive.gpt))) {
+		Error("GptValidityCheck() returned %d: %s\n", gpt_retval, GptError(gpt_retval));
+		retval = CGPT_FAILED;
+		goto done;
+	}
 
-  params->num_partitions = 0;
-  int numEntries = GetNumberOfEntries(&drive);
-  int i;
-  for (i = 0; i < numEntries; i++) {
-      GptEntry *entry = GetEntry(&drive.gpt, ANY_VALID, i);
-      if (GuidIsZero(&entry->type))
-        continue;
+	params->num_partitions = 0;
+	int numEntries = GetNumberOfEntries(&drive);
+	int i;
+	for (i = 0; i < numEntries; i++) {
+		GptEntry *entry = GetEntry(&drive.gpt, ANY_VALID, i);
+		if (GuidIsZero(&entry->type))
+			continue;
 
-      params->num_partitions++;
-  }
+		params->num_partitions++;
+	}
 
-  retval = CGPT_OK;
+	retval = CGPT_OK;
 
 done:
-  DriveClose(&drive, 0);
-  return retval;
+	DriveClose(&drive, 0);
+	return retval;
 }
 
-int GuidEqual(const Guid *guid1, const Guid *guid2) {
-  return (0 == memcmp(guid1, guid2, sizeof(Guid)));
+int GuidEqual(const Guid *guid1, const Guid *guid2)
+{
+	return (0 == memcmp(guid1, guid2, sizeof(Guid)));
 }
 
-int GuidIsZero(const Guid *gp) {
-  return GuidEqual(gp, &guid_unused);
-}
+int GuidIsZero(const Guid *gp) { return GuidEqual(gp, &guid_unused); }
 
-void PMBRToStr(struct pmbr *pmbr, char *str, unsigned int buflen) {
-  char buf[GUID_STRLEN];
-  if (GuidIsZero(&pmbr->boot_guid)) {
-    require(snprintf(str, buflen, "PMBR") < buflen);
-  } else {
-    GuidToStr(&pmbr->boot_guid, buf, sizeof(buf));
-    require(snprintf(str, buflen, "PMBR (Boot GUID: %s)", buf) < buflen);
-  }
+void PMBRToStr(struct pmbr *pmbr, char *str, unsigned int buflen)
+{
+	char buf[GUID_STRLEN];
+	if (GuidIsZero(&pmbr->boot_guid)) {
+		require(snprintf(str, buflen, "PMBR") < buflen);
+	} else {
+		GptGuidToStr(&pmbr->boot_guid, buf, sizeof(buf), GPT_GUID_UPPERCASE);
+		require(snprintf(str, buflen, "PMBR (Boot GUID: %s)", buf) < buflen);
+	}
 }
 
 /*
diff --git a/cgpt/cgpt_create.c b/cgpt/cgpt_create.c
index 0d5ef8bc..8331c7f4 100644
--- a/cgpt/cgpt_create.c
+++ b/cgpt/cgpt_create.c
@@ -9,129 +9,133 @@
 #include "cgptlib_internal.h"
 #include "vboot_host.h"
 
-static void AllocAndClear(uint8_t **buf, uint64_t size) {
-  if (*buf) {
-    memset(*buf, 0, size);
-  } else {
-    *buf = calloc(1, size);
-    if (!*buf) {
-      Error("Cannot allocate %" PRIu64 " bytes.\n", size);
-      abort();
-    }
-  }
+static void AllocAndClear(uint8_t **buf, uint64_t size)
+{
+	if (*buf) {
+		memset(*buf, 0, size);
+	} else {
+		*buf = calloc(1, size);
+		if (!*buf) {
+			Error("Cannot allocate %" PRIu64 " bytes.\n", size);
+			abort();
+		}
+	}
 }
 
-static int GptCreate(struct drive *drive, CgptCreateParams *params) {
-  // Do not replace any existing IGNOREME GPT headers.
-  if (!memcmp(((GptHeader*)drive->gpt.primary_header)->signature,
-              GPT_HEADER_SIGNATURE_IGNORED, GPT_HEADER_SIGNATURE_SIZE)) {
-    drive->gpt.ignored |= MASK_PRIMARY;
-    Warning("Primary GPT was marked ignored, will not overwrite.\n");
-  }
-
-  if (!memcmp(((GptHeader*)drive->gpt.secondary_header)->signature,
-              GPT_HEADER_SIGNATURE_IGNORED, GPT_HEADER_SIGNATURE_SIZE)) {
-    drive->gpt.ignored |= MASK_SECONDARY;
-    Warning("Secondary GPT was marked ignored, will not overwrite.\n");
-  }
-
-  // Allocate and/or erase the data.
-  // We cannot assume the GPT headers or entry arrays have been allocated
-  // by GptLoad() because those fields might have failed validation checks.
-  AllocAndClear(&drive->gpt.primary_header,
-                drive->gpt.sector_bytes * GPT_HEADER_SECTORS);
-  AllocAndClear(&drive->gpt.secondary_header,
-                drive->gpt.sector_bytes * GPT_HEADER_SECTORS);
-
-  drive->gpt.modified |= (GPT_MODIFIED_HEADER1 | GPT_MODIFIED_ENTRIES1 |
-                         GPT_MODIFIED_HEADER2 | GPT_MODIFIED_ENTRIES2);
-
-  // Initialize a blank set
-  if (!params->zap) {
-    GptHeader *h = (GptHeader *)drive->gpt.primary_header;
-    memcpy(h->signature, GPT_HEADER_SIGNATURE, GPT_HEADER_SIGNATURE_SIZE);
-    h->revision = GPT_HEADER_REVISION;
-    h->size = sizeof(GptHeader);
-    h->my_lba = GPT_PMBR_SECTORS;  /* The second sector on drive. */
-    h->alternate_lba = drive->gpt.gpt_drive_sectors - GPT_HEADER_SECTORS;
-    if (CGPT_OK != GenerateGuid(&h->disk_uuid)) {
-      Error("Unable to generate new GUID.\n");
-      return -1;
-    }
-
-    /* Calculate number of entries */
-    h->size_of_entry = sizeof(GptEntry);
-    h->number_of_entries = MAX_NUMBER_OF_ENTRIES;
-    if (drive->gpt.flags & GPT_FLAG_EXTERNAL) {
-      // We might have smaller space for the GPT table. Scale accordingly.
-      //
-      // +------+------------+---------------+-----+--------------+-----------+
-      // | PMBR | Prim. Head | Prim. Entries | ... | Sec. Entries | Sec. Head |
-      // +------+------------+---------------+-----+--------------+-----------+
-      //
-      // Half the size of gpt_drive_sectors must be big enough to hold PMBR +
-      // GPT Header + Entries Table, though the secondary structures do not
-      // contain PMBR.
-      size_t required_headers_size =
-          (GPT_PMBR_SECTORS + GPT_HEADER_SECTORS) * drive->gpt.sector_bytes;
-      size_t min_entries_size = MIN_NUMBER_OF_ENTRIES * h->size_of_entry;
-      size_t required_min_size = required_headers_size + min_entries_size;
-      size_t half_size =
-          (drive->gpt.gpt_drive_sectors / 2) * drive->gpt.sector_bytes;
-      if (half_size < required_min_size) {
-        Error("Not enough space to store GPT structures. Required %zu bytes.\n",
-              required_min_size * 2);
-        return -1;
-      }
-      size_t max_entries =
-          (half_size - required_headers_size) / h->size_of_entry;
-      if (h->number_of_entries > max_entries) {
-        h->number_of_entries = max_entries;
-      }
-    }
-
-    /* Then use number of entries to calculate entries_lba. */
-    h->entries_lba = h->my_lba + GPT_HEADER_SECTORS;
-    if (!(drive->gpt.flags & GPT_FLAG_EXTERNAL)) {
-      h->entries_lba += params->padding;
-      h->first_usable_lba = h->entries_lba + CalculateEntriesSectors(h,
-                                               drive->gpt.sector_bytes);
-    } else {
-      h->first_usable_lba = params->padding;
-    }
-    h->last_usable_lba = DriveLastUsableLBA(drive);
-
-    size_t entries_size = h->number_of_entries * h->size_of_entry;
-    AllocAndClear(&drive->gpt.primary_entries, entries_size);
-    AllocAndClear(&drive->gpt.secondary_entries, entries_size);
-
-    // Copy to secondary
-    RepairHeader(&drive->gpt, MASK_PRIMARY);
-
-    UpdateCrc(&drive->gpt);
-  }
-
-  return 0;
+static int GptCreate(struct drive *drive, CgptCreateParams *params)
+{
+	// Do not replace any existing IGNOREME GPT headers.
+	if (!memcmp(((GptHeader *)drive->gpt.primary_header)->signature,
+		    GPT_HEADER_SIGNATURE_IGNORED, GPT_HEADER_SIGNATURE_SIZE)) {
+		drive->gpt.ignored |= MASK_PRIMARY;
+		Warning("Primary GPT was marked ignored, will not overwrite.\n");
+	}
+
+	if (!memcmp(((GptHeader *)drive->gpt.secondary_header)->signature,
+		    GPT_HEADER_SIGNATURE_IGNORED, GPT_HEADER_SIGNATURE_SIZE)) {
+		drive->gpt.ignored |= MASK_SECONDARY;
+		Warning("Secondary GPT was marked ignored, will not overwrite.\n");
+	}
+
+	// Allocate and/or erase the data.
+	// We cannot assume the GPT headers or entry arrays have been allocated
+	// by GptLoad() because those fields might have failed validation checks.
+	AllocAndClear(&drive->gpt.primary_header, drive->gpt.sector_bytes * GPT_HEADER_SECTORS);
+	AllocAndClear(&drive->gpt.secondary_header,
+		      drive->gpt.sector_bytes * GPT_HEADER_SECTORS);
+
+	drive->gpt.modified |= (GPT_MODIFIED_HEADER1 | GPT_MODIFIED_ENTRIES1 |
+				GPT_MODIFIED_HEADER2 | GPT_MODIFIED_ENTRIES2);
+
+	// Initialize a blank set
+	if (!params->zap) {
+		GptHeader *h = (GptHeader *)drive->gpt.primary_header;
+		memcpy(h->signature, GPT_HEADER_SIGNATURE, GPT_HEADER_SIGNATURE_SIZE);
+		h->revision = GPT_HEADER_REVISION;
+		h->size = sizeof(GptHeader);
+		h->my_lba = GPT_PMBR_SECTORS; /* The second sector on drive. */
+		h->alternate_lba = drive->gpt.gpt_drive_sectors - GPT_HEADER_SECTORS;
+		if (CGPT_OK != GenerateGuid(&h->disk_uuid)) {
+			Error("Unable to generate new GUID.\n");
+			return -1;
+		}
+
+		/* Calculate number of entries */
+		h->size_of_entry = sizeof(GptEntry);
+		h->number_of_entries = MAX_NUMBER_OF_ENTRIES;
+		if (drive->gpt.flags & GPT_FLAG_EXTERNAL) {
+			// We might have smaller space for the GPT table. Scale accordingly.
+			//
+			// +------+------------+---------------+-----+--------------+-----------+
+			// | PMBR | Prim. Head | Prim. Entries | ... | Sec. Entries | Sec. Head
+			// |
+			// +------+------------+---------------+-----+--------------+-----------+
+			//
+			// Half the size of gpt_drive_sectors must be big enough to hold PMBR +
+			// GPT Header + Entries Table, though the secondary structures do not
+			// contain PMBR.
+			size_t required_headers_size = (GPT_PMBR_SECTORS + GPT_HEADER_SECTORS) *
+						       drive->gpt.sector_bytes;
+			size_t min_entries_size = MIN_NUMBER_OF_ENTRIES * h->size_of_entry;
+			size_t required_min_size = required_headers_size + min_entries_size;
+			size_t half_size =
+				(drive->gpt.gpt_drive_sectors / 2) * drive->gpt.sector_bytes;
+			if (half_size < required_min_size) {
+				Error("Not enough space to store GPT structures. Required %zu "
+				      "bytes.\n",
+				      required_min_size * 2);
+				return -1;
+			}
+			size_t max_entries =
+				(half_size - required_headers_size) / h->size_of_entry;
+			if (h->number_of_entries > max_entries) {
+				h->number_of_entries = max_entries;
+			}
+		}
+
+		/* Then use number of entries to calculate entries_lba. */
+		h->entries_lba = h->my_lba + GPT_HEADER_SECTORS;
+		if (!(drive->gpt.flags & GPT_FLAG_EXTERNAL)) {
+			h->entries_lba += params->padding;
+			h->first_usable_lba =
+				h->entries_lba +
+				CalculateEntriesSectors(h, drive->gpt.sector_bytes);
+		} else {
+			h->first_usable_lba = params->padding;
+		}
+		h->last_usable_lba = DriveLastUsableLBA(drive);
+
+		size_t entries_size = h->number_of_entries * h->size_of_entry;
+		AllocAndClear(&drive->gpt.primary_entries, entries_size);
+		AllocAndClear(&drive->gpt.secondary_entries, entries_size);
+
+		// Copy to secondary
+		RepairHeader(&drive->gpt, MASK_PRIMARY);
+
+		UpdateCrc(&drive->gpt);
+	}
+
+	return 0;
 }
 
-int CgptCreate(CgptCreateParams *params) {
-  struct drive drive;
+int CgptCreate(CgptCreateParams *params)
+{
+	struct drive drive;
 
-  if (params == NULL)
-    return CGPT_FAILED;
+	if (params == NULL)
+		return CGPT_FAILED;
 
-  if (CGPT_OK != DriveOpen(params->drive_name, &drive, O_RDWR,
-                           params->drive_size))
-    return CGPT_FAILED;
+	if (CGPT_OK != DriveOpen(params->drive_name, &drive, O_RDWR, params->drive_size))
+		return CGPT_FAILED;
 
-  if (GptCreate(&drive, params))
-    goto bad;
+	if (GptCreate(&drive, params))
+		goto bad;
 
-  // Write it all out
-  return DriveClose(&drive, 1);
+	// Write it all out
+	return DriveClose(&drive, 1);
 
 bad:
 
-  DriveClose(&drive, 0);
-  return CGPT_FAILED;
+	DriveClose(&drive, 0);
+	return CGPT_FAILED;
 }
diff --git a/cgpt/cgpt_edit.c b/cgpt/cgpt_edit.c
index 8ac3b68b..f086a9ba 100644
--- a/cgpt/cgpt_edit.c
+++ b/cgpt/cgpt_edit.c
@@ -8,44 +8,43 @@
 #include "cgpt_params.h"
 #include "vboot_host.h"
 
-int CgptEdit(CgptEditParams *params) {
-  struct drive drive;
-  GptHeader *h;
-  int gpt_retval;
-
-  if (params == NULL)
-    return CGPT_FAILED;
-
-  if (CGPT_OK != DriveOpen(params->drive_name, &drive, O_RDWR,
-                           params->drive_size))
-    return CGPT_FAILED;
-
-  if (GPT_SUCCESS != (gpt_retval = GptValidityCheck(&drive.gpt))) {
-    Error("GptValidityCheck() returned %d: %s\n",
-          gpt_retval, GptError(gpt_retval));
-    goto bad;
-  }
-
-  if (CGPT_OK != CheckValid(&drive)) {
-    Error("Please run 'cgpt repair' before changing settings.\n");
-    goto bad;
-  }
-
-  h = (GptHeader *)drive.gpt.primary_header;
-  if (params->set_unique) {
-    memcpy(&h->disk_uuid, &params->unique_guid, sizeof(h->disk_uuid));
-  }
-  // Copy to secondary
-  RepairHeader(&drive.gpt, MASK_PRIMARY);
-  drive.gpt.modified |= (GPT_MODIFIED_HEADER1 | GPT_MODIFIED_HEADER2);
-
-  UpdateCrc(&drive.gpt);
-
-  // Write it all out.
-  return DriveClose(&drive, 1);
+int CgptEdit(CgptEditParams *params)
+{
+	struct drive drive;
+	GptHeader *h;
+	int gpt_retval;
+
+	if (params == NULL)
+		return CGPT_FAILED;
+
+	if (CGPT_OK != DriveOpen(params->drive_name, &drive, O_RDWR, params->drive_size))
+		return CGPT_FAILED;
+
+	if (GPT_SUCCESS != (gpt_retval = GptValidityCheck(&drive.gpt))) {
+		Error("GptValidityCheck() returned %d: %s\n", gpt_retval, GptError(gpt_retval));
+		goto bad;
+	}
+
+	if (CGPT_OK != CheckValid(&drive)) {
+		Error("Please run 'cgpt repair' before changing settings.\n");
+		goto bad;
+	}
+
+	h = (GptHeader *)drive.gpt.primary_header;
+	if (params->set_unique) {
+		memcpy(&h->disk_uuid, &params->unique_guid, sizeof(h->disk_uuid));
+	}
+	// Copy to secondary
+	RepairHeader(&drive.gpt, MASK_PRIMARY);
+	drive.gpt.modified |= (GPT_MODIFIED_HEADER1 | GPT_MODIFIED_HEADER2);
+
+	UpdateCrc(&drive.gpt);
+
+	// Write it all out.
+	return DriveClose(&drive, 1);
 
 bad:
 
-  DriveClose(&drive, 0);
-  return CGPT_FAILED;
+	DriveClose(&drive, 0);
+	return CGPT_FAILED;
 }
diff --git a/cgpt/cgpt_find.c b/cgpt/cgpt_find.c
index 258afc57..03d6ae2d 100644
--- a/cgpt/cgpt_find.c
+++ b/cgpt/cgpt_find.c
@@ -17,321 +17,323 @@
 #define BUFSIZE 1024
 
 // fill comparebuf with the data to be examined, returning true on success.
-static int FillBuffer(CgptFindParams *params, int fd, uint64_t pos,
-                       uint64_t count) {
-  uint8_t *bufptr = params->comparebuf;
-
-  if (-1 == lseek(fd, pos, SEEK_SET))
-    return 0;
-
-  // keep reading until done or error
-  while (count) {
-    ssize_t bytes_read = read(fd, bufptr, count);
-    // negative means error, 0 means (unexpected) EOF
-    if (bytes_read <= 0)
-      return 0;
-    count -= bytes_read;
-    bufptr += bytes_read;
-  }
-
-  return 1;
+static int FillBuffer(CgptFindParams *params, int fd, uint64_t pos, uint64_t count)
+{
+	uint8_t *bufptr = params->comparebuf;
+
+	if (-1 == lseek(fd, pos, SEEK_SET))
+		return 0;
+
+	// keep reading until done or error
+	while (count) {
+		ssize_t bytes_read = read(fd, bufptr, count);
+		// negative means error, 0 means (unexpected) EOF
+		if (bytes_read <= 0)
+			return 0;
+		count -= bytes_read;
+		bufptr += bytes_read;
+	}
+
+	return 1;
 }
 
 // check partition data content. return true for match, 0 for no match or error
-static int match_content(CgptFindParams *params, struct drive *drive,
-                             GptEntry *entry) {
-  uint64_t part_size;
-
-  if (!params->matchlen)
-    return 1;
-
-  // Ensure that the region we want to match against is inside the partition.
-  part_size = drive->gpt.sector_bytes *
-    (entry->ending_lba - entry->starting_lba + 1);
-  if (params->matchoffset + params->matchlen > part_size) {
-    return 0;
-  }
-
-  // Read the partition data.
-  if (!FillBuffer(params, drive->fd,
-    (drive->gpt.sector_bytes * entry->starting_lba) + params->matchoffset,
-                  params->matchlen)) {
-    Error("unable to read partition data\n");
-    return 0;
-  }
-
-  // Compare it
-  if (0 == memcmp(params->matchbuf, params->comparebuf, params->matchlen)) {
-    return 1;
-  }
-
-  // Nope.
-  return 0;
+static int match_content(CgptFindParams *params, struct drive *drive, GptEntry *entry)
+{
+	uint64_t part_size;
+
+	if (!params->matchlen)
+		return 1;
+
+	// Ensure that the region we want to match against is inside the partition.
+	part_size = drive->gpt.sector_bytes * (entry->ending_lba - entry->starting_lba + 1);
+	if (params->matchoffset + params->matchlen > part_size) {
+		return 0;
+	}
+
+	// Read the partition data.
+	if (!FillBuffer(params, drive->fd,
+			(drive->gpt.sector_bytes * entry->starting_lba) + params->matchoffset,
+			params->matchlen)) {
+		Error("unable to read partition data\n");
+		return 0;
+	}
+
+	// Compare it
+	if (0 == memcmp(params->matchbuf, params->comparebuf, params->matchlen)) {
+		return 1;
+	}
+
+	// Nope.
+	return 0;
 }
 
 // This needs to handle /dev/mmcblk0 -> /dev/mmcblk0p3, /dev/sda -> /dev/sda3
-static void showmatch(CgptFindParams *params, const char *filename,
-                      int partnum, GptEntry *entry) {
-  const char * format = "%s%d\n";
-
-  /*
-   * Follow convention from disk_name() in kernel block/partition-generic.c
-   * code:
-   * If the last digit of the device name is a number, add a 'p' between the
-   * device name and the partition number.
-   */
-  if (isdigit(filename[strlen(filename) - 1]))
-    format = "%sp%d\n";
-
-  if (params->numeric) {
-    printf("%d\n", partnum);
-  } else {
-    if (params->show_fn) {
-      params->show_fn(params, filename, partnum, entry);
-    } else {
-      printf(format, filename, partnum);
-    }
-  }
-  if (params->verbose > 0)
-    EntryDetails(entry, partnum - 1, params->numeric);
+static void showmatch(CgptFindParams *params, const char *filename, int partnum,
+		      GptEntry *entry)
+{
+	const char *format = "%s%d\n";
+
+	/*
+	 * Follow convention from disk_name() in kernel block/partition-generic.c
+	 * code:
+	 * If the last digit of the device name is a number, add a 'p' between the
+	 * device name and the partition number.
+	 */
+	if (isdigit(filename[strlen(filename) - 1]))
+		format = "%sp%d\n";
+
+	if (params->numeric) {
+		printf("%d\n", partnum);
+	} else {
+		if (params->show_fn) {
+			params->show_fn(params, filename, partnum, entry);
+		} else {
+			printf(format, filename, partnum);
+		}
+	}
+	if (params->verbose > 0)
+		EntryDetails(entry, partnum - 1, params->numeric);
 }
 
 // This returns true if a GPT partition matches the search criteria. If a match
 // isn't found (or if the file doesn't contain a GPT), it returns false. The
 // filename and partition number that matched is left in a global, since we
 // could have multiple hits.
-static int gpt_search(CgptFindParams *params, struct drive *drive,
-                      const char *filename) {
-  int i;
-  GptEntry *entry;
-  int retval = 0;
-  char partlabel[GPT_PARTNAME_LEN];
-
-  if (GPT_SUCCESS != GptValidityCheck(&drive->gpt)) {
-    return 0;
-  }
-
-  for (i = 0; i < GetNumberOfEntries(drive); ++i) {
-    entry = GetEntry(&drive->gpt, ANY_VALID, i);
-
-    if (GuidIsZero(&entry->type))
-      continue;
-
-    int found = 0;
-    if ((params->set_unique && GuidEqual(&params->unique_guid, &entry->unique))
-        || (params->set_type && GuidEqual(&params->type_guid, &entry->type))) {
-      found = 1;
-    } else if (params->set_label) {
-      if (CGPT_OK != UTF16ToUTF8(entry->name,
-                                 sizeof(entry->name) / sizeof(entry->name[0]),
-                                 (uint8_t *)partlabel, sizeof(partlabel))) {
-        Error("The label cannot be converted from UTF16, so abort.\n");
-        return 0;
-      }
-      if (!strncmp(params->label, partlabel, sizeof(partlabel)))
-        found = 1;
-    }
-    if (found && match_content(params, drive, entry)) {
-      params->hits++;
-      retval++;
-      showmatch(params, filename, i+1, entry);
-      if (!params->match_partnum)
-        params->match_partnum = i+1;
-    }
-  }
-
-  return retval;
+static int gpt_search(CgptFindParams *params, struct drive *drive, const char *filename)
+{
+	int i;
+	GptEntry *entry;
+	int retval = 0;
+	char partlabel[GPT_PARTNAME_LEN];
+
+	if (GPT_SUCCESS != GptValidityCheck(&drive->gpt)) {
+		return 0;
+	}
+
+	for (i = 0; i < GetNumberOfEntries(drive); ++i) {
+		entry = GetEntry(&drive->gpt, ANY_VALID, i);
+
+		if (GuidIsZero(&entry->type))
+			continue;
+
+		int found = 0;
+		if ((params->set_unique && GuidEqual(&params->unique_guid, &entry->unique)) ||
+		    (params->set_type && GuidEqual(&params->type_guid, &entry->type))) {
+			found = 1;
+		} else if (params->set_label) {
+			if (CGPT_OK != UTF16ToUTF8(entry->name,
+						   sizeof(entry->name) / sizeof(entry->name[0]),
+						   (uint8_t *)partlabel, sizeof(partlabel))) {
+				Error("The label cannot be converted from UTF16, so abort.\n");
+				return 0;
+			}
+			if (!strncmp(params->label, partlabel, sizeof(partlabel)))
+				found = 1;
+		}
+		if (found && match_content(params, drive, entry)) {
+			params->hits++;
+			retval++;
+			showmatch(params, filename, i + 1, entry);
+			if (!params->match_partnum)
+				params->match_partnum = i + 1;
+		}
+	}
+
+	return retval;
 }
 
-static int do_search(CgptFindParams *params, const char *fileName) {
-  int retval;
-  struct drive drive;
+static int do_search(CgptFindParams *params, const char *fileName)
+{
+	int retval;
+	struct drive drive;
 
-  if (CGPT_OK != DriveOpen(fileName, &drive, O_RDONLY, params->drive_size))
-    return 0;
+	if (CGPT_OK != DriveOpen(fileName, &drive, O_RDONLY, params->drive_size))
+		return 0;
 
-  retval = gpt_search(params, &drive, fileName);
+	retval = gpt_search(params, &drive, fileName);
 
-  (void) DriveClose(&drive, 0);
+	(void)DriveClose(&drive, 0);
 
-  return retval;
+	return retval;
 }
 
-
 #define PROC_MTD "/proc/mtd"
 #define PROC_PARTITIONS "/proc/partitions"
 #define DEV_DIR "/dev"
 #define SYS_BLOCK_DIR "/sys/block"
 #define MAX_PARTITION_NAME_LEN 128
 
-static const char *devdirs[] = { "/dev", "/devices", "/devfs", 0 };
+static const char *devdirs[] = {"/dev", "/devices", "/devfs", 0};
 
 // Given basename "foo", see if we can find a whole, real device by that name.
 // This is copied from the logic in the linux utility 'findfs', although that
 // does more exhaustive searching.
-static char *is_wholedev(const char *basename) {
-  int i;
-  struct stat statbuf;
-  static char pathname[BUFSIZE];        // we'll return this.
-  char tmpname[BUFSIZE];
+static char *is_wholedev(const char *basename)
+{
+	int i;
+	struct stat statbuf;
+	static char pathname[BUFSIZE]; // we'll return this.
+	char tmpname[BUFSIZE];
 
-  // It should be a block device under /dev/,
-  for (i = 0; devdirs[i]; i++) {
-    sprintf(pathname, "%s/%s", devdirs[i], basename);
+	// It should be a block device under /dev/,
+	for (i = 0; devdirs[i]; i++) {
+		sprintf(pathname, "%s/%s", devdirs[i], basename);
 
-    if (0 != stat(pathname, &statbuf))
-      continue;
+		if (0 != stat(pathname, &statbuf))
+			continue;
 
-    if (!S_ISBLK(statbuf.st_mode))
-      continue;
+		if (!S_ISBLK(statbuf.st_mode))
+			continue;
 
-    // It should have a symlink called /sys/block/*/device
-    sprintf(tmpname, "%s/%s/device", SYS_BLOCK_DIR, basename);
+		// It should have a symlink called /sys/block/*/device
+		sprintf(tmpname, "%s/%s/device", SYS_BLOCK_DIR, basename);
 
-    if (0 != lstat(tmpname, &statbuf))
-      continue;
+		if (0 != lstat(tmpname, &statbuf))
+			continue;
 
-    if (!S_ISLNK(statbuf.st_mode))
-      continue;
+		if (!S_ISLNK(statbuf.st_mode))
+			continue;
 
-    // found it
-    return pathname;
-  }
+		// found it
+		return pathname;
+	}
 
-  return 0;
+	return 0;
 }
 
 #ifdef GPT_SPI_NOR
 // This handles the MTD devices. ChromeOS uses /dev/mtdX for kernel partitions,
 // /dev/ubiblockX_0 for root partitions, and /dev/ubiX for stateful partition.
-static void chromeos_mtd_show(CgptFindParams *params, const char *filename,
-                              int partnum, GptEntry *entry) {
-  if (GuidEqual(&guid_chromeos_kernel, &entry->type)) {
-    printf("/dev/mtd%d\n", partnum);
-  } else if (GuidEqual(&guid_chromeos_rootfs, &entry->type)) {
-    printf("/dev/ubiblock%d_0\n", partnum);
-  } else {
-    printf("/dev/ubi%d_0\n", partnum);
-  }
+static void chromeos_mtd_show(CgptFindParams *params, const char *filename, int partnum,
+			      GptEntry *entry)
+{
+	if (GuidEqual(&guid_chromeos_kernel, &entry->type)) {
+		printf("/dev/mtd%d\n", partnum);
+	} else if (GuidEqual(&guid_chromeos_rootfs, &entry->type)) {
+		printf("/dev/ubiblock%d_0\n", partnum);
+	} else {
+		printf("/dev/ubi%d_0\n", partnum);
+	}
 }
 
-static int scan_spi_gpt(CgptFindParams *params) {
-  int found = 0;
-  char partname[MAX_PARTITION_NAME_LEN];
-  FILE *fp;
-  size_t line_length = 0;
-  char *line = NULL;
-
-  fp = fopen(PROC_MTD, "re");
-  if (!fp) {
-    return found;
-  }
-
-  while (getline(&line, &line_length, fp) != -1) {
-    uint64_t sz;
-    uint32_t erasesz;
-    char name[128];
-    // dev:  size  erasesize  name
-    if (sscanf(line, "%64[^:]: %" PRIx64 " %x \"%127[^\"]\"",
-               partname, &sz, &erasesz, name) != 4)
-      continue;
-    if (strcmp(partname, "mtd0") == 0) {
-      char temp_dir[] = VBOOT_TMP_DIR "/cgpt_find.XXXXXX";
-      if (params->drive_size == 0) {
-        if (GetMtdSize("/dev/mtd0", &params->drive_size) != 0) {
-          perror("GetMtdSize");
-          goto cleanup;
-        }
-      }
-      // Create a temp dir to work in.
-      if (mkdtemp(temp_dir) == NULL) {
-        perror("Cannot create a temporary directory.\n");
-        goto cleanup;
-      }
-      if (ReadNorFlash(temp_dir) != 0) {
-        perror("ReadNorFlash");
-        RemoveDir(temp_dir);
-        goto cleanup;
-      }
-      char nor_file[64];
-      if (snprintf(nor_file, sizeof(nor_file), "%s/rw_gpt", temp_dir) > 0) {
-        params->show_fn = chromeos_mtd_show;
-        if (do_search(params, nor_file)) {
-          found++;
-        }
-        params->show_fn = NULL;
-      }
-      RemoveDir(temp_dir);
-      break;
-    }
-  }
+static int scan_spi_gpt(CgptFindParams *params)
+{
+	int found = 0;
+	char partname[MAX_PARTITION_NAME_LEN];
+	FILE *fp;
+	size_t line_length = 0;
+	char *line = NULL;
+
+	fp = fopen(PROC_MTD, "re");
+	if (!fp) {
+		return found;
+	}
+
+	while (getline(&line, &line_length, fp) != -1) {
+		uint64_t sz;
+		uint32_t erasesz;
+		char name[128];
+		// dev:  size  erasesize  name
+		if (sscanf(line, "%64[^:]: %" PRIx64 " %x \"%127[^\"]\"", partname, &sz,
+			   &erasesz, name) != 4)
+			continue;
+		if (strcmp(partname, "mtd0") == 0) {
+			char temp_dir[] = VBOOT_TMP_DIR "/cgpt_find.XXXXXX";
+			if (params->drive_size == 0) {
+				if (GetMtdSize("/dev/mtd0", &params->drive_size) != 0) {
+					perror("GetMtdSize");
+					goto cleanup;
+				}
+			}
+			// Create a temp dir to work in.
+			if (mkdtemp(temp_dir) == NULL) {
+				perror("Cannot create a temporary directory.\n");
+				goto cleanup;
+			}
+			if (ReadNorFlash(temp_dir) != 0) {
+				perror("ReadNorFlash");
+				RemoveDir(temp_dir);
+				goto cleanup;
+			}
+			char nor_file[64];
+			if (snprintf(nor_file, sizeof(nor_file), "%s/rw_gpt", temp_dir) > 0) {
+				params->show_fn = chromeos_mtd_show;
+				if (do_search(params, nor_file)) {
+					found++;
+				}
+				params->show_fn = NULL;
+			}
+			RemoveDir(temp_dir);
+			break;
+		}
+	}
 cleanup:
-  fclose(fp);
-  free(line);
-  return found;
+	fclose(fp);
+	free(line);
+	return found;
 }
 #else
 // Stub
-static int scan_spi_gpt(CgptFindParams *params) {
-  return 0;
-}
+static int scan_spi_gpt(CgptFindParams *params) { return 0; }
 #endif
 
 // This scans all the physical devices it can find, looking for a match. It
 // returns true if any matches were found, false otherwise.
-static int scan_real_devs(CgptFindParams *params) {
-  int found = 0;
-  char partname[MAX_PARTITION_NAME_LEN];
-  char partname_prev[MAX_PARTITION_NAME_LEN];
-  FILE *fp;
-  char *pathname;
-
-  fp = fopen(PROC_PARTITIONS, "re");
-  if (!fp) {
-    perror("can't read " PROC_PARTITIONS);
-    return found;
-  }
-
-  size_t line_length = 0;
-  char *line = NULL;
-  partname_prev[0] = '\0';
-  while (getline(&line, &line_length, fp) != -1) {
-    int ma, mi;
-    long long unsigned int sz;
-
-    if (sscanf(line, " %d %d %llu %127[^\n ]", &ma, &mi, &sz, partname) != 4)
-      continue;
-
-    /* Only check devices that have partitions under them.
-     * We can tell by checking that an entry like "sda" is immediately
-     * followed by one like "sda0". */
-    if (!strncmp(partname_prev, partname, strlen(partname_prev)) &&
-        strlen(partname_prev)) {
-      if ((pathname = is_wholedev(partname_prev))) {
-        if (do_search(params, pathname)) {
-          found++;
-        }
-      }
-    }
-
-    strcpy(partname_prev, partname);
-  }
-
-  fclose(fp);
-  free(line);
-
-  found += scan_spi_gpt(params);
-
-  return found;
+static int scan_real_devs(CgptFindParams *params)
+{
+	int found = 0;
+	char partname[MAX_PARTITION_NAME_LEN];
+	char partname_prev[MAX_PARTITION_NAME_LEN];
+	FILE *fp;
+	char *pathname;
+
+	fp = fopen(PROC_PARTITIONS, "re");
+	if (!fp) {
+		perror("can't read " PROC_PARTITIONS);
+		return found;
+	}
+
+	size_t line_length = 0;
+	char *line = NULL;
+	partname_prev[0] = '\0';
+	while (getline(&line, &line_length, fp) != -1) {
+		int ma, mi;
+		long long unsigned int sz;
+
+		if (sscanf(line, " %d %d %llu %127[^\n ]", &ma, &mi, &sz, partname) != 4)
+			continue;
+
+		/* Only check devices that have partitions under them.
+		 * We can tell by checking that an entry like "sda" is immediately
+		 * followed by one like "sda0". */
+		if (!strncmp(partname_prev, partname, strlen(partname_prev)) &&
+		    strlen(partname_prev)) {
+			if ((pathname = is_wholedev(partname_prev))) {
+				if (do_search(params, pathname)) {
+					found++;
+				}
+			}
+		}
+
+		strcpy(partname_prev, partname);
+	}
+
+	fclose(fp);
+	free(line);
+
+	found += scan_spi_gpt(params);
+
+	return found;
 }
 
+void CgptFind(CgptFindParams *params)
+{
+	if (params == NULL)
+		return;
 
-void CgptFind(CgptFindParams *params) {
-  if (params == NULL)
-    return;
-
-  if (params->drive_name != NULL)
-    do_search(params, params->drive_name);
-  else
-    scan_real_devs(params);
+	if (params->drive_name != NULL)
+		do_search(params, params->drive_name);
+	else
+		scan_real_devs(params);
 }
diff --git a/cgpt/cgpt_legacy.c b/cgpt/cgpt_legacy.c
index 0c98e5d0..62fd6f31 100644
--- a/cgpt/cgpt_legacy.c
+++ b/cgpt/cgpt_legacy.c
@@ -9,58 +9,57 @@
 #include "cgptlib_internal.h"
 #include "vboot_host.h"
 
-int CgptLegacy(CgptLegacyParams *params) {
-  struct drive drive;
-  int gpt_retval;
-  GptHeader *h1, *h2;
+int CgptLegacy(CgptLegacyParams *params)
+{
+	struct drive drive;
+	int gpt_retval;
+	GptHeader *h1, *h2;
 
-  if (params == NULL)
-    return CGPT_FAILED;
+	if (params == NULL)
+		return CGPT_FAILED;
 
-  if (CGPT_OK != DriveOpen(params->drive_name, &drive, O_RDWR,
-                           params->drive_size))
-    return CGPT_FAILED;
+	if (CGPT_OK != DriveOpen(params->drive_name, &drive, O_RDWR, params->drive_size))
+		return CGPT_FAILED;
 
-  if (GPT_SUCCESS != (gpt_retval = GptValidityCheck(&drive.gpt))) {
-    Error("GptValidityCheck() returned %d: %s\n",
-          gpt_retval, GptError(gpt_retval));
-    goto bad;
-  }
+	if (GPT_SUCCESS != (gpt_retval = GptValidityCheck(&drive.gpt))) {
+		Error("GptValidityCheck() returned %d: %s\n", gpt_retval, GptError(gpt_retval));
+		goto bad;
+	}
 
-  h1 = (GptHeader *)drive.gpt.primary_header;
-  h2 = (GptHeader *)drive.gpt.secondary_header;
-  if (params->mode == CGPT_LEGACY_MODE_EFIPART) {
-    drive.gpt.ignored = MASK_NONE;
-    memcpy(h1->signature, GPT_HEADER_SIGNATURE, GPT_HEADER_SIGNATURE_SIZE);
-    memcpy(h2->signature, GPT_HEADER_SIGNATURE, GPT_HEADER_SIGNATURE_SIZE);
-    RepairEntries(&drive.gpt, MASK_SECONDARY);
-    drive.gpt.modified |= (GPT_MODIFIED_HEADER1 | GPT_MODIFIED_ENTRIES1 |
-                           GPT_MODIFIED_HEADER2);
-  } else if (params->mode == CGPT_LEGACY_MODE_IGNORE_PRIMARY) {
-    if (!(drive.gpt.valid_headers & MASK_SECONDARY) ||
-        !(drive.gpt.valid_entries & MASK_SECONDARY) ||
-        drive.gpt.ignored & MASK_SECONDARY) {
-      Error("Refusing to mark primary GPT ignored unless secondary is valid.");
-      goto bad;
-    }
-    memset(h1, 0, sizeof(*h1));
-    memcpy(h1->signature, GPT_HEADER_SIGNATURE_IGNORED,
-           GPT_HEADER_SIGNATURE_SIZE);
-    drive.gpt.modified |= GPT_MODIFIED_HEADER1;
-  } else {
-    memcpy(h1->signature, GPT_HEADER_SIGNATURE2, GPT_HEADER_SIGNATURE_SIZE);
-    memcpy(h2->signature, GPT_HEADER_SIGNATURE2, GPT_HEADER_SIGNATURE_SIZE);
-    memset(drive.gpt.primary_entries, 0, drive.gpt.sector_bytes);
-    drive.gpt.modified |= (GPT_MODIFIED_HEADER1 | GPT_MODIFIED_ENTRIES1 |
-                           GPT_MODIFIED_HEADER2);
-  }
+	h1 = (GptHeader *)drive.gpt.primary_header;
+	h2 = (GptHeader *)drive.gpt.secondary_header;
+	if (params->mode == CGPT_LEGACY_MODE_EFIPART) {
+		drive.gpt.ignored = MASK_NONE;
+		memcpy(h1->signature, GPT_HEADER_SIGNATURE, GPT_HEADER_SIGNATURE_SIZE);
+		memcpy(h2->signature, GPT_HEADER_SIGNATURE, GPT_HEADER_SIGNATURE_SIZE);
+		RepairEntries(&drive.gpt, MASK_SECONDARY);
+		drive.gpt.modified |=
+			(GPT_MODIFIED_HEADER1 | GPT_MODIFIED_ENTRIES1 | GPT_MODIFIED_HEADER2);
+	} else if (params->mode == CGPT_LEGACY_MODE_IGNORE_PRIMARY) {
+		if (!(drive.gpt.valid_headers & MASK_SECONDARY) ||
+		    !(drive.gpt.valid_entries & MASK_SECONDARY) ||
+		    drive.gpt.ignored & MASK_SECONDARY) {
+			Error("Refusing to mark primary GPT ignored unless secondary is "
+			      "valid.");
+			goto bad;
+		}
+		memset(h1, 0, sizeof(*h1));
+		memcpy(h1->signature, GPT_HEADER_SIGNATURE_IGNORED, GPT_HEADER_SIGNATURE_SIZE);
+		drive.gpt.modified |= GPT_MODIFIED_HEADER1;
+	} else {
+		memcpy(h1->signature, GPT_HEADER_SIGNATURE2, GPT_HEADER_SIGNATURE_SIZE);
+		memcpy(h2->signature, GPT_HEADER_SIGNATURE2, GPT_HEADER_SIGNATURE_SIZE);
+		memset(drive.gpt.primary_entries, 0, drive.gpt.sector_bytes);
+		drive.gpt.modified |=
+			(GPT_MODIFIED_HEADER1 | GPT_MODIFIED_ENTRIES1 | GPT_MODIFIED_HEADER2);
+	}
 
-  UpdateCrc(&drive.gpt);
+	UpdateCrc(&drive.gpt);
 
-  // Write it all out
-  return DriveClose(&drive, 1);
+	// Write it all out
+	return DriveClose(&drive, 1);
 
 bad:
-  (void) DriveClose(&drive, 0);
-  return CGPT_FAILED;
+	(void)DriveClose(&drive, 0);
+	return CGPT_FAILED;
 }
diff --git a/cgpt/cgpt_nor.c b/cgpt/cgpt_nor.c
index fc8e2087..f51545b7 100644
--- a/cgpt/cgpt_nor.c
+++ b/cgpt/cgpt_nor.c
@@ -29,174 +29,179 @@
 static const char FLASHROM_PATH[] = "/usr/sbin/flashrom";
 
 // Obtain the MTD size from its sysfs node.
-int GetMtdSize(const char *mtd_device, uint64_t *size) {
-  mtd_device = strrchr(mtd_device, '/');
-  if (mtd_device == NULL) {
-    errno = EINVAL;
-    return 1;
-  }
-  char *sysfs_name;
-  if (asprintf(&sysfs_name, "/sys/class/mtd%s/size", mtd_device) == -1) {
-    return 1;
-  }
-  FILE *fp = fopen(sysfs_name, "r");
-  free(sysfs_name);
-  if (fp == NULL) {
-    return 1;
-  }
-  int ret = (fscanf(fp, "%" PRIu64 "\n", size) != 1);
-  fclose(fp);
-  return ret;
+int GetMtdSize(const char *mtd_device, uint64_t *size)
+{
+	mtd_device = strrchr(mtd_device, '/');
+	if (mtd_device == NULL) {
+		errno = EINVAL;
+		return 1;
+	}
+	char *sysfs_name;
+	if (asprintf(&sysfs_name, "/sys/class/mtd%s/size", mtd_device) == -1) {
+		return 1;
+	}
+	FILE *fp = fopen(sysfs_name, "r");
+	free(sysfs_name);
+	if (fp == NULL) {
+		return 1;
+	}
+	int ret = (fscanf(fp, "%" PRIu64 "\n", size) != 1);
+	fclose(fp);
+	return ret;
 }
 
 // TODO(b:184812319): Remove these functions and use subprocess_run everywhere.
-int ForkExecV(const char *cwd, const char *const argv[]) {
-  pid_t pid = fork();
-  if (pid == -1) {
-    return -1;
-  }
-  int status = -1;
-  if (pid == 0) {
-    if (cwd && chdir(cwd) != 0) {
-      return -1;
-    }
-    execv(argv[0], (char *const *)argv);
-    // If this is reached, execv fails.
-    err(-1, "Cannot exec %s in %s.", argv[0], cwd);
-  } else {
-    if (waitpid(pid, &status, 0) != -1 && WIFEXITED(status))
-      return WEXITSTATUS(status);
-  }
-  return status;
+int ForkExecV(const char *cwd, const char *const argv[])
+{
+	pid_t pid = fork();
+	if (pid == -1) {
+		return -1;
+	}
+	int status = -1;
+	if (pid == 0) {
+		if (cwd && chdir(cwd) != 0) {
+			return -1;
+		}
+		execv(argv[0], (char *const *)argv);
+		// If this is reached, execv fails.
+		err(-1, "Cannot exec %s in %s.", argv[0], cwd);
+	} else {
+		if (waitpid(pid, &status, 0) != -1 && WIFEXITED(status))
+			return WEXITSTATUS(status);
+	}
+	return status;
 }
 
-static int ForkExecL(const char *cwd, const char *cmd, ...) {
-  int argc;
-  va_list ap;
-  va_start(ap, cmd);
-  for (argc = 1; va_arg(ap, char *) != NULL; ++argc);
-  va_end(ap);
-
-  va_start(ap, cmd);
-  const char **argv = calloc(argc + 1, sizeof(char *));
-  if (argv == NULL) {
-    errno = ENOMEM;
-    va_end(ap);
-    return -1;
-  }
-  argv[0] = cmd;
-  int i;
-  for (i = 1; i < argc; ++i) {
-    argv[i] = va_arg(ap, char *);
-  }
-  va_end(ap);
-
-  int ret = ForkExecV(cwd, argv);
-  free(argv);
-  return ret;
+static int ForkExecL(const char *cwd, const char *cmd, ...)
+{
+	int argc;
+	va_list ap;
+	va_start(ap, cmd);
+	for (argc = 1; va_arg(ap, char *) != NULL; ++argc)
+		;
+	va_end(ap);
+
+	va_start(ap, cmd);
+	const char **argv = calloc(argc + 1, sizeof(char *));
+	if (argv == NULL) {
+		errno = ENOMEM;
+		va_end(ap);
+		return -1;
+	}
+	argv[0] = cmd;
+	int i;
+	for (i = 1; i < argc; ++i) {
+		argv[i] = va_arg(ap, char *);
+	}
+	va_end(ap);
+
+	int ret = ForkExecV(cwd, argv);
+	free(argv);
+	return ret;
 }
 
-static int read_write(int source_fd,
-                      uint64_t size,
-                      const char *src_name,
-                      int idx) {
-  int ret = 1;
-  const int bufsize = 4096;
-  char *buf = malloc(bufsize);
-  if (buf == NULL) {
-    goto clean_exit;
-  }
-
-  ret++;
-  char *dest;
-  if (asprintf(&dest, "%s_%d", src_name, idx) == -1) {
-    goto free_buf;
-  }
-
-  ret++;
-  int dest_fd = open(dest, O_WRONLY | O_CLOEXEC | O_CREAT, 0600);
-  if (dest_fd < 0) {
-    goto free_dest;
-  }
-
-  ret++;
-  uint64_t copied = 0;
-  ssize_t nr_read;
-  ssize_t nr_write;
-  while (copied < size) {
-    size_t to_read = size - copied;
-    if (to_read > bufsize) {
-      to_read = bufsize;
-    }
-    nr_read = read(source_fd, buf, to_read);
-    if (nr_read < 0) {
-      goto close_dest_fd;
-    }
-    nr_write = 0;
-    while (nr_write < nr_read) {
-      ssize_t s = write(dest_fd, buf + nr_write, nr_read - nr_write);
-      if (s < 0) {
-        goto close_dest_fd;
-      }
-      nr_write += s;
-    }
-    copied += nr_read;
-  }
-
-  ret = 0;
+static int read_write(int source_fd, uint64_t size, const char *src_name, int idx)
+{
+	int ret = 1;
+	const int bufsize = 4096;
+	char *buf = malloc(bufsize);
+	if (buf == NULL) {
+		goto clean_exit;
+	}
+
+	ret++;
+	char *dest;
+	if (asprintf(&dest, "%s_%d", src_name, idx) == -1) {
+		goto free_buf;
+	}
+
+	ret++;
+	int dest_fd = open(dest, O_WRONLY | O_CLOEXEC | O_CREAT, 0600);
+	if (dest_fd < 0) {
+		goto free_dest;
+	}
+
+	ret++;
+	uint64_t copied = 0;
+	ssize_t nr_read;
+	ssize_t nr_write;
+	while (copied < size) {
+		size_t to_read = size - copied;
+		if (to_read > bufsize) {
+			to_read = bufsize;
+		}
+		nr_read = read(source_fd, buf, to_read);
+		if (nr_read < 0) {
+			goto close_dest_fd;
+		}
+		nr_write = 0;
+		while (nr_write < nr_read) {
+			ssize_t s = write(dest_fd, buf + nr_write, nr_read - nr_write);
+			if (s < 0) {
+				goto close_dest_fd;
+			}
+			nr_write += s;
+		}
+		copied += nr_read;
+	}
+
+	ret = 0;
 
 close_dest_fd:
-  close(dest_fd);
+	close(dest_fd);
 free_dest:
-  free(dest);
+	free(dest);
 free_buf:
-  free(buf);
+	free(buf);
 clean_exit:
-  return ret;
+	return ret;
 }
 
-static int split_gpt(const char *dir_name, const char *file_name) {
-  int ret = 1;
-  char *source;
-  if (asprintf(&source, "%s/%s", dir_name, file_name) == -1) {
-    goto clean_exit;
-  }
-
-  ret++;
-  int fd = open(source, O_RDONLY | O_CLOEXEC);
-  if (fd < 0) {
-    goto free_source;
-  }
-
-  ret++;
-  struct stat stat;
-  if (fstat(fd, &stat) != 0 || (stat.st_size & 1) != 0) {
-    goto close_fd;
-  }
-  uint64_t half_size = stat.st_size / 2;
-
-  ret++;
-  if (read_write(fd, half_size, source, 1) != 0 ||
-      read_write(fd, half_size, source, 2) != 0) {
-    goto close_fd;
-  }
-
-  ret = 0;
+static int split_gpt(const char *dir_name, const char *file_name)
+{
+	int ret = 1;
+	char *source;
+	if (asprintf(&source, "%s/%s", dir_name, file_name) == -1) {
+		goto clean_exit;
+	}
+
+	ret++;
+	int fd = open(source, O_RDONLY | O_CLOEXEC);
+	if (fd < 0) {
+		goto free_source;
+	}
+
+	ret++;
+	struct stat stat;
+	if (fstat(fd, &stat) != 0 || (stat.st_size & 1) != 0) {
+		goto close_fd;
+	}
+	uint64_t half_size = stat.st_size / 2;
+
+	ret++;
+	if (read_write(fd, half_size, source, 1) != 0 ||
+	    read_write(fd, half_size, source, 2) != 0) {
+		goto close_fd;
+	}
+
+	ret = 0;
 close_fd:
-  close(fd);
+	close(fd);
 free_source:
-  free(source);
+	free(source);
 clean_exit:
-  return ret;
+	return ret;
 }
 
-static int remove_file_or_dir(const char *fpath, const struct stat *sb,
-                              int typeflag, struct FTW *ftwbuf) {
-  return remove(fpath);
+static int remove_file_or_dir(const char *fpath, const struct stat *sb, int typeflag,
+			      struct FTW *ftwbuf)
+{
+	return remove(fpath);
 }
 
-int RemoveDir(const char *dir) {
-  return nftw(dir, remove_file_or_dir, 20, FTW_DEPTH | FTW_PHYS);
+int RemoveDir(const char *dir)
+{
+	return nftw(dir, remove_file_or_dir, 20, FTW_DEPTH | FTW_PHYS);
 }
 
 #define FLASHROM_RW_GPT_PRI "RW_GPT_PRIMARY:rw_gpt_1",
@@ -205,89 +210,97 @@ int RemoveDir(const char *dir) {
 
 // Read RW_GPT from NOR flash to "rw_gpt" in a dir.
 // TODO(b:184812319): Replace this function with flashrom_read.
-int ReadNorFlash(const char *dir) {
-  int ret = 0;
-
-  // Read RW_GPT section from NOR flash to "rw_gpt".
-  ret++;
-
-  char *cwd = getcwd(NULL, 0);
-  if (!cwd) {
-    Error("Cannot get current directory.\n");
-    return ret;
-  }
-  if (chdir(dir) < 0) {
-    Error("Cannot change directory.\n");
-    goto out_free;
-  }
-  const char *const argv[] = {FLASHROM_PATH, "-i", FLASHROM_RW_GPT, "-r"};
-  // Redirect stdout to /dev/null so that flashrom does not muck up cgpt's
-  // output.
-  if (subprocess_run(argv, &subprocess_null, &subprocess_null, NULL) != 0) {
-    Error("Cannot exec flashrom to read from RW_GPT section.\n");
-  } else {
-    ret = 0;
-  }
-  if (chdir(cwd) < 0) {
-    Error("Cannot change directory back to original.\n");
-    goto out_free;
-  }
+int ReadNorFlash(const char *dir)
+{
+	int ret = 0;
+
+	// Read RW_GPT section from NOR flash to "rw_gpt".
+	ret++;
+
+	char *cwd = getcwd(NULL, 0);
+	if (!cwd) {
+		Error("Cannot get current directory.\n");
+		return ret;
+	}
+	if (chdir(dir) < 0) {
+		Error("Cannot change directory.\n");
+		goto out_free;
+	}
+	const char *const argv[] = {FLASHROM_PATH, "-i", FLASHROM_RW_GPT, "-r"};
+	// Redirect stdout to /dev/null so that flashrom does not muck up cgpt's
+	// output.
+	if (subprocess_run(argv, &subprocess_null, &subprocess_null, NULL) != 0) {
+		Error("Cannot exec flashrom to read from RW_GPT section.\n");
+	} else {
+		ret = 0;
+	}
+	if (chdir(cwd) < 0) {
+		Error("Cannot change directory back to original.\n");
+		goto out_free;
+	}
 
 out_free:
-  free(cwd);
-  return ret;
+	free(cwd);
+	return ret;
 }
 
 static int FlashromWriteRegion(const char *region)
 {
-  const char *const argv[] = {FLASHROM_PATH, "-i", region, "-w", "--noverify-all"};
-  // Redirect stdout to /dev/null so that flashrom does not muck up cgpt's
-  // output.
-  if (subprocess_run(argv, &subprocess_null, &subprocess_null, NULL) != 0) {
-    Warning("Cannot write '%s' back with flashrom.\n", region);
-    return 1;
-  }
-  return 0;
+	const char *const argv[] = {FLASHROM_PATH, "-i", region, "-w", "--noverify-all"};
+	// Redirect stdout to /dev/null so that flashrom does not muck up cgpt's
+	// output.
+	if (subprocess_run(argv, &subprocess_null, &subprocess_null, NULL) != 0) {
+		Warning("Cannot write '%s' back with flashrom.\n", region);
+		return 1;
+	}
+	return 0;
 }
 
 // Write "rw_gpt" back to NOR flash. We write the file in two parts for safety.
 // TODO(b:184812319): Replace this function with flashrom_write.
-int WriteNorFlash(const char *dir) {
-  int ret = 0;
-
-  ret++;
-  if (split_gpt(dir, "rw_gpt") != 0) {
-    Error("Cannot split rw_gpt in two.\n");
-    return ret;
-  }
-  ret++;
-  int nr_fails = 0;
-
-  char *cwd = getcwd(NULL, 0);
-  if (!cwd) {
-    Error("Cannot get current directory.\n");
-    return ret;
-  }
-  if (chdir(dir) < 0) {
-    Error("Cannot change directory.\n");
-    goto out_free;
-  }
-  if (FlashromWriteRegion(FLASHROM_RW_GPT_PRI))
-    nr_fails++;
-  if (FlashromWriteRegion(FLASHROM_RW_GPT_SEC))
-    nr_fails++;
-
-  if (chdir(cwd) < 0) {
-    Error("Cannot change directory back to original.\n");
-    goto out_free;
-  }
-  switch (nr_fails) {
-    case 0: ret = 0; break;
-    case 1: Warning("It might still be okay.\n"); break;
-    case 2: Error("Cannot write both parts back with flashrom.\n"); break;
-  }
+int WriteNorFlash(const char *dir)
+{
+	int ret = 0;
+
+	ret++;
+	if (split_gpt(dir, "rw_gpt") != 0) {
+		Error("Cannot split rw_gpt in two.\n");
+		return ret;
+	}
+	ret++;
+	int nr_fails = 0;
+
+	char *cwd = getcwd(NULL, 0);
+	if (!cwd) {
+		Error("Cannot get current directory.\n");
+		return ret;
+	}
+	if (chdir(dir) < 0) {
+		Error("Cannot change directory.\n");
+		goto out_free;
+	}
+	if (FlashromWriteRegion(FLASHROM_RW_GPT_PRI))
+		nr_fails++;
+	if (FlashromWriteRegion(FLASHROM_RW_GPT_SEC))
+		nr_fails++;
+
+	if (chdir(cwd) < 0) {
+		Error("Cannot change directory back to original.\n");
+		goto out_free;
+	}
+	switch (nr_fails) {
+	case 0:
+		ret = 0;
+		break;
+	case 1:
+		Warning("It might still be okay.\n");
+		break;
+	case 2:
+		Error("Cannot write both parts back with flashrom.\n");
+		break;
+	}
 
 out_free:
-  free(cwd);
-  return ret;
+	free(cwd);
+	return ret;
 }
diff --git a/cgpt/cgpt_prioritize.c b/cgpt/cgpt_prioritize.c
index d80e4bdd..f0a25317 100644
--- a/cgpt/cgpt_prioritize.c
+++ b/cgpt/cgpt_prioritize.c
@@ -13,203 +13,208 @@
 // We need a sorted list of priority groups, where each element in the list
 // contains an unordered list of GPT partition numbers.
 
-#define MAX_GROUPS 17                   // 0-15, plus one "higher"
+#define MAX_GROUPS 17 // 0-15, plus one "higher"
 
 typedef struct {
-  int priority;                         // priority of this group
-  int num_parts;                        // number of partitions in this group
-  uint32_t *part;                       // array of partitions in this group
+	int priority;	// priority of this group
+	int num_parts;	// number of partitions in this group
+	uint32_t *part; // array of partitions in this group
 } group_t;
 
 typedef struct {
-  int max_parts;                       // max number of partitions in any group
-  int num_groups;                      // number of non-empty groups
-  group_t group[MAX_GROUPS];           // array of groups
+	int max_parts;		   // max number of partitions in any group
+	int num_groups;		   // number of non-empty groups
+	group_t group[MAX_GROUPS]; // array of groups
 } group_list_t;
 
-
-static group_list_t *NewGroupList(int max_p) {
-  int i;
-  group_list_t *gl = (group_list_t *)malloc(sizeof(group_list_t));
-  require(gl);
-  gl->max_parts = max_p;
-  gl->num_groups = 0;
-  // reserve space for the maximum number of partitions in every group
-  for (i=0; i<MAX_GROUPS; i++) {
-    gl->group[i].priority = -1;
-    gl->group[i].num_parts = 0;
-    gl->group[i].part = (uint32_t *)malloc(sizeof(uint32_t) * max_p);
-    require(gl->group[i].part);
-  }
-
-  return gl;
+static group_list_t *NewGroupList(int max_p)
+{
+	int i;
+	group_list_t *gl = (group_list_t *)malloc(sizeof(group_list_t));
+	require(gl);
+	gl->max_parts = max_p;
+	gl->num_groups = 0;
+	// reserve space for the maximum number of partitions in every group
+	for (i = 0; i < MAX_GROUPS; i++) {
+		gl->group[i].priority = -1;
+		gl->group[i].num_parts = 0;
+		gl->group[i].part = (uint32_t *)malloc(sizeof(uint32_t) * max_p);
+		require(gl->group[i].part);
+	}
+
+	return gl;
 }
 
-static void FreeGroups(group_list_t *gl) {
-  int i;
-  for (i=0; i<MAX_GROUPS; i++)
-    free(gl->group[i].part);
-  free(gl);
+static void FreeGroups(group_list_t *gl)
+{
+	int i;
+	for (i = 0; i < MAX_GROUPS; i++)
+		free(gl->group[i].part);
+	free(gl);
 }
 
-static void AddToGroup(group_list_t *gl, int priority, int partition) {
-  int i;
-  // See if I've already got a group with this priority
-  for (i=0; i<gl->num_groups; i++)
-    if (gl->group[i].priority == priority)
-      break;
-  if (i == gl->num_groups) {
-    // no, add a group
-    require(i < MAX_GROUPS);
-    gl->num_groups++;
-    gl->group[i].priority = priority;
-  }
-  // add the partition to it
-  int j = gl->group[i].num_parts;
-  gl->group[i].part[j] = partition;
-  gl->group[i].num_parts++;
+static void AddToGroup(group_list_t *gl, int priority, int partition)
+{
+	int i;
+	// See if I've already got a group with this priority
+	for (i = 0; i < gl->num_groups; i++)
+		if (gl->group[i].priority == priority)
+			break;
+	if (i == gl->num_groups) {
+		// no, add a group
+		require(i < MAX_GROUPS);
+		gl->num_groups++;
+		gl->group[i].priority = priority;
+	}
+	// add the partition to it
+	int j = gl->group[i].num_parts;
+	gl->group[i].part[j] = partition;
+	gl->group[i].num_parts++;
 }
 
-static void ChangeGroup(group_list_t *gl, int old_priority, int new_priority) {
-  int i;
-  for (i=0; i<gl->num_groups; i++)
-    if (gl->group[i].priority == old_priority) {
-      gl->group[i].priority = new_priority;
-      break;
-    }
+static void ChangeGroup(group_list_t *gl, int old_priority, int new_priority)
+{
+	int i;
+	for (i = 0; i < gl->num_groups; i++)
+		if (gl->group[i].priority == old_priority) {
+			gl->group[i].priority = new_priority;
+			break;
+		}
 }
 
-static void SortGroups(group_list_t *gl) {
-  int i, j;
-  group_t tmp;
-
-  // straight insertion sort is fast enough
-  for (i=1; i<gl->num_groups; i++) {
-    tmp = gl->group[i];
-    for (j=i; j && (gl->group[j-1].priority < tmp.priority); j--)
-      gl->group[j] = gl->group[j-1];
-    gl->group[j] = tmp;
-  }
+static void SortGroups(group_list_t *gl)
+{
+	int i, j;
+	group_t tmp;
+
+	// straight insertion sort is fast enough
+	for (i = 1; i < gl->num_groups; i++) {
+		tmp = gl->group[i];
+		for (j = i; j && (gl->group[j - 1].priority < tmp.priority); j--)
+			gl->group[j] = gl->group[j - 1];
+		gl->group[j] = tmp;
+	}
 }
 
-int CgptPrioritize(CgptPrioritizeParams *params) {
-  struct drive drive;
-
-  int priority;
-
-  int gpt_retval;
-  uint32_t index;
-  uint32_t max_part;
-  int num_kernels;
-  int i,j;
-  group_list_t *groups;
-
-  if (params == NULL)
-    return CGPT_FAILED;
-
-  if (CGPT_OK != DriveOpen(params->drive_name, &drive, O_RDWR,
-                           params->drive_size))
-    return CGPT_FAILED;
-
-  if (GPT_SUCCESS != (gpt_retval = GptValidityCheck(&drive.gpt))) {
-    Error("GptValidityCheck() returned %d: %s\n",
-          gpt_retval, GptError(gpt_retval));
-    goto bad;
-  }
-
-  if (CGPT_OK != CheckValid(&drive)) {
-    Error("please run 'cgpt repair' before reordering the priority.\n");
-    (void) DriveClose(&drive, 0);
-    return CGPT_OK;
-  }
-
-  max_part = GetNumberOfEntries(&drive);
-
-  if (params->set_partition) {
-    if (params->set_partition < 1 || params->set_partition > max_part) {
-      Error("invalid partition number: %d (must be between 1 and %d\n",
-            params->set_partition, max_part);
-      goto bad;
-    }
-    index = params->set_partition - 1;
-    // it must be a kernel
-    if (!IsBootable(&drive, PRIMARY, index)) {
-      Error("partition %d is not a ChromeOS kernel\n", params->set_partition);
-      goto bad;
-    }
-  }
-
-  // How many kernel partitions do I have?
-  num_kernels = 0;
-  for (i = 0; i < max_part; i++) {
-    if (IsBootable(&drive, PRIMARY, i))
-      num_kernels++;
-  }
-
-  if (num_kernels) {
-    // Determine the current priority groups
-    groups = NewGroupList(num_kernels);
-    for (i = 0; i < max_part; i++) {
-      if (!IsBootable(&drive, PRIMARY, i))
-        continue;
-
-      priority = GetPriority(&drive, PRIMARY, i);
-
-      // Is this partition special?
-      if (params->set_partition && (i+1 == params->set_partition)) {
-        params->orig_priority = priority;  // remember the original priority
-        if (params->set_friends)
-          AddToGroup(groups, priority, i); // we'll move them all later
-        else
-          AddToGroup(groups, 99, i);       // move only this one
-      } else {
-        AddToGroup(groups, priority, i);   // just remember
-      }
-    }
-
-    // If we're including friends, then change the original group priority
-    if (params->set_partition && params->set_friends) {
-      ChangeGroup(groups, params->orig_priority, 99);
-    }
-
-    // Sorting gives the new order. Now we just need to reassign the
-    // priorities.
-    SortGroups(groups);
-
-    // We'll never lower anything to zero, so if the last group is priority zero
-    // we can ignore it.
-    i = groups->num_groups;
-    if (groups->group[i-1].priority == 0)
-      groups->num_groups--;
-
-    // Where do we start?
-    if (params->max_priority)
-      priority = params->max_priority;
-    else
-      priority = groups->num_groups > 15 ? 15 : groups->num_groups;
-
-    // Figure out what the new values should be
-    for (i=0; i<groups->num_groups; i++) {
-      groups->group[i].priority = priority;
-      if (priority > 1)
-        priority--;
-    }
-
-    // Now apply the ranking to the GPT
-    for (i=0; i<groups->num_groups; i++)
-      for (j=0; j<groups->group[i].num_parts; j++)
-        SetPriority(&drive, PRIMARY,
-                    groups->group[i].part[j], groups->group[i].priority);
-
-    FreeGroups(groups);
-  }
-
-  // Write it all out
-  UpdateAllEntries(&drive);
-
-  return DriveClose(&drive, 1);
+int CgptPrioritize(CgptPrioritizeParams *params)
+{
+	struct drive drive;
+
+	int priority;
+
+	int gpt_retval;
+	uint32_t index;
+	uint32_t max_part;
+	int num_kernels;
+	int i, j;
+	group_list_t *groups;
+
+	if (params == NULL)
+		return CGPT_FAILED;
+
+	if (CGPT_OK != DriveOpen(params->drive_name, &drive, O_RDWR, params->drive_size))
+		return CGPT_FAILED;
+
+	if (GPT_SUCCESS != (gpt_retval = GptValidityCheck(&drive.gpt))) {
+		Error("GptValidityCheck() returned %d: %s\n", gpt_retval, GptError(gpt_retval));
+		goto bad;
+	}
+
+	if (CGPT_OK != CheckValid(&drive)) {
+		Error("please run 'cgpt repair' before reordering the priority.\n");
+		(void)DriveClose(&drive, 0);
+		return CGPT_OK;
+	}
+
+	max_part = GetNumberOfEntries(&drive);
+
+	if (params->set_partition) {
+		if (params->set_partition < 1 || params->set_partition > max_part) {
+			Error("invalid partition number: %d (must be between 1 and %d\n",
+			      params->set_partition, max_part);
+			goto bad;
+		}
+		index = params->set_partition - 1;
+		// it must be a kernel
+		if (!IsBootable(&drive, PRIMARY, index)) {
+			Error("partition %d is not a ChromeOS kernel\n", params->set_partition);
+			goto bad;
+		}
+	}
+
+	// How many kernel partitions do I have?
+	num_kernels = 0;
+	for (i = 0; i < max_part; i++) {
+		if (IsBootable(&drive, PRIMARY, i))
+			num_kernels++;
+	}
+
+	if (num_kernels) {
+		// Determine the current priority groups
+		groups = NewGroupList(num_kernels);
+		for (i = 0; i < max_part; i++) {
+			if (!IsBootable(&drive, PRIMARY, i))
+				continue;
+
+			priority = GetPriority(&drive, PRIMARY, i);
+
+			// Is this partition special?
+			if (params->set_partition && (i + 1 == params->set_partition)) {
+				params->orig_priority =
+					priority; // remember the original priority
+				if (params->set_friends)
+					AddToGroup(groups, priority,
+						   i); // we'll move them all later
+				else
+					AddToGroup(groups, 99, i); // move only this one
+			} else {
+				AddToGroup(groups, priority, i); // just remember
+			}
+		}
+
+		// If we're including friends, then change the original group priority
+		if (params->set_partition && params->set_friends) {
+			ChangeGroup(groups, params->orig_priority, 99);
+		}
+
+		// Sorting gives the new order. Now we just need to reassign the
+		// priorities.
+		SortGroups(groups);
+
+		// We'll never lower anything to zero, so if the last group is priority zero
+		// we can ignore it.
+		i = groups->num_groups;
+		if (groups->group[i - 1].priority == 0)
+			groups->num_groups--;
+
+		// Where do we start?
+		if (params->max_priority)
+			priority = params->max_priority;
+		else
+			priority = groups->num_groups > 15 ? 15 : groups->num_groups;
+
+		// Figure out what the new values should be
+		for (i = 0; i < groups->num_groups; i++) {
+			groups->group[i].priority = priority;
+			if (priority > 1)
+				priority--;
+		}
+
+		// Now apply the ranking to the GPT
+		for (i = 0; i < groups->num_groups; i++)
+			for (j = 0; j < groups->group[i].num_parts; j++)
+				SetPriority(&drive, PRIMARY, groups->group[i].part[j],
+					    groups->group[i].priority);
+
+		FreeGroups(groups);
+	}
+
+	// Write it all out
+	UpdateAllEntries(&drive);
+
+	return DriveClose(&drive, 1);
 
 bad:
-  (void) DriveClose(&drive, 0);
-  return CGPT_FAILED;
+	(void)DriveClose(&drive, 0);
+	return CGPT_FAILED;
 }
diff --git a/cgpt/cgpt_repair.c b/cgpt/cgpt_repair.c
index b8af65f7..e64e815e 100644
--- a/cgpt/cgpt_repair.c
+++ b/cgpt/cgpt_repair.c
@@ -9,65 +9,65 @@
 #include "cgptlib_internal.h"
 #include "vboot_host.h"
 
-int CgptRepair(CgptRepairParams *params) {
-  struct drive drive;
+int CgptRepair(CgptRepairParams *params)
+{
+	struct drive drive;
 
-  if (params == NULL)
-    return CGPT_FAILED;
+	if (params == NULL)
+		return CGPT_FAILED;
 
-  if (CGPT_OK != DriveOpen(params->drive_name, &drive, O_RDWR,
-                           params->drive_size))
-    return CGPT_FAILED;
+	if (CGPT_OK != DriveOpen(params->drive_name, &drive, O_RDWR, params->drive_size))
+		return CGPT_FAILED;
 
-  int gpt_retval = GptValidityCheck(&drive.gpt);
-  if (params->verbose)
-    printf("GptValidityCheck() returned %d: %s\n",
-           gpt_retval, GptError(gpt_retval));
+	int gpt_retval = GptValidityCheck(&drive.gpt);
+	if (params->verbose)
+		printf("GptValidityCheck() returned %d: %s\n", gpt_retval,
+		       GptError(gpt_retval));
 
-  GptRepair(&drive.gpt);
-  if (drive.gpt.modified & GPT_MODIFIED_HEADER1)
-    printf("Primary Header is updated.\n");
-  if (drive.gpt.modified & GPT_MODIFIED_ENTRIES1)
-    printf("Primary Entries is updated.\n");
-  if (drive.gpt.modified & GPT_MODIFIED_ENTRIES2)
-    printf("Secondary Entries is updated.\n");
-  if (drive.gpt.modified & GPT_MODIFIED_HEADER2)
-    printf("Secondary Header is updated.\n");
+	GptRepair(&drive.gpt);
+	if (drive.gpt.modified & GPT_MODIFIED_HEADER1)
+		printf("Primary Header is updated.\n");
+	if (drive.gpt.modified & GPT_MODIFIED_ENTRIES1)
+		printf("Primary Entries is updated.\n");
+	if (drive.gpt.modified & GPT_MODIFIED_ENTRIES2)
+		printf("Secondary Entries is updated.\n");
+	if (drive.gpt.modified & GPT_MODIFIED_HEADER2)
+		printf("Secondary Header is updated.\n");
 
-  /*
-   * If the drive size increased (say, volume expansion),
-   * the secondary header/entries moved to end of drive,
-   * but both headers do not reflect the new drive size
-   * (Alternate LBA in primary; Last Usable LBA in both).
-   *
-   * Per the UEFI spec, first move the secondary header
-   * to the end of drive (done above), and later update
-   * primary/secondary headers to reflect the new size.
-   *
-   * Note: do not check for last_usable_lba, as it does
-   * not change if '-D' is specified (run_cgpt_tests.sh).
-   */
-  GptHeader *primary = (GptHeader *)(drive.gpt.primary_header);
-  GptHeader *secondary = (GptHeader *)(drive.gpt.secondary_header);
-  if ((primary->alternate_lba < secondary->my_lba) &&
-      drive.gpt.modified == (GPT_MODIFIED_HEADER2 | GPT_MODIFIED_ENTRIES2)) {
-    printf("Drive size expansion detected; headers update required.\n");
+	/*
+	 * If the drive size increased (say, volume expansion),
+	 * the secondary header/entries moved to end of drive,
+	 * but both headers do not reflect the new drive size
+	 * (Alternate LBA in primary; Last Usable LBA in both).
+	 *
+	 * Per the UEFI spec, first move the secondary header
+	 * to the end of drive (done above), and later update
+	 * primary/secondary headers to reflect the new size.
+	 *
+	 * Note: do not check for last_usable_lba, as it does
+	 * not change if '-D' is specified (run_cgpt_tests.sh).
+	 */
+	GptHeader *primary = (GptHeader *)(drive.gpt.primary_header);
+	GptHeader *secondary = (GptHeader *)(drive.gpt.secondary_header);
+	if ((primary->alternate_lba < secondary->my_lba) &&
+	    drive.gpt.modified == (GPT_MODIFIED_HEADER2 | GPT_MODIFIED_ENTRIES2)) {
+		printf("Drive size expansion detected; headers update required.\n");
 
-    if (CGPT_OK != DriveClose(&drive, 1))
-      return CGPT_FAILED;
-    if (CGPT_OK != DriveOpen(params->drive_name, &drive, O_RDWR,
-                             params->drive_size))
-      return CGPT_FAILED;
+		if (CGPT_OK != DriveClose(&drive, 1))
+			return CGPT_FAILED;
+		if (CGPT_OK !=
+		    DriveOpen(params->drive_name, &drive, O_RDWR, params->drive_size))
+			return CGPT_FAILED;
 
-    primary = (GptHeader *)(drive.gpt.primary_header);
-    secondary = (GptHeader *)(drive.gpt.secondary_header);
-    primary->alternate_lba = secondary->my_lba;
-    primary->last_usable_lba = secondary->last_usable_lba
-                             = DriveLastUsableLBA(&drive);
-    drive.gpt.modified = GPT_MODIFIED_HEADER1 | GPT_MODIFIED_HEADER2;
-    UpdateCrc(&drive.gpt);
-    printf("Primary Header updated.\n");
-    printf("Secondary Header updated.\n");
-  }
-  return DriveClose(&drive, 1);
+		primary = (GptHeader *)(drive.gpt.primary_header);
+		secondary = (GptHeader *)(drive.gpt.secondary_header);
+		primary->alternate_lba = secondary->my_lba;
+		primary->last_usable_lba = secondary->last_usable_lba =
+			DriveLastUsableLBA(&drive);
+		drive.gpt.modified = GPT_MODIFIED_HEADER1 | GPT_MODIFIED_HEADER2;
+		UpdateCrc(&drive.gpt);
+		printf("Primary Header updated.\n");
+		printf("Secondary Header updated.\n");
+	}
+	return DriveClose(&drive, 1);
 }
diff --git a/cgpt/cgpt_show.c b/cgpt/cgpt_show.c
index fc1e3de5..c7743bbd 100644
--- a/cgpt/cgpt_show.c
+++ b/cgpt/cgpt_show.c
@@ -19,396 +19,406 @@
  *
  * Needs (size*3-1+3) bytes of space in 'buf' (included the tailing '\0').
  */
-#define BUFFER_SIZE(size) (size *3 - 1 + 3)
-static short Uint8To2Chars(const uint8_t t) {
-  int h = t >> 4;
-  int l = t & 0xf;
-  h = (h >= 0xA) ? h - 0xA + 'A' : h + '0';
-  l = (l >= 0xA) ? l - 0xA + 'A' : l + '0';
-  return (h << 8) + l;
+#define BUFFER_SIZE(size) (size * 3 - 1 + 3)
+static short Uint8To2Chars(const uint8_t t)
+{
+	int h = t >> 4;
+	int l = t & 0xf;
+	h = (h >= 0xA) ? h - 0xA + 'A' : h + '0';
+	l = (l >= 0xA) ? l - 0xA + 'A' : l + '0';
+	return (h << 8) + l;
 }
 
-static void RawDump(const uint8_t *memory, const int size,
-                    char *buf, int group) {
-  int i, outlen = 0;
-  buf[outlen++] = '[';
-  for (i = 0; i < size; ++i) {
-    short c2 = Uint8To2Chars(memory[i]);
-    buf[outlen++] = c2 >> 8;
-    buf[outlen++] = c2 & 0xff;
-    if (i != (size - 1) && ((i + 1) % group) == 0)
-      buf[outlen++] = '-';
-  }
-  buf[outlen++] = ']';
-  buf[outlen++] = '\0';
+static void RawDump(const uint8_t *memory, const int size, char *buf, int group)
+{
+	int i, outlen = 0;
+	buf[outlen++] = '[';
+	for (i = 0; i < size; ++i) {
+		short c2 = Uint8To2Chars(memory[i]);
+		buf[outlen++] = c2 >> 8;
+		buf[outlen++] = c2 & 0xff;
+		if (i != (size - 1) && ((i + 1) % group) == 0)
+			buf[outlen++] = '-';
+	}
+	buf[outlen++] = ']';
+	buf[outlen++] = '\0';
 }
 
 /* Output formatters */
-#define TITLE_FMT      "%12s%12s%8s  %s\n"
-#define GPT_FMT        "%12"PRId64"%12"PRId64"%8s  %s\n"
-#define GPT_MORE       "%12s%12s%8s  ", "", "", ""
-#define PARTITION_FMT  "%12"PRId64"%12"PRId64"%8d  %s\n"
+#define TITLE_FMT "%12s%12s%8s  %s\n"
+#define GPT_FMT "%12" PRId64 "%12" PRId64 "%8s  %s\n"
+#define GPT_MORE "%12s%12s%8s  ", "", "", ""
+#define PARTITION_FMT "%12" PRId64 "%12" PRId64 "%8d  %s\n"
 #define PARTITION_MORE "%12s%12s%8s  %s%s\n", "", "", ""
 
-static void PrintSignature(const char *indent, const char *sig, size_t n,
-                           int raw) {
-  size_t i;
-  printf("%sSig: ", indent);
-  if (!raw) {
-    printf("[");
-    for (i = 0; i < n; ++i)
-      printf("%c", sig[i]);
-    printf("]");
-  } else {
-    char *buf = malloc(BUFFER_SIZE(n));
-    RawDump((uint8_t *)sig, n, buf, 1);
-    printf("%s", buf);
-    free(buf);
-  }
-  printf("\n");
+static void PrintSignature(const char *indent, const char *sig, size_t n, int raw)
+{
+	size_t i;
+	printf("%sSig: ", indent);
+	if (!raw) {
+		printf("[");
+		for (i = 0; i < n; ++i)
+			printf("%c", sig[i]);
+		printf("]");
+	} else {
+		char *buf = malloc(BUFFER_SIZE(n));
+		RawDump((uint8_t *)sig, n, buf, 1);
+		printf("%s", buf);
+		free(buf);
+	}
+	printf("\n");
 }
 
-static void HeaderDetails(GptHeader *header, GptEntry *entries,
-                          const char *indent, int raw) {
-  PrintSignature(indent, header->signature, sizeof(header->signature), raw);
-
-  printf("%sRev: 0x%08x\n", indent, header->revision);
-  printf("%sSize: %d (blocks)\n", indent, header->size);
-  printf("%sHeader CRC: 0x%08x %s\n", indent, header->header_crc32,
-         (HeaderCrc(header) != header->header_crc32) ? "(INVALID)" : "");
-  printf("%sMy LBA: %lld\n", indent, (long long)header->my_lba);
-  printf("%sAlternate LBA: %lld\n", indent, (long long)header->alternate_lba);
-  printf("%sFirst LBA: %lld\n", indent, (long long)header->first_usable_lba);
-  printf("%sLast LBA: %lld\n", indent, (long long)header->last_usable_lba);
-
-  {  /* For disk guid */
-    char buf[GUID_STRLEN];
-    GuidToStr(&header->disk_uuid, buf, GUID_STRLEN);
-    printf("%sDisk UUID: %s\n", indent, buf);
-  }
-
-  printf("%sEntries LBA: %lld\n", indent, (long long)header->entries_lba);
-  printf("%sNumber of entries: %d\n", indent, header->number_of_entries);
-  printf("%sSize of entry: %d\n", indent, header->size_of_entry);
-  printf("%sEntries CRC: 0x%08x %s\n", indent, header->entries_crc32,
-         header->entries_crc32 !=
-             Crc32((const uint8_t *)entries,header->size_of_entry *
-                                            header->number_of_entries)
-             ? "INVALID" : ""
-         );
+static void HeaderDetails(GptHeader *header, GptEntry *entries, const char *indent, int raw)
+{
+	PrintSignature(indent, header->signature, sizeof(header->signature), raw);
+
+	printf("%sRev: 0x%08x\n", indent, header->revision);
+	printf("%sSize: %d (blocks)\n", indent, header->size);
+	printf("%sHeader CRC: 0x%08x %s\n", indent, header->header_crc32,
+	       (HeaderCrc(header) != header->header_crc32) ? "(INVALID)" : "");
+	printf("%sMy LBA: %lld\n", indent, (long long)header->my_lba);
+	printf("%sAlternate LBA: %lld\n", indent, (long long)header->alternate_lba);
+	printf("%sFirst LBA: %lld\n", indent, (long long)header->first_usable_lba);
+	printf("%sLast LBA: %lld\n", indent, (long long)header->last_usable_lba);
+
+	{ /* For disk guid */
+		char buf[GUID_STRLEN];
+		GptGuidToStr(&header->disk_uuid, buf, GUID_STRLEN, GPT_GUID_UPPERCASE);
+		printf("%sDisk UUID: %s\n", indent, buf);
+	}
+
+	printf("%sEntries LBA: %lld\n", indent, (long long)header->entries_lba);
+	printf("%sNumber of entries: %d\n", indent, header->number_of_entries);
+	printf("%sSize of entry: %d\n", indent, header->size_of_entry);
+	printf("%sEntries CRC: 0x%08x %s\n", indent, header->entries_crc32,
+	       header->entries_crc32 != Crc32((const uint8_t *)entries,
+					      header->size_of_entry * header->number_of_entries)
+		       ? "INVALID"
+		       : "");
 }
 
-void EntryDetails(GptEntry *entry, uint32_t index, int raw) {
-  char contents[256];                   // scratch buffer for formatting output
-  uint8_t label[GPT_PARTNAME_LEN];
-  char type[GUID_STRLEN], unique[GUID_STRLEN];
-  int clen;
-
-  UTF16ToUTF8(entry->name, sizeof(entry->name) / sizeof(entry->name[0]),
-              label, sizeof(label));
-  require(snprintf(contents, sizeof(contents),
-                   "Label: \"%s\"", label) < sizeof(contents));
-  printf(PARTITION_FMT, (uint64_t)entry->starting_lba,
-         (uint64_t)(entry->ending_lba - entry->starting_lba + 1),
-         index+1, contents);
-
-  if (!raw && CGPT_OK == ResolveType(&entry->type, type)) {
-    printf(PARTITION_MORE, "Type: ", type);
-  } else {
-    GuidToStr(&entry->type, type, GUID_STRLEN);
-    printf(PARTITION_MORE, "Type: ", type);
-  }
-  GuidToStr(&entry->unique, unique, GUID_STRLEN);
-  printf(PARTITION_MORE, "UUID: ", unique);
-
-  clen = 0;
-  if (!raw) {
-    if (GuidEqual(&guid_chromeos_kernel, &entry->type) ||
-        GuidEqual(&guid_android_vbmeta, &entry->type)) {
-      int tries = (entry->attrs.fields.gpt_att &
-                   CGPT_ATTRIBUTE_TRIES_MASK) >>
-          CGPT_ATTRIBUTE_TRIES_OFFSET;
-      int successful = (entry->attrs.fields.gpt_att &
-                        CGPT_ATTRIBUTE_SUCCESSFUL_MASK) >>
-          CGPT_ATTRIBUTE_SUCCESSFUL_OFFSET;
-      int priority = (entry->attrs.fields.gpt_att &
-                      CGPT_ATTRIBUTE_PRIORITY_MASK) >>
-          CGPT_ATTRIBUTE_PRIORITY_OFFSET;
-      int error_counter = (entry->attrs.fields.gpt_att &
-                           CGPT_ATTRIBUTE_ERROR_COUNTER_MASK) >>
-          CGPT_ATTRIBUTE_ERROR_COUNTER_OFFSET;
-      clen = snprintf(contents, sizeof(contents),
-                      "priority=%d tries=%d successful=%d error_counter=%d ",
-                      priority, tries, successful, error_counter);
-    }
-
-    if (entry->attrs.fields.required) {
-      clen += snprintf(contents + clen, sizeof(contents) - clen,
-                       "required=%d ", entry->attrs.fields.required);
-      require(clen < sizeof(contents));
-    }
-
-    if (entry->attrs.fields.efi_ignore) {
-      clen += snprintf(contents + clen, sizeof(contents) - clen,
-                       "efi_ignore=%d ", entry->attrs.fields.efi_ignore);
-      require(clen < sizeof(contents));
-    }
-
-    if (entry->attrs.fields.legacy_boot) {
-      clen += snprintf(contents + clen, sizeof(contents) - clen,
-                       "legacy_boot=%d ", entry->attrs.fields.legacy_boot);
-      require(clen < sizeof(contents));
-    }
-  } else {
-    clen = snprintf(contents, sizeof(contents),
-                    "[%x]", entry->attrs.fields.gpt_att);
-  }
-  require(clen < sizeof(contents));
-  if (clen)
-    printf(PARTITION_MORE, "Attr: ", contents);
+void EntryDetails(GptEntry *entry, uint32_t index, int raw)
+{
+	char contents[256]; // scratch buffer for formatting output
+	uint8_t label[GPT_PARTNAME_LEN];
+	char type[GUID_STRLEN], unique[GUID_STRLEN];
+	int clen;
+
+	UTF16ToUTF8(entry->name, sizeof(entry->name) / sizeof(entry->name[0]), label,
+		    sizeof(label));
+	require(snprintf(contents, sizeof(contents), "Label: \"%s\"", label) <
+		sizeof(contents));
+	printf(PARTITION_FMT, (uint64_t)entry->starting_lba,
+	       (uint64_t)(entry->ending_lba - entry->starting_lba + 1), index + 1, contents);
+
+	if (!raw && CGPT_OK == ResolveType(&entry->type, type)) {
+		printf(PARTITION_MORE, "Type: ", type);
+	} else {
+		GptGuidToStr(&entry->type, type, GUID_STRLEN, GPT_GUID_UPPERCASE);
+		printf(PARTITION_MORE, "Type: ", type);
+	}
+	GptGuidToStr(&entry->unique, unique, GUID_STRLEN, GPT_GUID_UPPERCASE);
+	printf(PARTITION_MORE, "UUID: ", unique);
+
+	clen = 0;
+	if (!raw) {
+		if (GuidEqual(&guid_chromeos_kernel, &entry->type) ||
+		    GuidEqual(&guid_android_vbmeta, &entry->type)) {
+			int tries = (entry->attrs.fields.gpt_att & CGPT_ATTRIBUTE_TRIES_MASK) >>
+				    CGPT_ATTRIBUTE_TRIES_OFFSET;
+			int successful = (entry->attrs.fields.gpt_att &
+					  CGPT_ATTRIBUTE_SUCCESSFUL_MASK) >>
+					 CGPT_ATTRIBUTE_SUCCESSFUL_OFFSET;
+			int priority =
+				(entry->attrs.fields.gpt_att & CGPT_ATTRIBUTE_PRIORITY_MASK) >>
+				CGPT_ATTRIBUTE_PRIORITY_OFFSET;
+			int error_counter = (entry->attrs.fields.gpt_att &
+					     CGPT_ATTRIBUTE_ERROR_COUNTER_MASK) >>
+					    CGPT_ATTRIBUTE_ERROR_COUNTER_OFFSET;
+			clen = snprintf(contents, sizeof(contents),
+					"priority=%d tries=%d successful=%d error_counter=%d ",
+					priority, tries, successful, error_counter);
+		}
+
+		if (entry->attrs.fields.required) {
+			clen += snprintf(contents + clen, sizeof(contents) - clen,
+					 "required=%d ", entry->attrs.fields.required);
+			require(clen < sizeof(contents));
+		}
+
+		if (entry->attrs.fields.efi_ignore) {
+			clen += snprintf(contents + clen, sizeof(contents) - clen,
+					 "efi_ignore=%d ", entry->attrs.fields.efi_ignore);
+			require(clen < sizeof(contents));
+		}
+
+		if (entry->attrs.fields.legacy_boot) {
+			clen += snprintf(contents + clen, sizeof(contents) - clen,
+					 "legacy_boot=%d ", entry->attrs.fields.legacy_boot);
+			require(clen < sizeof(contents));
+		}
+	} else {
+		clen = snprintf(contents, sizeof(contents), "[%x]",
+				entry->attrs.fields.gpt_att);
+	}
+	require(clen < sizeof(contents));
+	if (clen)
+		printf(PARTITION_MORE, "Attr: ", contents);
 }
 
-static void EntriesDetails(struct drive *drive, const int secondary, int raw) {
-  uint32_t i;
+static void EntriesDetails(struct drive *drive, const int secondary, int raw)
+{
+	uint32_t i;
 
-  for (i = 0; i < GetNumberOfEntries(drive); ++i) {
-    GptEntry *entry;
-    entry = GetEntry(&drive->gpt, secondary, i);
+	for (i = 0; i < GetNumberOfEntries(drive); ++i) {
+		GptEntry *entry;
+		entry = GetEntry(&drive->gpt, secondary, i);
 
-    if (GuidIsZero(&entry->type))
-      continue;
+		if (GuidIsZero(&entry->type))
+			continue;
 
-    EntryDetails(entry, i, raw);
-  }
+		EntryDetails(entry, i, raw);
+	}
 }
 
-static int GptShow(struct drive *drive, CgptShowParams *params) {
-  int gpt_retval;
-  if (GPT_SUCCESS != (gpt_retval = GptValidityCheck(&drive->gpt))) {
-    Error("GptValidityCheck() returned %d: %s\n",
-          gpt_retval, GptError(gpt_retval));
-    return CGPT_FAILED;
-  }
-
-  if (params->partition) {                      // show single partition
-
-    if (params->partition > GetNumberOfEntries(drive)) {
-      Error("invalid partition number: %d\n", params->partition);
-      return CGPT_FAILED;
-    }
-
-    uint32_t index = params->partition - 1;
-    GptEntry *entry = GetEntry(&drive->gpt, ANY_VALID, index);
-    char buf[256];                      // scratch buffer for string conversion
-
-    if (params->single_item) {
-      switch(params->single_item) {
-      case 'b':
-        printf("%" PRId64 "\n", entry->starting_lba);
-        break;
-      case 's': {
-        uint64_t size = 0;
-        // If these aren't actually defined, don't show anything
-        if (entry->ending_lba || entry->starting_lba)
-          size = entry->ending_lba - entry->starting_lba + 1;
-        printf("%" PRId64 "\n", size);
-        break;
-      }
-      case 't':
-        GuidToStr(&entry->type, buf, sizeof(buf));
-        printf("%s\n", buf);
-        break;
-      case 'u':
-        GuidToStr(&entry->unique, buf, sizeof(buf));
-        printf("%s\n", buf);
-        break;
-      case 'l':
-        UTF16ToUTF8(entry->name, sizeof(entry->name) / sizeof(entry->name[0]),
-                    (uint8_t *)buf, sizeof(buf));
-        printf("%s\n", buf);
-        break;
-      case 'S':
-        printf("%d\n", GetSuccessful(drive, ANY_VALID, index));
-        break;
-      case 'T':
-        printf("%d\n", GetTries(drive, ANY_VALID, index));
-        break;
-      case 'P':
-        printf("%d\n", GetPriority(drive, ANY_VALID, index));
-        break;
-      case 'R':
-        printf("%d\n", GetRequired(drive, ANY_VALID, index));
-        break;
-      case 'B':
-        printf("%d\n", GetLegacyBoot(drive, ANY_VALID, index));
-        break;
-      case 'A':
-        printf("%#x\n", entry->attrs.fields.gpt_att);
-        break;
-      }
-    } else {
-      printf(TITLE_FMT, "start", "size", "part", "contents");
-      EntryDetails(entry, index, params->numeric);
-    }
-
-  } else if (params->quick) {                   // show all partitions, quickly
-    uint32_t i;
-    GptEntry *entry;
-    char type[GUID_STRLEN];
-
-    for (i = 0; i < GetNumberOfEntries(drive); ++i) {
-      entry = GetEntry(&drive->gpt, ANY_VALID, i);
-
-      if (GuidIsZero(&entry->type))
-        continue;
-
-      if (!params->numeric && CGPT_OK == ResolveType(&entry->type, type)) {
-      } else {
-        GuidToStr(&entry->type, type, GUID_STRLEN);
-      }
-      printf(PARTITION_FMT, (uint64_t)entry->starting_lba,
-             (uint64_t)(entry->ending_lba - entry->starting_lba + 1),
-             i+1, type);
-    }
-  } else {                              // show all partitions
-    GptEntry *entries;
-
-    if (params->debug || params->verbose) {
-      printf("Drive details:\n");
-      printf("    Total Size (bytes): %" PRIu64 "\n", drive->size);
-      printf("    LBA Size (bytes): %d\n", drive->gpt.sector_bytes);
-      if (drive->gpt.flags & GPT_FLAG_EXTERNAL) {
-        printf("    Drive (where GPT lives) Size (blocks): %" PRIu64 "\n",
-               drive->gpt.gpt_drive_sectors);
-        printf("    Drive (where partitions live) Size (blocks): %" PRIu64 "\n",
-               drive->gpt.streaming_drive_sectors);
-      } else {
-        // We know gpt_drive_sectors == streaming_drive_sectors here.
-        printf("    Drive Size (blocks): %" PRIu64 "\n",
-               drive->gpt.gpt_drive_sectors);
-      }
-      printf("\n");
-    }
-
-    if (CGPT_OK != ReadPMBR(drive)) {
-      Error("Unable to read PMBR\n");
-      return CGPT_FAILED;
-    }
-
-    printf(TITLE_FMT, "start", "size", "part", "contents");
-    char buf[256];                      // buffer for formatted PMBR content
-    PMBRToStr(&drive->pmbr, buf, sizeof(buf)); // will exit if buf is too small
-    printf(GPT_FMT, (uint64_t)0, (uint64_t)GPT_PMBR_SECTORS, "", buf);
-
-    if (drive->gpt.ignored & MASK_PRIMARY) {
-      printf(GPT_FMT, (uint64_t)GPT_PMBR_SECTORS,
-             (uint64_t)GPT_HEADER_SECTORS, "IGNORED", "Pri GPT header");
-    } else {
-      if (drive->gpt.valid_headers & MASK_PRIMARY) {
-        printf(GPT_FMT, (uint64_t)GPT_PMBR_SECTORS,
-               (uint64_t)GPT_HEADER_SECTORS, "", "Pri GPT header");
-      } else {
-        printf(GPT_FMT, (uint64_t)GPT_PMBR_SECTORS,
-               (uint64_t)GPT_HEADER_SECTORS, "INVALID", "Pri GPT header");
-      }
-
-      if (params->debug ||
-          ((drive->gpt.valid_headers & MASK_PRIMARY) && params->verbose)) {
-        GptHeader *header;
-        char indent[64];
-
-        require(snprintf(indent, sizeof(indent), GPT_MORE) < sizeof(indent));
-        header = (GptHeader*)drive->gpt.primary_header;
-        entries = (GptEntry*)drive->gpt.primary_entries;
-        HeaderDetails(header, entries, indent, params->numeric);
-      }
-
-      GptHeader* primary_header = (GptHeader*)drive->gpt.primary_header;
-      printf(GPT_FMT, (uint64_t)primary_header->entries_lba,
-             (uint64_t)CalculateEntriesSectors(primary_header,
-                         drive->gpt.sector_bytes),
-             drive->gpt.valid_entries & MASK_PRIMARY ? "" : "INVALID",
-             "Pri GPT table");
-
-      if (params->debug ||
-          (drive->gpt.valid_entries & MASK_PRIMARY))
-        EntriesDetails(drive, PRIMARY, params->numeric);
-    }
-
-    /****************************** Secondary *************************/
-    if (drive->gpt.ignored & MASK_SECONDARY) {
-      printf(GPT_FMT,
-             (uint64_t)(drive->gpt.gpt_drive_sectors - GPT_HEADER_SECTORS),
-             (uint64_t)GPT_HEADER_SECTORS, "IGNORED", "Sec GPT header");
-    } else {
-      GptHeader* secondary_header = (GptHeader*)drive->gpt.secondary_header;
-      printf(GPT_FMT, (uint64_t)secondary_header->entries_lba,
-             (uint64_t)CalculateEntriesSectors(secondary_header,
-                         drive->gpt.sector_bytes),
-             drive->gpt.valid_entries & MASK_SECONDARY ? "" : "INVALID",
-             "Sec GPT table");
-      /* We show secondary table details if any of following is true.
-       *   1. in debug mode.
-       *   2. primary table is being ignored
-       *   3. only secondary is valid.
-       *   4. secondary is not identical to primary.
-       */
-      if (params->debug || (drive->gpt.ignored & MASK_PRIMARY) ||
-          ((drive->gpt.valid_entries & MASK_SECONDARY) &&
-           (!(drive->gpt.valid_entries & MASK_PRIMARY) ||
-            memcmp(drive->gpt.primary_entries, drive->gpt.secondary_entries,
-                   secondary_header->number_of_entries *
-                   secondary_header->size_of_entry)))) {
-        EntriesDetails(drive, SECONDARY, params->numeric);
-      }
-
-      if (drive->gpt.valid_headers & MASK_SECONDARY) {
-        printf(GPT_FMT,
-               (uint64_t)(drive->gpt.gpt_drive_sectors - GPT_HEADER_SECTORS),
-               (uint64_t)GPT_HEADER_SECTORS, "", "Sec GPT header");
-      } else {
-        printf(GPT_FMT, (uint64_t)GPT_PMBR_SECTORS,
-               (uint64_t)GPT_HEADER_SECTORS, "INVALID", "Sec GPT header");
-      }
-      /* We show secondary header if any of following is true:
-       *   1. in debug mode.
-       *   2. primary table is being ignored
-       *   3. only secondary is valid.
-       *   4. secondary is not synonymous to primary and not ignored.
-       */
-      if (params->debug || (drive->gpt.ignored & MASK_PRIMARY) ||
-          ((drive->gpt.valid_headers & MASK_SECONDARY) &&
-           (!(drive->gpt.valid_headers & MASK_PRIMARY) ||
-            !IsSynonymous((GptHeader*)drive->gpt.primary_header,
-                          (GptHeader*)drive->gpt.secondary_header)) &&
-           params->verbose)) {
-        GptHeader *header;
-        char indent[64];
-
-        require(snprintf(indent, sizeof(indent), GPT_MORE) < sizeof(indent));
-        header = (GptHeader*)drive->gpt.secondary_header;
-        entries = (GptEntry*)drive->gpt.secondary_entries;
-        HeaderDetails(header, entries, indent, params->numeric);
-      }
-    }
-  }
-
-  CheckValid(drive);
-
-  return CGPT_OK;
+static int GptShow(struct drive *drive, CgptShowParams *params)
+{
+	int gpt_retval;
+	if (GPT_SUCCESS != (gpt_retval = GptValidityCheck(&drive->gpt))) {
+		Error("GptValidityCheck() returned %d: %s\n", gpt_retval, GptError(gpt_retval));
+		return CGPT_FAILED;
+	}
+
+	if (params->partition) { // show single partition
+
+		if (params->partition > GetNumberOfEntries(drive)) {
+			Error("invalid partition number: %d\n", params->partition);
+			return CGPT_FAILED;
+		}
+
+		uint32_t index = params->partition - 1;
+		GptEntry *entry = GetEntry(&drive->gpt, ANY_VALID, index);
+		char buf[256]; // scratch buffer for string conversion
+
+		if (params->single_item) {
+			switch (params->single_item) {
+			case 'b':
+				printf("%" PRId64 "\n", entry->starting_lba);
+				break;
+			case 's': {
+				uint64_t size = 0;
+				// If these aren't actually defined, don't show anything
+				if (entry->ending_lba || entry->starting_lba)
+					size = entry->ending_lba - entry->starting_lba + 1;
+				printf("%" PRId64 "\n", size);
+				break;
+			}
+			case 't':
+				GptGuidToStr(&entry->type, buf, sizeof(buf),
+					     GPT_GUID_UPPERCASE);
+				printf("%s\n", buf);
+				break;
+			case 'u':
+				GptGuidToStr(&entry->unique, buf, sizeof(buf),
+					     GPT_GUID_UPPERCASE);
+				printf("%s\n", buf);
+				break;
+			case 'l':
+				UTF16ToUTF8(entry->name,
+					    sizeof(entry->name) / sizeof(entry->name[0]),
+					    (uint8_t *)buf, sizeof(buf));
+				printf("%s\n", buf);
+				break;
+			case 'S':
+				printf("%d\n", GetSuccessful(drive, ANY_VALID, index));
+				break;
+			case 'T':
+				printf("%d\n", GetTries(drive, ANY_VALID, index));
+				break;
+			case 'P':
+				printf("%d\n", GetPriority(drive, ANY_VALID, index));
+				break;
+			case 'R':
+				printf("%d\n", GetRequired(drive, ANY_VALID, index));
+				break;
+			case 'B':
+				printf("%d\n", GetLegacyBoot(drive, ANY_VALID, index));
+				break;
+			case 'A':
+				printf("%#x\n", entry->attrs.fields.gpt_att);
+				break;
+			}
+		} else {
+			printf(TITLE_FMT, "start", "size", "part", "contents");
+			EntryDetails(entry, index, params->numeric);
+		}
+
+	} else if (params->quick) { // show all partitions, quickly
+		uint32_t i;
+		GptEntry *entry;
+		char type[GUID_STRLEN];
+
+		for (i = 0; i < GetNumberOfEntries(drive); ++i) {
+			entry = GetEntry(&drive->gpt, ANY_VALID, i);
+
+			if (GuidIsZero(&entry->type))
+				continue;
+
+			if (!params->numeric && CGPT_OK == ResolveType(&entry->type, type)) {
+			} else {
+				GptGuidToStr(&entry->type, type, GUID_STRLEN,
+					     GPT_GUID_UPPERCASE);
+			}
+			printf(PARTITION_FMT, (uint64_t)entry->starting_lba,
+			       (uint64_t)(entry->ending_lba - entry->starting_lba + 1), i + 1,
+			       type);
+		}
+	} else { // show all partitions
+		GptEntry *entries;
+
+		if (params->debug || params->verbose) {
+			printf("Drive details:\n");
+			printf("    Total Size (bytes): %" PRIu64 "\n", drive->size);
+			printf("    LBA Size (bytes): %d\n", drive->gpt.sector_bytes);
+			if (drive->gpt.flags & GPT_FLAG_EXTERNAL) {
+				printf("    Drive (where GPT lives) Size (blocks): %" PRIu64
+				       "\n",
+				       drive->gpt.gpt_drive_sectors);
+				printf("    Drive (where partitions live) Size (blocks): "
+				       "%" PRIu64 "\n",
+				       drive->gpt.streaming_drive_sectors);
+			} else {
+				// We know gpt_drive_sectors == streaming_drive_sectors here.
+				printf("    Drive Size (blocks): %" PRIu64 "\n",
+				       drive->gpt.gpt_drive_sectors);
+			}
+			printf("\n");
+		}
+
+		if (CGPT_OK != ReadPMBR(drive)) {
+			Error("Unable to read PMBR\n");
+			return CGPT_FAILED;
+		}
+
+		printf(TITLE_FMT, "start", "size", "part", "contents");
+		char buf[256];				   // buffer for formatted PMBR content
+		PMBRToStr(&drive->pmbr, buf, sizeof(buf)); // will exit if buf is too small
+		printf(GPT_FMT, (uint64_t)0, (uint64_t)GPT_PMBR_SECTORS, "", buf);
+
+		if (drive->gpt.ignored & MASK_PRIMARY) {
+			printf(GPT_FMT, (uint64_t)GPT_PMBR_SECTORS,
+			       (uint64_t)GPT_HEADER_SECTORS, "IGNORED", "Pri GPT header");
+		} else {
+			if (drive->gpt.valid_headers & MASK_PRIMARY) {
+				printf(GPT_FMT, (uint64_t)GPT_PMBR_SECTORS,
+				       (uint64_t)GPT_HEADER_SECTORS, "", "Pri GPT header");
+			} else {
+				printf(GPT_FMT, (uint64_t)GPT_PMBR_SECTORS,
+				       (uint64_t)GPT_HEADER_SECTORS, "INVALID",
+				       "Pri GPT header");
+			}
+
+			if (params->debug ||
+			    ((drive->gpt.valid_headers & MASK_PRIMARY) && params->verbose)) {
+				GptHeader *header;
+				char indent[64];
+
+				require(snprintf(indent, sizeof(indent), GPT_MORE) <
+					sizeof(indent));
+				header = (GptHeader *)drive->gpt.primary_header;
+				entries = (GptEntry *)drive->gpt.primary_entries;
+				HeaderDetails(header, entries, indent, params->numeric);
+			}
+
+			GptHeader *primary_header = (GptHeader *)drive->gpt.primary_header;
+			printf(GPT_FMT, (uint64_t)primary_header->entries_lba,
+			       (uint64_t)CalculateEntriesSectors(primary_header,
+								 drive->gpt.sector_bytes),
+			       drive->gpt.valid_entries & MASK_PRIMARY ? "" : "INVALID",
+			       "Pri GPT table");
+
+			if (params->debug || (drive->gpt.valid_entries & MASK_PRIMARY))
+				EntriesDetails(drive, PRIMARY, params->numeric);
+		}
+
+		/****************************** Secondary *************************/
+		if (drive->gpt.ignored & MASK_SECONDARY) {
+			printf(GPT_FMT,
+			       (uint64_t)(drive->gpt.gpt_drive_sectors - GPT_HEADER_SECTORS),
+			       (uint64_t)GPT_HEADER_SECTORS, "IGNORED", "Sec GPT header");
+		} else {
+			GptHeader *secondary_header = (GptHeader *)drive->gpt.secondary_header;
+			printf(GPT_FMT, (uint64_t)secondary_header->entries_lba,
+			       (uint64_t)CalculateEntriesSectors(secondary_header,
+								 drive->gpt.sector_bytes),
+			       drive->gpt.valid_entries & MASK_SECONDARY ? "" : "INVALID",
+			       "Sec GPT table");
+			/* We show secondary table details if any of following is true.
+			 *   1. in debug mode.
+			 *   2. primary table is being ignored
+			 *   3. only secondary is valid.
+			 *   4. secondary is not identical to primary.
+			 */
+			if (params->debug || (drive->gpt.ignored & MASK_PRIMARY) ||
+			    ((drive->gpt.valid_entries & MASK_SECONDARY) &&
+			     (!(drive->gpt.valid_entries & MASK_PRIMARY) ||
+			      memcmp(drive->gpt.primary_entries, drive->gpt.secondary_entries,
+				     secondary_header->number_of_entries *
+					     secondary_header->size_of_entry)))) {
+				EntriesDetails(drive, SECONDARY, params->numeric);
+			}
+
+			if (drive->gpt.valid_headers & MASK_SECONDARY) {
+				printf(GPT_FMT,
+				       (uint64_t)(drive->gpt.gpt_drive_sectors -
+						  GPT_HEADER_SECTORS),
+				       (uint64_t)GPT_HEADER_SECTORS, "", "Sec GPT header");
+			} else {
+				printf(GPT_FMT, (uint64_t)GPT_PMBR_SECTORS,
+				       (uint64_t)GPT_HEADER_SECTORS, "INVALID",
+				       "Sec GPT header");
+			}
+			/* We show secondary header if any of following is true:
+			 *   1. in debug mode.
+			 *   2. primary table is being ignored
+			 *   3. only secondary is valid.
+			 *   4. secondary is not synonymous to primary and not ignored.
+			 */
+			if (params->debug || (drive->gpt.ignored & MASK_PRIMARY) ||
+			    ((drive->gpt.valid_headers & MASK_SECONDARY) &&
+			     (!(drive->gpt.valid_headers & MASK_PRIMARY) ||
+			      !IsSynonymous((GptHeader *)drive->gpt.primary_header,
+					    (GptHeader *)drive->gpt.secondary_header)) &&
+			     params->verbose)) {
+				GptHeader *header;
+				char indent[64];
+
+				require(snprintf(indent, sizeof(indent), GPT_MORE) <
+					sizeof(indent));
+				header = (GptHeader *)drive->gpt.secondary_header;
+				entries = (GptEntry *)drive->gpt.secondary_entries;
+				HeaderDetails(header, entries, indent, params->numeric);
+			}
+		}
+	}
+
+	CheckValid(drive);
+
+	return CGPT_OK;
 }
 
-int CgptShow(CgptShowParams *params) {
-  struct drive drive;
+int CgptShow(CgptShowParams *params)
+{
+	struct drive drive;
 
-  if (params == NULL)
-    return CGPT_FAILED;
+	if (params == NULL)
+		return CGPT_FAILED;
 
-  if (CGPT_OK != DriveOpen(params->drive_name, &drive, O_RDONLY,
-                           params->drive_size))
-    return CGPT_FAILED;
+	if (CGPT_OK != DriveOpen(params->drive_name, &drive, O_RDONLY, params->drive_size))
+		return CGPT_FAILED;
 
-  int ret = GptShow(&drive, params);
-  DriveClose(&drive, 0);
-  return ret;
+	int ret = GptShow(&drive, params);
+	DriveClose(&drive, 0);
+	return ret;
 }
diff --git a/cgpt/cgpt_wrapper.c b/cgpt/cgpt_wrapper.c
index 0fe76dd3..37c385fb 100644
--- a/cgpt/cgpt_wrapper.c
+++ b/cgpt/cgpt_wrapper.c
@@ -35,170 +35,173 @@
 
 // Check if cmdline |argv| has "-D". "-D" signifies that GPT structs are stored
 // off device, and hence we should not wrap around cgpt.
-static bool has_dash_D(int argc, const char *const argv[]) {
-  int i;
-  // We go from 2, because the second arg is a cgpt command such as "create".
-  for (i = 2; i < argc; ++i) {
-    if (strcmp("-D", argv[i]) == 0) {
-      return true;
-    }
-  }
-  return false;
+static bool has_dash_D(int argc, const char *const argv[])
+{
+	int i;
+	// We go from 2, because the second arg is a cgpt command such as "create".
+	for (i = 2; i < argc; ++i) {
+		if (strcmp("-D", argv[i]) == 0) {
+			return true;
+		}
+	}
+	return false;
 }
 
 // Check if |device_path| is an MTD device based on its major number being 90.
-static bool is_mtd(const char *device_path) {
-  struct stat stat;
-  if (lstat(device_path, &stat) != 0) {
-    return false;
-  }
+static bool is_mtd(const char *device_path)
+{
+	struct stat stat;
+	if (lstat(device_path, &stat) != 0) {
+		return false;
+	}
 
 #if !defined(__FreeBSD__)
-  if (major(stat.st_rdev) == MTD_CHAR_MAJOR) {
-    return true;
-  }
+	if (major(stat.st_rdev) == MTD_CHAR_MAJOR) {
+		return true;
+	}
 #endif
-  return false;
+	return false;
 }
 
 // Return the element in |argv| that is an MTD device.
-static const char *find_mtd_device(int argc, const char *const argv[]) {
-  int i;
-  for (i = 2; i < argc; ++i) {
-    if (is_mtd(argv[i])) {
-      return argv[i];
-    }
-  }
-  return NULL;
+static const char *find_mtd_device(int argc, const char *const argv[])
+{
+	int i;
+	for (i = 2; i < argc; ++i) {
+		if (is_mtd(argv[i])) {
+			return argv[i];
+		}
+	}
+	return NULL;
 }
 
-static int wrap_cgpt(int argc,
-                     const char *const argv[],
-                     const char *mtd_device) {
-  uint8_t original_hash[VB2_SHA1_DIGEST_SIZE];
-  uint8_t modified_hash[VB2_SHA1_DIGEST_SIZE];
-  int ret = 0;
-
-  // Create a temp dir to work in.
-  ret++;
-  char temp_dir[] = VBOOT_TMP_DIR "/cgpt_wrapper.XXXXXX";
-  if (mkdtemp(temp_dir_template) == NULL) {
-    Error("Cannot create a temporary directory.\n");
-    return ret;
-  }
-  if (ReadNorFlash(temp_dir) != 0) {
-    goto cleanup;
-  }
-  char rw_gpt_path[PATH_MAX];
-  if (snprintf(rw_gpt_path, sizeof(rw_gpt_path), "%s/rw_gpt", temp_dir) < 0) {
-    goto cleanup;
-  }
-  if (VB2_SUCCESS != DigestFile(rw_gpt_path, VB2_HASH_SHA1,
-				original_hash, sizeof(original_hash))) {
-    Error("Cannot compute original GPT digest.\n");
-    goto cleanup;
-  }
-
-  // Obtain the MTD size.
-  ret++;
-  uint64_t drive_size = 0;
-  if (GetMtdSize(mtd_device, &drive_size) != 0) {
-    Error("Cannot get the size of %s.\n", mtd_device);
-    goto cleanup;
-  }
-
-  // Launch cgpt on "rw_gpt" with -D size.
-  ret++;
-  const char** my_argv = calloc(argc + 2 + 1, sizeof(char *));
-  if (my_argv == NULL) {
-    errno = ENOMEM;
-    goto cleanup;
-  }
-  memcpy(my_argv, argv, sizeof(char *) * argc);
-  char *real_cgpt;
-  if (asprintf(&real_cgpt, "%s.bin", argv[0]) == -1) {
-    free(my_argv);
-    goto cleanup;
-  }
-  my_argv[0] = real_cgpt;
-
-  int i;
-  for (i = 2; i < argc; ++i) {
-    if (strcmp(my_argv[i], mtd_device) == 0) {
-      my_argv[i] = rw_gpt_path;
-    }
-  }
-  my_argv[argc] = "-D";
-  char size[32];
-  snprintf(size, sizeof(size), "%" PRIu64, drive_size);
-  my_argv[argc + 1] = size;
-  i = ForkExecV(NULL, my_argv);
-  free(real_cgpt);
-  free(my_argv);
-  if (i != 0) {
-    Error("Cannot exec cgpt to modify rw_gpt.\n");
-    goto cleanup;
-  }
-
-  // Write back "rw_gpt" to NOR flash in two chunks.
-  ret++;
-  if (VB2_SUCCESS == DigestFile(rw_gpt_path, VB2_HASH_SHA1,
-				modified_hash, sizeof(modified_hash))) {
-    if (memcmp(original_hash, modified_hash, VB2_SHA1_DIGEST_SIZE) != 0) {
-      ret = WriteNorFlash(temp_dir);
-    } else {
-      ret = 0;
-    }
-  }
+static int wrap_cgpt(int argc, const char *const argv[], const char *mtd_device)
+{
+	uint8_t original_hash[VB2_SHA1_DIGEST_SIZE];
+	uint8_t modified_hash[VB2_SHA1_DIGEST_SIZE];
+	int ret = 0;
+
+	// Create a temp dir to work in.
+	ret++;
+	char temp_dir[] = VBOOT_TMP_DIR "/cgpt_wrapper.XXXXXX";
+	if (mkdtemp(temp_dir_template) == NULL) {
+		Error("Cannot create a temporary directory.\n");
+		return ret;
+	}
+	if (ReadNorFlash(temp_dir) != 0) {
+		goto cleanup;
+	}
+	char rw_gpt_path[PATH_MAX];
+	if (snprintf(rw_gpt_path, sizeof(rw_gpt_path), "%s/rw_gpt", temp_dir) < 0) {
+		goto cleanup;
+	}
+	if (VB2_SUCCESS !=
+	    DigestFile(rw_gpt_path, VB2_HASH_SHA1, original_hash, sizeof(original_hash))) {
+		Error("Cannot compute original GPT digest.\n");
+		goto cleanup;
+	}
+
+	// Obtain the MTD size.
+	ret++;
+	uint64_t drive_size = 0;
+	if (GetMtdSize(mtd_device, &drive_size) != 0) {
+		Error("Cannot get the size of %s.\n", mtd_device);
+		goto cleanup;
+	}
+
+	// Launch cgpt on "rw_gpt" with -D size.
+	ret++;
+	const char **my_argv = calloc(argc + 2 + 1, sizeof(char *));
+	if (my_argv == NULL) {
+		errno = ENOMEM;
+		goto cleanup;
+	}
+	memcpy(my_argv, argv, sizeof(char *) * argc);
+	char *real_cgpt;
+	if (asprintf(&real_cgpt, "%s.bin", argv[0]) == -1) {
+		free(my_argv);
+		goto cleanup;
+	}
+	my_argv[0] = real_cgpt;
+
+	int i;
+	for (i = 2; i < argc; ++i) {
+		if (strcmp(my_argv[i], mtd_device) == 0) {
+			my_argv[i] = rw_gpt_path;
+		}
+	}
+	my_argv[argc] = "-D";
+	char size[32];
+	snprintf(size, sizeof(size), "%" PRIu64, drive_size);
+	my_argv[argc + 1] = size;
+	i = ForkExecV(NULL, my_argv);
+	free(real_cgpt);
+	free(my_argv);
+	if (i != 0) {
+		Error("Cannot exec cgpt to modify rw_gpt.\n");
+		goto cleanup;
+	}
+
+	// Write back "rw_gpt" to NOR flash in two chunks.
+	ret++;
+	if (VB2_SUCCESS ==
+	    DigestFile(rw_gpt_path, VB2_HASH_SHA1, modified_hash, sizeof(modified_hash))) {
+		if (memcmp(original_hash, modified_hash, VB2_SHA1_DIGEST_SIZE) != 0) {
+			ret = WriteNorFlash(temp_dir);
+		} else {
+			ret = 0;
+		}
+	}
 
 cleanup:
-  RemoveDir(temp_dir);
-  return ret;
+	RemoveDir(temp_dir);
+	return ret;
 }
 
-int main(int argc, const char *argv[]) {
-  char resolved_cgpt[PATH_MAX];
-  pid_t pid = getpid();
-  char exe_link[40];
-  int retval = 0;
-
-  if (argc < 1) {
-    return -1;
-  }
-
-  const char *orig_argv0 = argv[0];
-
-  snprintf(exe_link, sizeof(exe_link), "/proc/%d/exe", pid);
-  memset(resolved_cgpt, 0, sizeof(resolved_cgpt));
-  if (readlink(exe_link, resolved_cgpt, sizeof(resolved_cgpt) - 1) == -1) {
-    perror("readlink");
-    return -1;
-  }
-
-  argv[0] = resolved_cgpt;
-
-  if (argc > 2 && !has_dash_D(argc, argv)) {
-    const char *mtd_device = find_mtd_device(argc, argv);
-    if (mtd_device) {
-      retval = wrap_cgpt(argc, argv, mtd_device);
-      goto cleanup;
-    }
-  }
-
-  // Forward to cgpt as-is. Real cgpt has been renamed cgpt.bin.
-  char *real_cgpt;
-  if (asprintf(&real_cgpt, "%s.bin", argv[0]) == -1) {
-    retval = -1;
-    goto cleanup;
-  }
-  argv[0] = real_cgpt;
-  if (execv(argv[0], (char * const *)argv) == -1) {
-    err(-2, "execv(%s) failed", real_cgpt);
-  }
-  free(real_cgpt);
-  retval = -2;
+int main(int argc, const char *argv[])
+{
+	char resolved_cgpt[PATH_MAX];
+	pid_t pid = getpid();
+	char exe_link[40];
+	int retval = 0;
+
+	if (argc < 1) {
+		return -1;
+	}
+
+	const char *orig_argv0 = argv[0];
+
+	snprintf(exe_link, sizeof(exe_link), "/proc/%d/exe", pid);
+	memset(resolved_cgpt, 0, sizeof(resolved_cgpt));
+	if (readlink(exe_link, resolved_cgpt, sizeof(resolved_cgpt) - 1) == -1) {
+		perror("readlink");
+		return -1;
+	}
+
+	argv[0] = resolved_cgpt;
+
+	if (argc > 2 && !has_dash_D(argc, argv)) {
+		const char *mtd_device = find_mtd_device(argc, argv);
+		if (mtd_device) {
+			retval = wrap_cgpt(argc, argv, mtd_device);
+			goto cleanup;
+		}
+	}
+
+	// Forward to cgpt as-is. Real cgpt has been renamed cgpt.bin.
+	char *real_cgpt;
+	if (asprintf(&real_cgpt, "%s.bin", argv[0]) == -1) {
+		retval = -1;
+		goto cleanup;
+	}
+	argv[0] = real_cgpt;
+	if (execv(argv[0], (char *const *)argv) == -1) {
+		err(-2, "execv(%s) failed", real_cgpt);
+	}
+	free(real_cgpt);
+	retval = -2;
 
 cleanup:
-  argv[0] = orig_argv0;
-  return retval;
+	argv[0] = orig_argv0;
+	return retval;
 }
diff --git a/cgpt/cmd_add.c b/cgpt/cmd_add.c
index 3411925a..82f8fef4 100644
--- a/cgpt/cmd_add.c
+++ b/cgpt/cmd_add.c
@@ -9,157 +9,155 @@
 #include "cgpt.h"
 #include "vboot_host.h"
 
-extern const char* progname;
+extern const char *progname;
 
 static void Usage(void)
 {
-  printf("\nUsage: %s add [OPTIONS] DRIVE\n\n"
-         "Add, edit, or remove a partition entry.\n\n"
-         "Options:\n"
-         "  -D NUM       Size (in bytes) of the disk where partitions reside;\n"
-         "                 default 0, meaning partitions and GPT structs are\n"
-         "                 both on DRIVE\n"
-         "  -i NUM       Specify partition (default is next available)\n"
-         "  -b NUM       First block (a.k.a. start of partition)\n"
-         "  -s NUM       Size (in blocks)\n"
-         "  -t GUID      Partition Type GUID\n"
-         "  -u GUID      Partition Unique ID\n"
-         "  -l LABEL     Label\n"
-         "  -E NUM       set Error counter flag (0|1)\n"
-         "  -S NUM       set Successful flag (0|1)\n"
-         "  -T NUM       set Tries flag (0-15)\n"
-         "  -P NUM       set Priority flag (0-15)\n"
-         "  -R NUM       set Required flag (0|1)\n"
-         "  -B NUM       set Legacy Boot flag (0|1)\n"
-         "  -A NUM       set raw 16-bit attribute value (bits 48-63)\n"
-         "\n"
-         "Use the -i option to modify an existing partition.\n"
-         "The -b, -s, and -t options must be given for new partitions.\n"
-         "\n", progname);
-  PrintTypes();
+	printf("\nUsage: %s add [OPTIONS] DRIVE\n\n"
+	       "Add, edit, or remove a partition entry.\n\n"
+	       "Options:\n"
+	       "  -D NUM       Size (in bytes) of the disk where partitions reside;\n"
+	       "                 default 0, meaning partitions and GPT structs are\n"
+	       "                 both on DRIVE\n"
+	       "  -i NUM       Specify partition (default is next available)\n"
+	       "  -b NUM       First block (a.k.a. start of partition)\n"
+	       "  -s NUM       Size (in blocks)\n"
+	       "  -t GUID      Partition Type GUID\n"
+	       "  -u GUID      Partition Unique ID\n"
+	       "  -l LABEL     Label\n"
+	       "  -E NUM       set Error counter flag (0|1)\n"
+	       "  -S NUM       set Successful flag (0|1)\n"
+	       "  -T NUM       set Tries flag (0-15)\n"
+	       "  -P NUM       set Priority flag (0-15)\n"
+	       "  -R NUM       set Required flag (0|1)\n"
+	       "  -B NUM       set Legacy Boot flag (0|1)\n"
+	       "  -A NUM       set raw 16-bit attribute value (bits 48-63)\n"
+	       "\n"
+	       "Use the -i option to modify an existing partition.\n"
+	       "The -b, -s, and -t options must be given for new partitions.\n"
+	       "\n",
+	       progname);
+	PrintTypes();
 }
 
-int cmd_add(int argc, char *argv[]) {
+int cmd_add(int argc, char *argv[])
+{
 
-  CgptAddParams params;
-  memset(&params, 0, sizeof(params));
+	CgptAddParams params;
+	memset(&params, 0, sizeof(params));
 
-  int c;
-  int errorcnt = 0;
-  char *e = 0;
+	int c;
+	int errorcnt = 0;
+	char *e = 0;
 
-  opterr = 0;                     // quiet, you
-  while ((c=getopt(argc, argv, ":hi:b:s:t:u:l:E:S:T:P:R:B:A:D:")) != -1)
-  {
-    switch (c)
-    {
-    case 'D':
-      params.drive_size = strtoull(optarg, &e, 0);
-      errorcnt += check_int_parse(c, e);
-      break;
-    case 'i':
-      params.partition = (uint32_t)strtoul(optarg, &e, 0);
-      errorcnt += check_int_parse(c, e);
-      break;
-    case 'b':
-      params.set_begin = 1;
-      params.begin = strtoull(optarg, &e, 0);
-      errorcnt += check_int_parse(c, e);
-      break;
-    case 's':
-      params.set_size = 1;
-      params.size = strtoull(optarg, &e, 0);
-      errorcnt += check_int_parse(c, e);
-      break;
-    case 't':
-      params.set_type = 1;
-      if (CGPT_OK != SupportedType(optarg, &params.type_guid) &&
-          CGPT_OK != StrToGuid(optarg, &params.type_guid)) {
-        Error("invalid argument to -%c: %s\n", c, optarg);
-        errorcnt++;
-      }
-      break;
-    case 'u':
-      params.set_unique = 1;
-      if (CGPT_OK != StrToGuid(optarg, &params.unique_guid)) {
-        Error("invalid argument to -%c: %s\n", c, optarg);
-        errorcnt++;
-      }
-      break;
-    case 'l':
-      params.label = optarg;
-      break;
-    case 'E':
-      params.set_error_counter = 1;
-      params.error_counter = (uint32_t)strtoul(optarg, &e, 0);
-      errorcnt += check_int_parse(c, e);
-      errorcnt += check_int_limit(c, params.error_counter, 0, 1);
-      break;
-    case 'S':
-      params.set_successful = 1;
-      params.successful = (uint32_t)strtoul(optarg, &e, 0);
-      errorcnt += check_int_parse(c, e);
-      errorcnt += check_int_limit(c, params.successful, 0, 1);
-      break;
-    case 'T':
-      params.set_tries = 1;
-      params.tries = (uint32_t)strtoul(optarg, &e, 0);
-      errorcnt += check_int_parse(c, e);
-      errorcnt += check_int_limit(c, params.tries, 0, 15);
-      break;
-    case 'P':
-      params.set_priority = 1;
-      params.priority = (uint32_t)strtoul(optarg, &e, 0);
-      errorcnt += check_int_parse(c, e);
-      errorcnt += check_int_limit(c, params.priority, 0, 15);
-      break;
-    case 'R':
-      params.set_required = 1;
-      params.required = (uint32_t)strtoul(optarg, &e, 0);
-      errorcnt += check_int_parse(c, e);
-      errorcnt += check_int_limit(c, params.required, 0, 1);
-      break;
-    case 'B':
-      params.set_legacy_boot = 1;
-      params.legacy_boot = (uint32_t)strtoul(optarg, &e, 0);
-      errorcnt += check_int_parse(c, e);
-      errorcnt += check_int_limit(c, params.legacy_boot, 0, 1);
-      break;
-    case 'A':
-      params.set_raw = 1;
-      params.raw_value = strtoull(optarg, &e, 0);
-      errorcnt += check_int_parse(c, e);
-      break;
+	opterr = 0; // quiet, you
+	while ((c = getopt(argc, argv, ":hi:b:s:t:u:l:E:S:T:P:R:B:A:D:")) != -1) {
+		switch (c) {
+		case 'D':
+			params.drive_size = strtoull(optarg, &e, 0);
+			errorcnt += check_int_parse(c, e);
+			break;
+		case 'i':
+			params.partition = (uint32_t)strtoul(optarg, &e, 0);
+			errorcnt += check_int_parse(c, e);
+			break;
+		case 'b':
+			params.set_begin = 1;
+			params.begin = strtoull(optarg, &e, 0);
+			errorcnt += check_int_parse(c, e);
+			break;
+		case 's':
+			params.set_size = 1;
+			params.size = strtoull(optarg, &e, 0);
+			errorcnt += check_int_parse(c, e);
+			break;
+		case 't':
+			params.set_type = 1;
+			if (CGPT_OK != SupportedType(optarg, &params.type_guid) &&
+			    CGPT_OK != GptStrToGuid(optarg, &params.type_guid)) {
+				Error("invalid argument to -%c: %s\n", c, optarg);
+				errorcnt++;
+			}
+			break;
+		case 'u':
+			params.set_unique = 1;
+			if (CGPT_OK != GptStrToGuid(optarg, &params.unique_guid)) {
+				Error("invalid argument to -%c: %s\n", c, optarg);
+				errorcnt++;
+			}
+			break;
+		case 'l':
+			params.label = optarg;
+			break;
+		case 'E':
+			params.set_error_counter = 1;
+			params.error_counter = (uint32_t)strtoul(optarg, &e, 0);
+			errorcnt += check_int_parse(c, e);
+			errorcnt += check_int_limit(c, params.error_counter, 0, 1);
+			break;
+		case 'S':
+			params.set_successful = 1;
+			params.successful = (uint32_t)strtoul(optarg, &e, 0);
+			errorcnt += check_int_parse(c, e);
+			errorcnt += check_int_limit(c, params.successful, 0, 1);
+			break;
+		case 'T':
+			params.set_tries = 1;
+			params.tries = (uint32_t)strtoul(optarg, &e, 0);
+			errorcnt += check_int_parse(c, e);
+			errorcnt += check_int_limit(c, params.tries, 0, 15);
+			break;
+		case 'P':
+			params.set_priority = 1;
+			params.priority = (uint32_t)strtoul(optarg, &e, 0);
+			errorcnt += check_int_parse(c, e);
+			errorcnt += check_int_limit(c, params.priority, 0, 15);
+			break;
+		case 'R':
+			params.set_required = 1;
+			params.required = (uint32_t)strtoul(optarg, &e, 0);
+			errorcnt += check_int_parse(c, e);
+			errorcnt += check_int_limit(c, params.required, 0, 1);
+			break;
+		case 'B':
+			params.set_legacy_boot = 1;
+			params.legacy_boot = (uint32_t)strtoul(optarg, &e, 0);
+			errorcnt += check_int_parse(c, e);
+			errorcnt += check_int_limit(c, params.legacy_boot, 0, 1);
+			break;
+		case 'A':
+			params.set_raw = 1;
+			params.raw_value = strtoull(optarg, &e, 0);
+			errorcnt += check_int_parse(c, e);
+			break;
 
-    case 'h':
-      Usage();
-      return CGPT_OK;
-    case '?':
-      Error("unrecognized option: -%c\n", optopt);
-      errorcnt++;
-      break;
-    case ':':
-      Error("missing argument to -%c\n", optopt);
-      errorcnt++;
-      break;
-    default:
-      errorcnt++;
-      break;
-    }
-  }
-  if (errorcnt)
-  {
-    Usage();
-    return CGPT_FAILED;
-  }
+		case 'h':
+			Usage();
+			return CGPT_OK;
+		case '?':
+			Error("unrecognized option: -%c\n", optopt);
+			errorcnt++;
+			break;
+		case ':':
+			Error("missing argument to -%c\n", optopt);
+			errorcnt++;
+			break;
+		default:
+			errorcnt++;
+			break;
+		}
+	}
+	if (errorcnt) {
+		Usage();
+		return CGPT_FAILED;
+	}
 
-  if (optind >= argc)
-  {
-    Error("missing drive argument\n");
-    return CGPT_FAILED;
-  }
+	if (optind >= argc) {
+		Error("missing drive argument\n");
+		return CGPT_FAILED;
+	}
 
-  params.drive_name = argv[optind];
+	params.drive_name = argv[optind];
 
-  return CgptAdd(&params);
+	return CgptAdd(&params);
 }
diff --git a/cgpt/cmd_boot.c b/cgpt/cmd_boot.c
index 98eeab3a..34b61582 100644
--- a/cgpt/cmd_boot.c
+++ b/cgpt/cmd_boot.c
@@ -9,82 +9,79 @@
 #include "cgpt.h"
 #include "vboot_host.h"
 
-extern const char* progname;
+extern const char *progname;
 
 static void Usage(void)
 {
-  printf("\nUsage: %s boot [OPTIONS] DRIVE\n\n"
-         "Edit the PMBR sector for legacy BIOSes\n\n"
-         "Options:\n"
-         "  -D NUM       Size (in bytes) of the disk where partitions reside;\n"
-         "                 default 0, meaning partitions and GPT structs are\n"
-         "                 both on DRIVE\n"
-         "  -i NUM       Set bootable partition\n"
-         "  -b FILE      Install bootloader code in the PMBR\n"
-         "  -p           Create legacy PMBR partition table\n"
-         "\n"
-         "With no options, it will just print the PMBR boot guid\n"
-         "\n", progname);
+	printf("\nUsage: %s boot [OPTIONS] DRIVE\n\n"
+	       "Edit the PMBR sector for legacy BIOSes\n\n"
+	       "Options:\n"
+	       "  -D NUM       Size (in bytes) of the disk where partitions reside;\n"
+	       "                 default 0, meaning partitions and GPT structs are\n"
+	       "                 both on DRIVE\n"
+	       "  -i NUM       Set bootable partition\n"
+	       "  -b FILE      Install bootloader code in the PMBR\n"
+	       "  -p           Create legacy PMBR partition table\n"
+	       "\n"
+	       "With no options, it will just print the PMBR boot guid\n"
+	       "\n",
+	       progname);
 }
 
+int cmd_boot(int argc, char *argv[])
+{
+	CgptBootParams params;
+	memset(&params, 0, sizeof(params));
 
-int cmd_boot(int argc, char *argv[]) {
-  CgptBootParams params;
-  memset(&params, 0, sizeof(params));
-
-
-  int c;
-  int errorcnt = 0;
-  char *e = 0;
+	int c;
+	int errorcnt = 0;
+	char *e = 0;
 
-  opterr = 0;                     // quiet, you
-  while ((c=getopt(argc, argv, ":hi:b:pD:")) != -1)
-  {
-    switch (c)
-    {
-    case 'D':
-      params.drive_size = strtoull(optarg, &e, 0);
-      errorcnt += check_int_parse(c, e);
-      break;
-    case 'i':
-      params.partition = (uint32_t)strtoul(optarg, &e, 0);
-      errorcnt += check_int_parse(c, e);
-      break;
-    case 'b':
-      params.bootfile = optarg;
-      break;
-    case 'p':
-      params.create_pmbr = 1;
-      break;
+	opterr = 0; // quiet, you
+	while ((c = getopt(argc, argv, ":hi:b:pD:")) != -1) {
+		switch (c) {
+		case 'D':
+			params.drive_size = strtoull(optarg, &e, 0);
+			errorcnt += check_int_parse(c, e);
+			break;
+		case 'i':
+			params.partition = (uint32_t)strtoul(optarg, &e, 0);
+			errorcnt += check_int_parse(c, e);
+			break;
+		case 'b':
+			params.bootfile = optarg;
+			break;
+		case 'p':
+			params.create_pmbr = 1;
+			break;
 
-    case 'h':
-      Usage();
-      return CGPT_OK;
-    case '?':
-      Error("unrecognized option: -%c\n", optopt);
-      errorcnt++;
-      break;
-    case ':':
-      Error("missing argument to -%c\n", optopt);
-      errorcnt++;
-      break;
-    default:
-      errorcnt++;
-      break;
-    }
-  }
-  if (errorcnt)
-  {
-    Usage();
-    return CGPT_FAILED;
-  }
+		case 'h':
+			Usage();
+			return CGPT_OK;
+		case '?':
+			Error("unrecognized option: -%c\n", optopt);
+			errorcnt++;
+			break;
+		case ':':
+			Error("missing argument to -%c\n", optopt);
+			errorcnt++;
+			break;
+		default:
+			errorcnt++;
+			break;
+		}
+	}
+	if (errorcnt) {
+		Usage();
+		return CGPT_FAILED;
+	}
 
-  if (optind >= argc) {
-    Error("missing drive argument\n");
-    return CGPT_FAILED;
-  }
+	if (optind >= argc) {
+		Error("missing drive argument\n");
+		return CGPT_FAILED;
+	}
 
-  params.drive_name = argv[optind];
+	params.drive_name = argv[optind];
 
-  return CgptBoot(&params);
+	return CgptBoot(&params);
 }
diff --git a/cgpt/cmd_create.c b/cgpt/cmd_create.c
index f2d93c4e..10c222ae 100644
--- a/cgpt/cmd_create.c
+++ b/cgpt/cmd_create.c
@@ -9,74 +9,73 @@
 #include "cgpt.h"
 #include "vboot_host.h"
 
-extern const char* progname;
+extern const char *progname;
 
 static void Usage(void)
 {
-  printf("\nUsage: %s create [OPTIONS] DRIVE\n\n"
-         "Create or reset an empty GPT.\n\n"
-         "Options:\n"
-         "  -D NUM       Size (in bytes) of the disk where partitions reside;\n"
-         "                 default 0, meaning partitions and GPT structs are\n"
-         "                 both on DRIVE\n"
-         "  -z           Zero the blocks of the GPT table and entries\n"
-         "  -p NUM       Size (in blocks) of the disk to pad between the\n"
-         "                 primary GPT header and its entries, default 0\n"
-         "\n", progname);
+	printf("\nUsage: %s create [OPTIONS] DRIVE\n\n"
+	       "Create or reset an empty GPT.\n\n"
+	       "Options:\n"
+	       "  -D NUM       Size (in bytes) of the disk where partitions reside;\n"
+	       "                 default 0, meaning partitions and GPT structs are\n"
+	       "                 both on DRIVE\n"
+	       "  -z           Zero the blocks of the GPT table and entries\n"
+	       "  -p NUM       Size (in blocks) of the disk to pad between the\n"
+	       "                 primary GPT header and its entries, default 0\n"
+	       "\n",
+	       progname);
 }
 
-int cmd_create(int argc, char *argv[]) {
-  CgptCreateParams params;
-  memset(&params, 0, sizeof(params));
+int cmd_create(int argc, char *argv[])
+{
+	CgptCreateParams params;
+	memset(&params, 0, sizeof(params));
 
-  int c;
-  int errorcnt = 0;
-  char *e = 0;
+	int c;
+	int errorcnt = 0;
+	char *e = 0;
 
-  opterr = 0;                     // quiet, you
-  while ((c=getopt(argc, argv, ":hzp:D:")) != -1)
-  {
-    switch (c)
-    {
-    case 'D':
-      params.drive_size = strtoull(optarg, &e, 0);
-      errorcnt += check_int_parse(c, e);
-      break;
-    case 'z':
-      params.zap = 1;
-      break;
-    case 'p':
-      params.padding = strtoull(optarg, &e, 0);
-      errorcnt += check_int_parse(c, e);
-      break;
-    case 'h':
-      Usage();
-      return CGPT_OK;
-    case '?':
-      Error("unrecognized option: -%c\n", optopt);
-      errorcnt++;
-      break;
-    case ':':
-      Error("missing argument to -%c\n", optopt);
-      errorcnt++;
-      break;
-    default:
-      errorcnt++;
-      break;
-    }
-  }
-  if (errorcnt)
-  {
-    Usage();
-    return CGPT_FAILED;
-  }
+	opterr = 0; // quiet, you
+	while ((c = getopt(argc, argv, ":hzp:D:")) != -1) {
+		switch (c) {
+		case 'D':
+			params.drive_size = strtoull(optarg, &e, 0);
+			errorcnt += check_int_parse(c, e);
+			break;
+		case 'z':
+			params.zap = 1;
+			break;
+		case 'p':
+			params.padding = strtoull(optarg, &e, 0);
+			errorcnt += check_int_parse(c, e);
+			break;
+		case 'h':
+			Usage();
+			return CGPT_OK;
+		case '?':
+			Error("unrecognized option: -%c\n", optopt);
+			errorcnt++;
+			break;
+		case ':':
+			Error("missing argument to -%c\n", optopt);
+			errorcnt++;
+			break;
+		default:
+			errorcnt++;
+			break;
+		}
+	}
+	if (errorcnt) {
+		Usage();
+		return CGPT_FAILED;
+	}
 
-  if (optind >= argc) {
-    Usage();
-    return CGPT_FAILED;
-  }
+	if (optind >= argc) {
+		Usage();
+		return CGPT_FAILED;
+	}
 
-  params.drive_name = argv[optind];
+	params.drive_name = argv[optind];
 
-  return CgptCreate(&params);
+	return CgptCreate(&params);
 }
diff --git a/cgpt/cmd_edit.c b/cgpt/cmd_edit.c
index 11087b58..6dac5e01 100644
--- a/cgpt/cmd_edit.c
+++ b/cgpt/cmd_edit.c
@@ -8,80 +8,77 @@
 #include "cgpt.h"
 #include "vboot_host.h"
 
-extern const char* progname;
+extern const char *progname;
 
 static void Usage(void)
 {
-  printf("\nUsage: %s edit [OPTIONS] DRIVE\n\n"
-         "Edit a drive's parameters.\n\n"
-         "Options:\n"
-         "  -D NUM       Size (in bytes) of the disk where partitions reside;\n"
-         "                 default 0, meaning partitions and GPT structs are\n"
-         "                 both on DRIVE\n"
-         "  -u GUID      Drive Unique ID\n"
-         "\n", progname);
+	printf("\nUsage: %s edit [OPTIONS] DRIVE\n\n"
+	       "Edit a drive's parameters.\n\n"
+	       "Options:\n"
+	       "  -D NUM       Size (in bytes) of the disk where partitions reside;\n"
+	       "                 default 0, meaning partitions and GPT structs are\n"
+	       "                 both on DRIVE\n"
+	       "  -u GUID      Drive Unique ID\n"
+	       "\n",
+	       progname);
 }
 
-int cmd_edit(int argc, char *argv[]) {
+int cmd_edit(int argc, char *argv[])
+{
 
-  CgptEditParams params;
-  memset(&params, 0, sizeof(params));
+	CgptEditParams params;
+	memset(&params, 0, sizeof(params));
 
-  int c;
-  int errorcnt = 0;
-  char *e = 0;
+	int c;
+	int errorcnt = 0;
+	char *e = 0;
 
-  opterr = 0;                     // quiet, you
-  while ((c=getopt(argc, argv, ":hu:D:")) != -1)
-  {
-    switch (c)
-    {
-    case 'D':
-      params.drive_size = strtoull(optarg, &e, 0);
-      errorcnt += check_int_parse(c, e);
-      break;
-    case 'u':
-      params.set_unique = 1;
-      if (CGPT_OK != StrToGuid(optarg, &params.unique_guid)) {
-        Error("invalid argument to -%c: %s\n", c, optarg);
-        errorcnt++;
-      }
-      break;
-    case 'h':
-      Usage();
-      return CGPT_OK;
-    case '?':
-      Error("unrecognized option: -%c\n", optopt);
-      errorcnt++;
-      break;
-    case ':':
-      Error("missing argument to -%c\n", optopt);
-      errorcnt++;
-      break;
-    default:
-      errorcnt++;
-      break;
-    }
-  }
-  if (errorcnt)
-  {
-    Usage();
-    return CGPT_FAILED;
-  }
+	opterr = 0; // quiet, you
+	while ((c = getopt(argc, argv, ":hu:D:")) != -1) {
+		switch (c) {
+		case 'D':
+			params.drive_size = strtoull(optarg, &e, 0);
+			errorcnt += check_int_parse(c, e);
+			break;
+		case 'u':
+			params.set_unique = 1;
+			if (CGPT_OK != GptStrToGuid(optarg, &params.unique_guid)) {
+				Error("invalid argument to -%c: %s\n", c, optarg);
+				errorcnt++;
+			}
+			break;
+		case 'h':
+			Usage();
+			return CGPT_OK;
+		case '?':
+			Error("unrecognized option: -%c\n", optopt);
+			errorcnt++;
+			break;
+		case ':':
+			Error("missing argument to -%c\n", optopt);
+			errorcnt++;
+			break;
+		default:
+			errorcnt++;
+			break;
+		}
+	}
+	if (errorcnt) {
+		Usage();
+		return CGPT_FAILED;
+	}
 
-  if (optind >= argc)
-  {
-    Error("missing drive argument\n");
-    return CGPT_FAILED;
-  }
+	if (optind >= argc) {
+		Error("missing drive argument\n");
+		return CGPT_FAILED;
+	}
 
-  params.drive_name = argv[optind];
+	params.drive_name = argv[optind];
 
-  if (!params.set_unique)
-  {
-    Error("no parameters were edited\n");
-    return CGPT_FAILED;
-  }
+	if (!params.set_unique) {
+		Error("no parameters were edited\n");
+		return CGPT_FAILED;
+	}
 
-  return CgptEdit(&params);
+	return CgptEdit(&params);
 }
diff --git a/cgpt/cmd_find.c b/cgpt/cmd_find.c
index 0c927559..e2ff1c76 100644
--- a/cgpt/cmd_find.c
+++ b/cgpt/cmd_find.c
@@ -9,175 +9,176 @@
 #include "cgpt.h"
 #include "vboot_host.h"
 
-extern const char* progname;
+extern const char *progname;
 
 static void Usage(void)
 {
-  printf("\nUsage: %s find [OPTIONS] [DRIVE]\n\n"
-         "Find a partition by its UUID or label. With no specified DRIVE\n"
-         "it scans all physical drives.\n\n"
-         "Options:\n"
-         "  -D NUM       Size (in bytes) of the disk where partitions reside;\n"
-         "                 default 0, meaning partitions and GPT structs are\n"
-         "                 both on DRIVE\n"
-         "  -t GUID      Search for Partition Type GUID\n"
-         "  -u GUID      Search for Partition Unique ID\n"
-         "  -l LABEL     Search for Label\n"
-         "  -v           Be verbose in displaying matches (repeatable)\n"
-         "  -n           Numeric output only\n"
-         "  -1           Fail if more than one match is found\n"
-         "  -M FILE"
-         "      Matching partition data must also contain FILE content\n"
-         "  -O NUM"
-         "       Byte offset into partition to match content (default 0)\n"
-         "\n", progname);
-  PrintTypes();
+	printf("\nUsage: %s find [OPTIONS] [DRIVE]\n\n"
+	       "Find a partition by its UUID or label. With no specified DRIVE\n"
+	       "it scans all physical drives.\n\n"
+	       "Options:\n"
+	       "  -D NUM       Size (in bytes) of the disk where partitions reside;\n"
+	       "                 default 0, meaning partitions and GPT structs are\n"
+	       "                 both on DRIVE\n"
+	       "  -t GUID      Search for Partition Type GUID\n"
+	       "  -u GUID      Search for Partition Unique ID\n"
+	       "  -l LABEL     Search for Label\n"
+	       "  -v           Be verbose in displaying matches (repeatable)\n"
+	       "  -n           Numeric output only\n"
+	       "  -1           Fail if more than one match is found\n"
+	       "  -M FILE"
+	       "      Matching partition data must also contain FILE content\n"
+	       "  -O NUM"
+	       "       Byte offset into partition to match content (default 0)\n"
+	       "\n",
+	       progname);
+	PrintTypes();
 }
 
 // read a file into a buffer, return buffer and update size
-static uint8_t *ReadFile(const char *filename, uint64_t *size) {
-  FILE *f;
-  uint8_t *buf;
-  long pos;
-
-  f = fopen(filename, "rb");
-  if (!f) {
-    return NULL;
-  }
-
-  fseek(f, 0, SEEK_END);
-  pos = ftell(f);
-  if (pos < 0) {
-    fclose(f);
-    return NULL;
-  }
-  *size = pos;
-  rewind(f);
-
-  buf = malloc(*size);
-  if (!buf) {
-    fclose(f);
-    return NULL;
-  }
-
-  if (1 != fread(buf, *size, 1, f)) {
-    fclose(f);
-    free(buf);
-    return NULL;
-  }
-
-  fclose(f);
-  return buf;
+static uint8_t *ReadFile(const char *filename, uint64_t *size)
+{
+	FILE *f;
+	uint8_t *buf;
+	long pos;
+
+	f = fopen(filename, "rb");
+	if (!f) {
+		return NULL;
+	}
+
+	fseek(f, 0, SEEK_END);
+	pos = ftell(f);
+	if (pos < 0) {
+		fclose(f);
+		return NULL;
+	}
+	*size = pos;
+	rewind(f);
+
+	buf = malloc(*size);
+	if (!buf) {
+		fclose(f);
+		return NULL;
+	}
+
+	if (1 != fread(buf, *size, 1, f)) {
+		fclose(f);
+		free(buf);
+		return NULL;
+	}
+
+	fclose(f);
+	return buf;
 }
 
-int cmd_find(int argc, char *argv[]) {
-
-  CgptFindParams params;
-  memset(&params, 0, sizeof(params));
-
-  int i;
-  int errorcnt = 0;
-  char *e = 0;
-  int c;
-
-  opterr = 0;                     // quiet, you
-  while ((c=getopt(argc, argv, ":hv1nt:u:l:M:O:D:")) != -1)
-  {
-    switch (c)
-    {
-    case 'D':
-      params.drive_size = strtoull(optarg, &e, 0);
-      errorcnt += check_int_parse(c, e);
-      break;
-    case 'v':
-      params.verbose++;
-      break;
-    case 'n':
-      params.numeric = 1;
-      break;
-    case '1':
-      params.oneonly = 1;
-      break;
-    case 'l':
-      params.set_label = 1;
-      params.label = optarg;
-      break;
-    case 't':
-      params.set_type = 1;
-      if (CGPT_OK != SupportedType(optarg, &params.type_guid) &&
-          CGPT_OK != StrToGuid(optarg, &params.type_guid)) {
-        Error("invalid argument to -%c: %s\n", c, optarg);
-        errorcnt++;
-      }
-      break;
-    case 'u':
-      params.set_unique = 1;
-      if (CGPT_OK != StrToGuid(optarg, &params.unique_guid)) {
-        Error("invalid argument to -%c: %s\n", c, optarg);
-        errorcnt++;
-      }
-      break;
-    case 'M':
-      params.matchbuf = ReadFile(optarg, &params.matchlen);
-      if (!params.matchbuf || !params.matchlen) {
-        Error("Unable to read from %s\n", optarg);
-        errorcnt++;
-      }
-      // Go ahead and allocate space for the comparison too
-      params.comparebuf = (uint8_t *)malloc(params.matchlen);
-      if (!params.comparebuf) {
-        Error("Unable to allocate %" PRIu64 "bytes for comparison buffer\n",
-              params.matchlen);
-        errorcnt++;
-      }
-      break;
-    case 'O':
-      params.matchoffset = strtoull(optarg, &e, 0);
-      errorcnt += check_int_parse(c, e);
-      break;
-
-    case 'h':
-      Usage();
-      return CGPT_OK;
-    case '?':
-      Error("unrecognized option: -%c\n", optopt);
-      errorcnt++;
-      break;
-    case ':':
-      Error("missing argument to -%c\n", optopt);
-      errorcnt++;
-      break;
-    default:
-      errorcnt++;
-      break;
-    }
-  }
-  if (!params.set_unique && !params.set_type && !params.set_label) {
-    Error("You must specify at least one of -t, -u, or -l\n");
-    errorcnt++;
-  }
-  if (errorcnt)
-  {
-    Usage();
-    return CGPT_FAILED;
-  }
-
-  if (optind < argc) {
-    for (i=optind; i<argc; i++) {
-      params.drive_name = argv[i];
-      CgptFind(&params);
-      }
-  } else {
-      CgptFind(&params);
-  }
-
-  if (params.oneonly && params.hits != 1) {
-    return CGPT_FAILED;
-  }
-
-  if (params.match_partnum) {
-    return CGPT_OK;
-  }
-
-  return CGPT_FAILED;
+int cmd_find(int argc, char *argv[])
+{
+
+	CgptFindParams params;
+	memset(&params, 0, sizeof(params));
+
+	int i;
+	int errorcnt = 0;
+	char *e = 0;
+	int c;
+
+	opterr = 0; // quiet, you
+	while ((c = getopt(argc, argv, ":hv1nt:u:l:M:O:D:")) != -1) {
+		switch (c) {
+		case 'D':
+			params.drive_size = strtoull(optarg, &e, 0);
+			errorcnt += check_int_parse(c, e);
+			break;
+		case 'v':
+			params.verbose++;
+			break;
+		case 'n':
+			params.numeric = 1;
+			break;
+		case '1':
+			params.oneonly = 1;
+			break;
+		case 'l':
+			params.set_label = 1;
+			params.label = optarg;
+			break;
+		case 't':
+			params.set_type = 1;
+			if (CGPT_OK != SupportedType(optarg, &params.type_guid) &&
+			    CGPT_OK != GptStrToGuid(optarg, &params.type_guid)) {
+				Error("invalid argument to -%c: %s\n", c, optarg);
+				errorcnt++;
+			}
+			break;
+		case 'u':
+			params.set_unique = 1;
+			if (CGPT_OK != GptStrToGuid(optarg, &params.unique_guid)) {
+				Error("invalid argument to -%c: %s\n", c, optarg);
+				errorcnt++;
+			}
+			break;
+		case 'M':
+			params.matchbuf = ReadFile(optarg, &params.matchlen);
+			if (!params.matchbuf || !params.matchlen) {
+				Error("Unable to read from %s\n", optarg);
+				errorcnt++;
+			}
+			// Go ahead and allocate space for the comparison too
+			params.comparebuf = (uint8_t *)malloc(params.matchlen);
+			if (!params.comparebuf) {
+				Error("Unable to allocate %" PRIu64
+				      "bytes for comparison buffer\n",
+				      params.matchlen);
+				errorcnt++;
+			}
+			break;
+		case 'O':
+			params.matchoffset = strtoull(optarg, &e, 0);
+			errorcnt += check_int_parse(c, e);
+			break;
+
+		case 'h':
+			Usage();
+			return CGPT_OK;
+		case '?':
+			Error("unrecognized option: -%c\n", optopt);
+			errorcnt++;
+			break;
+		case ':':
+			Error("missing argument to -%c\n", optopt);
+			errorcnt++;
+			break;
+		default:
+			errorcnt++;
+			break;
+		}
+	}
+	if (!params.set_unique && !params.set_type && !params.set_label) {
+		Error("You must specify at least one of -t, -u, or -l\n");
+		errorcnt++;
+	}
+	if (errorcnt) {
+		Usage();
+		return CGPT_FAILED;
+	}
+
+	if (optind < argc) {
+		for (i = optind; i < argc; i++) {
+			params.drive_name = argv[i];
+			CgptFind(&params);
+		}
+	} else {
+		CgptFind(&params);
+	}
+
+	if (params.oneonly && params.hits != 1) {
+		return CGPT_FAILED;
+	}
+
+	if (params.match_partnum) {
+		return CGPT_OK;
+	}
+
+	return CGPT_FAILED;
 }
diff --git a/cgpt/cmd_legacy.c b/cgpt/cmd_legacy.c
index e3b64567..a20e2ff4 100644
--- a/cgpt/cmd_legacy.c
+++ b/cgpt/cmd_legacy.c
@@ -9,80 +9,79 @@
 #include "cgpt.h"
 #include "vboot_host.h"
 
-extern const char* progname;
+extern const char *progname;
 
 static void Usage(void)
 {
-  printf("\nUsage: %s legacy [OPTIONS] DRIVE\n\n"
-         "Switch GPT header signature to \"CHROMEOS\".\n\n"
-         "Options:\n"
-         "  -D NUM       Size (in bytes) of the disk where partitions reside;\n"
-         "                 default 0, meaning partitions and GPT structs are\n"
-         "                 both on DRIVE\n"
-         "  -e           Switch GPT header signature back to \"EFI PART\"\n"
-         "  -p           Switch primary GPT header signature to \"IGNOREME\"\n"
-         "\n", progname);
+	printf("\nUsage: %s legacy [OPTIONS] DRIVE\n\n"
+	       "Switch GPT header signature to \"CHROMEOS\".\n\n"
+	       "Options:\n"
+	       "  -D NUM       Size (in bytes) of the disk where partitions reside;\n"
+	       "                 default 0, meaning partitions and GPT structs are\n"
+	       "                 both on DRIVE\n"
+	       "  -e           Switch GPT header signature back to \"EFI PART\"\n"
+	       "  -p           Switch primary GPT header signature to \"IGNOREME\"\n"
+	       "\n",
+	       progname);
 }
 
-int cmd_legacy(int argc, char *argv[]) {
-  CgptLegacyParams params;
-  memset(&params, 0, sizeof(params));
+int cmd_legacy(int argc, char *argv[])
+{
+	CgptLegacyParams params;
+	memset(&params, 0, sizeof(params));
 
-  int c;
-  char* e = 0;
-  int errorcnt = 0;
+	int c;
+	char *e = 0;
+	int errorcnt = 0;
 
-  opterr = 0;                     // quiet, you
-  while ((c=getopt(argc, argv, ":hepD:")) != -1)
-  {
-    switch (c)
-    {
-    case 'D':
-      params.drive_size = strtoull(optarg, &e, 0);
-      errorcnt += check_int_parse(c, e);
-      break;
-    case 'e':
-      if (params.mode) {
-        Error("Incompatible flags, pick either -e or -p\n");
-        errorcnt++;
-      }
-      params.mode = CGPT_LEGACY_MODE_EFIPART;
-      break;
-    case 'p':
-      if (params.mode) {
-        Error("Incompatible flags, pick either -e or -p\n");
-        errorcnt++;
-      }
-      params.mode = CGPT_LEGACY_MODE_IGNORE_PRIMARY;
-      break;
-    case 'h':
-      Usage();
-      return CGPT_OK;
-    case '?':
-      Error("unrecognized option: -%c\n", optopt);
-      errorcnt++;
-      break;
-    case ':':
-      Error("missing argument to -%c\n", optopt);
-      errorcnt++;
-      break;
-    default:
-      errorcnt++;
-      break;
-    }
-  }
-  if (errorcnt)
-  {
-    Usage();
-    return CGPT_FAILED;
-  }
+	opterr = 0; // quiet, you
+	while ((c = getopt(argc, argv, ":hepD:")) != -1) {
+		switch (c) {
+		case 'D':
+			params.drive_size = strtoull(optarg, &e, 0);
+			errorcnt += check_int_parse(c, e);
+			break;
+		case 'e':
+			if (params.mode) {
+				Error("Incompatible flags, pick either -e or -p\n");
+				errorcnt++;
+			}
+			params.mode = CGPT_LEGACY_MODE_EFIPART;
+			break;
+		case 'p':
+			if (params.mode) {
+				Error("Incompatible flags, pick either -e or -p\n");
+				errorcnt++;
+			}
+			params.mode = CGPT_LEGACY_MODE_IGNORE_PRIMARY;
+			break;
+		case 'h':
+			Usage();
+			return CGPT_OK;
+		case '?':
+			Error("unrecognized option: -%c\n", optopt);
+			errorcnt++;
+			break;
+		case ':':
+			Error("missing argument to -%c\n", optopt);
+			errorcnt++;
+			break;
+		default:
+			errorcnt++;
+			break;
+		}
+	}
+	if (errorcnt) {
+		Usage();
+		return CGPT_FAILED;
+	}
 
-  if (optind >= argc) {
-    Usage();
-    return CGPT_FAILED;
-  }
+	if (optind >= argc) {
+		Usage();
+		return CGPT_FAILED;
+	}
 
-  params.drive_name = argv[optind];
+	params.drive_name = argv[optind];
 
-  return CgptLegacy(&params);
+	return CgptLegacy(&params);
 }
diff --git a/cgpt/cmd_prioritize.c b/cgpt/cmd_prioritize.c
index 6d8b7070..7d98f28d 100644
--- a/cgpt/cmd_prioritize.c
+++ b/cgpt/cmd_prioritize.c
@@ -12,96 +12,95 @@
 #include "cgpt.h"
 #include "vboot_host.h"
 
-extern const char* progname;
+extern const char *progname;
 
 static void Usage(void)
 {
-  printf("\nUsage: %s prioritize [OPTIONS] DRIVE\n\n"
-         "Reorder the priority of all active ChromeOS Kernel partitions.\n\n"
-         "Options:\n"
-         "  -D NUM       Size (in bytes) of the disk where partitions reside;\n"
-         "                 default 0, meaning partitions and GPT structs are\n"
-         "                 both on DRIVE\n"
-         "  -P NUM       Highest priority to use in the new ordering. The\n"
-         "                 other partitions will be ranked in decreasing\n"
-         "                 priority while preserving their original order.\n"
-         "                 If necessary the lowest ranks will be coalesced.\n"
-         "                 No active kernels will be lowered to priority 0.\n"
-         "  -i NUM       Specify the partition to make the highest in the new\n"
-         "                 order.\n"
-         "  -f           Friends of the given partition (those with the same\n"
-         "                 starting priority) are also updated to the new\n"
-         "                 highest priority.\n"
-         "\n"
-         "With no options this will set the lowest active kernel to\n"
-         "priority 1 while maintaining the original order.\n"
-         "\n", progname);
+	printf("\nUsage: %s prioritize [OPTIONS] DRIVE\n\n"
+	       "Reorder the priority of all active ChromeOS Kernel partitions.\n\n"
+	       "Options:\n"
+	       "  -D NUM       Size (in bytes) of the disk where partitions reside;\n"
+	       "                 default 0, meaning partitions and GPT structs are\n"
+	       "                 both on DRIVE\n"
+	       "  -P NUM       Highest priority to use in the new ordering. The\n"
+	       "                 other partitions will be ranked in decreasing\n"
+	       "                 priority while preserving their original order.\n"
+	       "                 If necessary the lowest ranks will be coalesced.\n"
+	       "                 No active kernels will be lowered to priority 0.\n"
+	       "  -i NUM       Specify the partition to make the highest in the new\n"
+	       "                 order.\n"
+	       "  -f           Friends of the given partition (those with the same\n"
+	       "                 starting priority) are also updated to the new\n"
+	       "                 highest priority.\n"
+	       "\n"
+	       "With no options this will set the lowest active kernel to\n"
+	       "priority 1 while maintaining the original order.\n"
+	       "\n",
+	       progname);
 }
 
-int cmd_prioritize(int argc, char *argv[]) {
-  CgptPrioritizeParams params;
-  memset(&params, 0, sizeof(params));
+int cmd_prioritize(int argc, char *argv[])
+{
+	CgptPrioritizeParams params;
+	memset(&params, 0, sizeof(params));
 
-  int c;
-  int errorcnt = 0;
-  char *e = 0;
+	int c;
+	int errorcnt = 0;
+	char *e = 0;
 
-  opterr = 0;                     // quiet, you
-  while ((c=getopt(argc, argv, ":hi:fP:D:")) != -1)
-  {
-    switch (c)
-    {
-    case 'D':
-      params.drive_size = strtoull(optarg, &e, 0);
-      errorcnt += check_int_parse(c, e);
-      break;
-    case 'i':
-      params.set_partition = (uint32_t)strtoul(optarg, &e, 0);
-      errorcnt += check_int_parse(c, e);
-      break;
-    case 'f':
-      params.set_friends = 1;
-      break;
-    case 'P':
-      params.max_priority = (int)strtol(optarg, &e, 0);
-      errorcnt += check_int_parse(c, e);
-      errorcnt += check_int_limit(c, params.max_priority, 1, 15);
-      break;
+	opterr = 0; // quiet, you
+	while ((c = getopt(argc, argv, ":hi:fP:D:")) != -1) {
+		switch (c) {
+		case 'D':
+			params.drive_size = strtoull(optarg, &e, 0);
+			errorcnt += check_int_parse(c, e);
+			break;
+		case 'i':
+			params.set_partition = (uint32_t)strtoul(optarg, &e, 0);
+			errorcnt += check_int_parse(c, e);
+			break;
+		case 'f':
+			params.set_friends = 1;
+			break;
+		case 'P':
+			params.max_priority = (int)strtol(optarg, &e, 0);
+			errorcnt += check_int_parse(c, e);
+			errorcnt += check_int_limit(c, params.max_priority, 1, 15);
+			break;
 
-    case 'h':
-      Usage();
-      return CGPT_OK;
-    case '?':
-      Error("unrecognized option: -%c\n", optopt);
-      errorcnt++;
-      break;
-    case ':':
-      Error("missing argument to -%c\n", optopt);
-      errorcnt++;
-      break;
-    default:
-      errorcnt++;
-      break;
-    }
-  }
-  if (errorcnt)
-  {
-    Usage();
-    return CGPT_FAILED;
-  }
+		case 'h':
+			Usage();
+			return CGPT_OK;
+		case '?':
+			Error("unrecognized option: -%c\n", optopt);
+			errorcnt++;
+			break;
+		case ':':
+			Error("missing argument to -%c\n", optopt);
+			errorcnt++;
+			break;
+		default:
+			errorcnt++;
+			break;
+		}
+	}
+	if (errorcnt) {
+		Usage();
+		return CGPT_FAILED;
+	}
 
-  if (params.set_friends && !params.set_partition) {
-    Error("the -f option is only useful with the -i option\n");
-    Usage();
-    return CGPT_FAILED;
-  }
+	if (params.set_friends && !params.set_partition) {
+		Error("the -f option is only useful with the -i option\n");
+		Usage();
+		return CGPT_FAILED;
+	}
 
-  if (optind >= argc) {
-    Error("missing drive argument\n");
-    return CGPT_FAILED;
-  }
+	if (optind >= argc) {
+		Error("missing drive argument\n");
+		return CGPT_FAILED;
+	}
 
-  params.drive_name = argv[optind];
+	params.drive_name = argv[optind];
 
-  return CgptPrioritize(&params);
+	return CgptPrioritize(&params);
 }
diff --git a/cgpt/cmd_repair.c b/cgpt/cmd_repair.c
index 889bb9a6..246f9f14 100644
--- a/cgpt/cmd_repair.c
+++ b/cgpt/cmd_repair.c
@@ -9,64 +9,63 @@
 #include "cgpt.h"
 #include "vboot_host.h"
 
-extern const char* progname;
+extern const char *progname;
 
 static void Usage(void)
 {
-  printf("\nUsage: %s repair [OPTIONS] DRIVE\n\n"
-         "Repair damaged GPT headers and tables.\n\n"
-         "Options:\n"
-         "  -D NUM       Size (in bytes) of the disk where partitions reside;\n"
-         "                 default 0, meaning partitions and GPT structs are\n"
-         "                 both on DRIVE\n"
-         "  -v           Verbose\n"
-         "\n", progname);
+	printf("\nUsage: %s repair [OPTIONS] DRIVE\n\n"
+	       "Repair damaged GPT headers and tables.\n\n"
+	       "Options:\n"
+	       "  -D NUM       Size (in bytes) of the disk where partitions reside;\n"
+	       "                 default 0, meaning partitions and GPT structs are\n"
+	       "                 both on DRIVE\n"
+	       "  -v           Verbose\n"
+	       "\n",
+	       progname);
 }
 
-int cmd_repair(int argc, char *argv[]) {
-  CgptRepairParams params;
-  memset(&params, 0, sizeof(params));
+int cmd_repair(int argc, char *argv[])
+{
+	CgptRepairParams params;
+	memset(&params, 0, sizeof(params));
 
-  int c;
-  char* e = 0;
-  int errorcnt = 0;
+	int c;
+	char *e = 0;
+	int errorcnt = 0;
 
-  opterr = 0;                     // quiet, you
-  while ((c=getopt(argc, argv, ":hvD:")) != -1)
-  {
-    switch (c)
-    {
-    case 'D':
-      params.drive_size = strtoull(optarg, &e, 0);
-      errorcnt += check_int_parse(c, e);
-      break;
-    case 'v':
-      params.verbose++;
-      break;
+	opterr = 0; // quiet, you
+	while ((c = getopt(argc, argv, ":hvD:")) != -1) {
+		switch (c) {
+		case 'D':
+			params.drive_size = strtoull(optarg, &e, 0);
+			errorcnt += check_int_parse(c, e);
+			break;
+		case 'v':
+			params.verbose++;
+			break;
 
-    case 'h':
-      Usage();
-      return CGPT_OK;
-    case '?':
-      Error("unrecognized option: -%c\n", optopt);
-      errorcnt++;
-      break;
-    case ':':
-      Error("missing argument to -%c\n", optopt);
-      errorcnt++;
-      break;
-    default:
-      errorcnt++;
-      break;
-    }
-  }
-  if (errorcnt)
-  {
-    Usage();
-    return CGPT_FAILED;
-  }
+		case 'h':
+			Usage();
+			return CGPT_OK;
+		case '?':
+			Error("unrecognized option: -%c\n", optopt);
+			errorcnt++;
+			break;
+		case ':':
+			Error("missing argument to -%c\n", optopt);
+			errorcnt++;
+			break;
+		default:
+			errorcnt++;
+			break;
+		}
+	}
+	if (errorcnt) {
+		Usage();
+		return CGPT_FAILED;
+	}
 
-  params.drive_name = argv[optind];
+	params.drive_name = argv[optind];
 
-  return CgptRepair(&params);
+	return CgptRepair(&params);
 }
diff --git a/cgpt/cmd_show.c b/cgpt/cmd_show.c
index 7f5147ea..89fa1648 100644
--- a/cgpt/cmd_show.c
+++ b/cgpt/cmd_show.c
@@ -12,129 +12,128 @@
 #include "cgpt.h"
 #include "vboot_host.h"
 
-extern const char* progname;
+extern const char *progname;
 
 static void Usage(void)
 {
-  printf("\nUsage: %s show [OPTIONS] DRIVE\n\n"
-         "Display the GPT table.\n\n"
-         "Units are blocks by default.\n\n"
-         "Options:\n"
-         "  -D NUM       Size (in bytes) of the disk where partitions reside;\n"
-         "                 default 0, meaning partitions and GPT structs are\n"
-         "                 both on DRIVE\n"
-         "  -n           Numeric output only\n"
-         "  -v           Verbose output\n"
-         "  -q           Quick output\n"
-         "  -i NUM       Show specified partition only\n"
-         "  -d           Debug output (including invalid headers)\n"
-         "\n"
-         "When using -i, specific fields may be displayed using one of:\n"
-         "  -b  first block (a.k.a. start of partition)\n"
-         "  -s  partition size (in blocks)\n"
-         "  -t  type guid\n"
-         "  -u  unique guid\n"
-         "  -l  label\n"
-         "  -S  Successful flag\n"
-         "  -T  Tries flag\n"
-         "  -P  Priority flag\n"
-         "  -R  Required flag\n"
-         "  -B  Legacy Boot flag\n"
-         "  -A  raw 16-bit attribute value (bits 48-63)\n"
-         "\n", progname);
+	printf("\nUsage: %s show [OPTIONS] DRIVE\n\n"
+	       "Display the GPT table.\n\n"
+	       "Units are blocks by default.\n\n"
+	       "Options:\n"
+	       "  -D NUM       Size (in bytes) of the disk where partitions reside;\n"
+	       "                 default 0, meaning partitions and GPT structs are\n"
+	       "                 both on DRIVE\n"
+	       "  -n           Numeric output only\n"
+	       "  -v           Verbose output\n"
+	       "  -q           Quick output\n"
+	       "  -i NUM       Show specified partition only\n"
+	       "  -d           Debug output (including invalid headers)\n"
+	       "\n"
+	       "When using -i, specific fields may be displayed using one of:\n"
+	       "  -b  first block (a.k.a. start of partition)\n"
+	       "  -s  partition size (in blocks)\n"
+	       "  -t  type guid\n"
+	       "  -u  unique guid\n"
+	       "  -l  label\n"
+	       "  -S  Successful flag\n"
+	       "  -T  Tries flag\n"
+	       "  -P  Priority flag\n"
+	       "  -R  Required flag\n"
+	       "  -B  Legacy Boot flag\n"
+	       "  -A  raw 16-bit attribute value (bits 48-63)\n"
+	       "\n",
+	       progname);
 }
 
-int cmd_show(int argc, char *argv[]) {
-  CgptShowParams params;
-  memset(&params, 0, sizeof(params));
+int cmd_show(int argc, char *argv[])
+{
+	CgptShowParams params;
+	memset(&params, 0, sizeof(params));
 
-  int c;
-  int errorcnt = 0;
-  char *e = 0;
+	int c;
+	int errorcnt = 0;
+	char *e = 0;
 
-  opterr = 0;                     // quiet, you
-  while ((c=getopt(argc, argv, ":hnvqi:bstulSTPRBAdD:")) != -1)
-  {
-    switch (c)
-    {
-    case 'D':
-      params.drive_size = strtoull(optarg, &e, 0);
-      errorcnt += check_int_parse(c, e);
-      break;
-    case 'n':
-      params.numeric = 1;
-      break;
-    case 'v':
-      params.verbose = 1;
-      break;
-    case 'q':
-      params.quick = 1;
-      break;
-    case 'i':
-      params.partition = (uint32_t)strtoul(optarg, &e, 0);
-      errorcnt += check_int_parse(c, e);
-      if (params.partition <= 0) {
-        Error("-i requires a number between 1 and 128 (inclusive)\n");
-        errorcnt++;
-      }
-      break;
-    case 'b':
-    case 's':
-    case 't':
-    case 'u':
-    case 'l':
-    case 'S':
-    case 'T':
-    case 'P':
-    case 'R':
-    case 'B':
-    case 'A':
-      if (params.single_item) {
-        Error("-%c already specified; rejecting additional -%c\n",
-              params.single_item, c);
-        Error("Only a single item may be displayed at a time\n");
-        errorcnt++;
-      }
-      params.single_item = c;
-      break;
+	opterr = 0; // quiet, you
+	while ((c = getopt(argc, argv, ":hnvqi:bstulSTPRBAdD:")) != -1) {
+		switch (c) {
+		case 'D':
+			params.drive_size = strtoull(optarg, &e, 0);
+			errorcnt += check_int_parse(c, e);
+			break;
+		case 'n':
+			params.numeric = 1;
+			break;
+		case 'v':
+			params.verbose = 1;
+			break;
+		case 'q':
+			params.quick = 1;
+			break;
+		case 'i':
+			params.partition = (uint32_t)strtoul(optarg, &e, 0);
+			errorcnt += check_int_parse(c, e);
+			if (params.partition <= 0) {
+				Error("-i requires a number between 1 and 128 (inclusive)\n");
+				errorcnt++;
+			}
+			break;
+		case 'b':
+		case 's':
+		case 't':
+		case 'u':
+		case 'l':
+		case 'S':
+		case 'T':
+		case 'P':
+		case 'R':
+		case 'B':
+		case 'A':
+			if (params.single_item) {
+				Error("-%c already specified; rejecting additional -%c\n",
+				      params.single_item, c);
+				Error("Only a single item may be displayed at a time\n");
+				errorcnt++;
+			}
+			params.single_item = c;
+			break;
 
-    case 'd':
-      params.debug = 1;
-      break;
+		case 'd':
+			params.debug = 1;
+			break;
 
-    case 'h':
-      Usage();
-      return CGPT_OK;
-    case '?':
-      Error("unrecognized option: -%c\n", optopt);
-      errorcnt++;
-      break;
-    case ':':
-      Error("missing argument to -%c\n", optopt);
-      errorcnt++;
-      break;
-    default:
-      errorcnt++;
-      break;
-    }
-  }
-  if (!params.partition && params.single_item) {
-    Error("-i required when displaying a single item\n");
-    errorcnt++;
-  }
-  if (errorcnt)
-  {
-    Usage();
-    return CGPT_FAILED;
-  }
+		case 'h':
+			Usage();
+			return CGPT_OK;
+		case '?':
+			Error("unrecognized option: -%c\n", optopt);
+			errorcnt++;
+			break;
+		case ':':
+			Error("missing argument to -%c\n", optopt);
+			errorcnt++;
+			break;
+		default:
+			errorcnt++;
+			break;
+		}
+	}
+	if (!params.partition && params.single_item) {
+		Error("-i required when displaying a single item\n");
+		errorcnt++;
+	}
+	if (errorcnt) {
+		Usage();
+		return CGPT_FAILED;
+	}
 
-  if (optind >= argc) {
-    Error("missing drive argument\n");
-    Usage();
-    return CGPT_FAILED;
-  }
+	if (optind >= argc) {
+		Error("missing drive argument\n");
+		Usage();
+		return CGPT_FAILED;
+	}
 
-  params.drive_name = argv[optind];
+	params.drive_name = argv[optind];
 
-  return CgptShow(&params);
+	return CgptShow(&params);
 }
diff --git a/firmware/2lib/2secdata_kernel.c b/firmware/2lib/2secdata_kernel.c
index a61589d7..b87304c9 100644
--- a/firmware/2lib/2secdata_kernel.c
+++ b/firmware/2lib/2secdata_kernel.c
@@ -93,8 +93,9 @@ static vb2_error_t secdata_kernel_check_v1(struct vb2_context *ctx,
 	}
 
 	if (*size < sec->struct_size) {
-		VB2_DEBUG("secdata_kernel: incomplete data (missing %d bytes)\n",
-			  sec->struct_size - *size);
+		VB2_DEBUG("secdata_kernel: size %u smaller than struct size %u;"
+			  " returning correct size\n",
+			  *size, sec->struct_size);
 		*size = sec->struct_size;
 		return VB2_ERROR_SECDATA_KERNEL_INCOMPLETE;
 	}
diff --git a/firmware/2lib/include/2sysincludes.h b/firmware/2lib/include/2sysincludes.h
index cbf39f90..93cd86f5 100644
--- a/firmware/2lib/include/2sysincludes.h
+++ b/firmware/2lib/include/2sysincludes.h
@@ -21,5 +21,10 @@
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
+#if defined(__NetBSD__) || defined(__FreeBSD__) || defined(__DragonFly__)
+#include <sys/endian.h>
+#else
+#include <endian.h>
+#endif
 
 #endif  /* VBOOT_REFERENCE_2SYSINCLUDES_H_ */
diff --git a/firmware/include/gpt.h b/firmware/include/gpt.h
index 912ea508..52a05371 100644
--- a/firmware/include/gpt.h
+++ b/firmware/include/gpt.h
@@ -136,6 +136,17 @@ typedef struct {
 
 #define GPTENTRY_EXPECTED_SIZE 128
 
+#define GUID_STRLEN 37
+
+typedef enum {
+	GPT_GUID_LOWERCASE,
+	GPT_GUID_UPPERCASE,
+} GptGuidLetterCase;
+
+void GptGuidToStr(const Guid *guid, char *str, unsigned int buflen,
+		  GptGuidLetterCase case_type);
+
+
 #ifdef __cplusplus
 }
 #endif  /* __cplusplus */
diff --git a/firmware/include/vb2_android_bootimg.h b/firmware/include/vb2_android_bootimg.h
new file mode 100644
index 00000000..b55f7748
--- /dev/null
+++ b/firmware/include/vb2_android_bootimg.h
@@ -0,0 +1,191 @@
+/* Copyright 2007 The Android Open Source Project
+ * Use of this source code is governed by a BSD-style license that can be
+ * found in the LICENSE file.
+ *
+ * This file was ported from repo:
+ * https://android.googlesource.com/platform/system/tools/mkbootimg
+ * Path: include/bootimg/bootimg.h
+ * Commit: a306f82e5a60ca1fc0be77ca2afa31a01d797295
+ */
+
+#ifndef VBOOT_REFERENCE_VB2_ANDROID_BOOTIMG_H_
+#define VBOOT_REFERENCE_VB2_ANDROID_BOOTIMG_H_
+
+#include <stdint.h>
+
+#define BOOT_MAGIC "ANDROID!"
+#define BOOT_MAGIC_SIZE 8
+#define BOOT_NAME_SIZE 16
+#define BOOT_ARGS_SIZE 512
+#define BOOT_EXTRA_ARGS_SIZE 1024
+#define BOOT_HEADER_SIZE 4096
+
+#define VENDOR_BOOT_MAGIC "VNDRBOOT"
+#define VENDOR_BOOT_MAGIC_SIZE 8
+#define VENDOR_BOOT_ARGS_SIZE 2048
+#define VENDOR_BOOT_NAME_SIZE 16
+
+#define VENDOR_RAMDISK_TYPE_NONE 0
+#define VENDOR_RAMDISK_TYPE_PLATFORM 1
+#define VENDOR_RAMDISK_TYPE_RECOVERY 2
+#define VENDOR_RAMDISK_TYPE_DLKM 3
+#define VENDOR_RAMDISK_NAME_SIZE 32
+#define VENDOR_RAMDISK_TABLE_ENTRY_BOARD_ID_SIZE 16
+
+/* When the boot image header has a version of 4, the structure of the boot
+ * image is as follows:
+ *
+ * +---------------------+
+ * | boot header         | 4096 bytes
+ * +---------------------+
+ * | kernel              | m pages
+ * +---------------------+
+ * | ramdisk             | n pages
+ * +---------------------+
+ * | boot signature      | g pages
+ * +---------------------+
+ *
+ * m = (kernel_size + 4096 - 1) / 4096
+ * n = (ramdisk_size + 4096 - 1) / 4096
+ * g = (signature_size + 4096 - 1) / 4096
+ *
+ * Note that in version 4 of the boot image header, page size is fixed at 4096
+ * bytes.
+ *
+ * The structure of the vendor boot image version 4, which is required to be
+ * present when a version 4 boot image is used, is as follows:
+ *
+ * +------------------------+
+ * | vendor boot header     | o pages
+ * +------------------------+
+ * | vendor ramdisk section | p pages
+ * +------------------------+
+ * | dtb                    | q pages
+ * +------------------------+
+ * | vendor ramdisk table   | r pages
+ * +------------------------+
+ * | bootconfig             | s pages
+ * +------------------------+
+ *
+ * o = (2128 + page_size - 1) / page_size
+ * p = (vendor_ramdisk_size + page_size - 1) / page_size
+ * q = (dtb_size + page_size - 1) / page_size
+ * r = (vendor_ramdisk_table_size + page_size - 1) / page_size
+ * s = (vendor_bootconfig_size + page_size - 1) / page_size
+ *
+ * Note that in version 4 of the vendor boot image, multiple vendor ramdisks can
+ * be included in the vendor boot image. The bootloader can select a subset of
+ * ramdisks to load at runtime. To help the bootloader select the ramdisks, each
+ * ramdisk is tagged with a type tag and a set of hardware identifiers
+ * describing the board, soc or platform that this ramdisk is intended for.
+ *
+ * The vendor ramdisk section is consist of multiple ramdisk images concatenated
+ * one after another, and vendor_ramdisk_size is the size of the section, which
+ * is the total size of all the ramdisks included in the vendor boot image.
+ *
+ * The vendor ramdisk table holds the size, offset, type, name and hardware
+ * identifiers of each ramdisk. The type field denotes the type of its content.
+ * The vendor ramdisk names are unique. The hardware identifiers are specified
+ * in the board_id field in each table entry. The board_id field is consist of a
+ * vector of unsigned integer words, and the encoding scheme is defined by the
+ * hardware vendor.
+ *
+ * For the different type of ramdisks, there are:
+ *    - VENDOR_RAMDISK_TYPE_NONE indicates the value is unspecified.
+ *    - VENDOR_RAMDISK_TYPE_PLATFORM ramdisks contain platform specific bits, so
+ *      the bootloader should always load these into memory.
+ *    - VENDOR_RAMDISK_TYPE_RECOVERY ramdisks contain recovery resources, so
+ *      the bootloader should load these when booting into recovery.
+ *    - VENDOR_RAMDISK_TYPE_DLKM ramdisks contain dynamic loadable kernel
+ *      modules.
+ *
+ * Version 4 of the vendor boot image also adds a bootconfig section to the end
+ * of the image. This section contains Boot Configuration parameters known at
+ * build time. The bootloader is responsible for placing this section directly
+ * after the generic ramdisk, followed by the bootconfig trailer, before
+ * entering the kernel.
+ *
+ * 0. all entities in the boot image are 4096-byte aligned in flash, all
+ *    entities in the vendor boot image are page_size (determined by the vendor
+ *    and specified in the vendor boot image header) aligned in flash
+ * 1. kernel, ramdisk, and DTB are required (size != 0)
+ * 2. load the kernel and DTB at the specified physical address (kernel_addr,
+ *    dtb_addr)
+ * 3. load the vendor ramdisks at ramdisk_addr
+ * 4. load the generic ramdisk immediately following the vendor ramdisk in
+ *    memory
+ * 5. load the bootconfig immediately following the generic ramdisk. Add
+ *    additional bootconfig parameters followed by the bootconfig trailer.
+ * 6. set up registers for kernel entry as required by your architecture
+ * 7. if the platform has a second stage bootloader jump to it (must be
+ *    contained outside boot and vendor boot partitions), otherwise
+ *    jump to kernel_addr
+ */
+struct boot_img_hdr_v4 {
+	// Must be BOOT_MAGIC.
+	uint8_t magic[BOOT_MAGIC_SIZE];
+
+	uint32_t kernel_size; /* size in bytes */
+	uint32_t ramdisk_size; /* size in bytes */
+
+	// Operating system version and security patch level.
+	// For version "A.B.C" and patch level "Y-M-D":
+	//   (7 bits for each of A, B, C; 7 bits for (Y-2000), 4 bits for M)
+	//   os_version = A[31:25] B[24:18] C[17:11] (Y-2000)[10:4] M[3:0]
+	uint32_t os_version;
+
+	uint32_t header_size;
+
+	uint32_t reserved[4];
+
+	// Version of the boot image header.
+	uint32_t header_version;
+
+	// Asciiz kernel commandline.
+	uint8_t cmdline[BOOT_ARGS_SIZE + BOOT_EXTRA_ARGS_SIZE];
+	uint32_t signature_size; /* size in bytes */
+} __attribute__((packed));
+
+struct vendor_boot_img_hdr_v4 {
+	// Must be VENDOR_BOOT_MAGIC.
+	uint8_t magic[VENDOR_BOOT_MAGIC_SIZE];
+
+	// Version of the vendor boot image header.
+	uint32_t header_version;
+
+	uint32_t page_size; /* flash page size we assume */
+
+	uint32_t kernel_addr; /* physical load addr */
+	uint32_t ramdisk_addr; /* physical load addr */
+
+	uint32_t vendor_ramdisk_size; /* size in bytes */
+
+	uint8_t cmdline[VENDOR_BOOT_ARGS_SIZE]; /* asciiz kernel commandline */
+
+	uint32_t tags_addr; /* physical addr for kernel tags (if required) */
+	uint8_t name[VENDOR_BOOT_NAME_SIZE]; /* asciiz product name */
+
+	uint32_t header_size;
+
+	uint32_t dtb_size; /* size in bytes for DTB image */
+	uint64_t dtb_addr; /* physical load address for DTB image */
+	uint32_t vendor_ramdisk_table_size; /* size in bytes for the vendor ramdisk table */
+	/* number of entries in the vendor ramdisk table */
+	uint32_t vendor_ramdisk_table_entry_num;
+	/* size in bytes for a vendor ramdisk table entry */
+	uint32_t vendor_ramdisk_table_entry_size;
+	uint32_t bootconfig_size; /* size in bytes for the bootconfig section */
+} __attribute__((packed));
+
+struct vendor_ramdisk_table_entry_v4 {
+	uint32_t ramdisk_size; /* size in bytes for the ramdisk image */
+	uint32_t ramdisk_offset; /* offset to the ramdisk image in vendor ramdisk section */
+	uint32_t ramdisk_type; /* type of the ramdisk */
+	uint8_t ramdisk_name[VENDOR_RAMDISK_NAME_SIZE]; /* asciiz ramdisk name */
+
+	// Hardware identifiers describing the board, soc or platform which this
+	// ramdisk is intended to be loaded on.
+	uint32_t board_id[VENDOR_RAMDISK_TABLE_ENTRY_BOARD_ID_SIZE];
+} __attribute__((packed));
+
+#endif /* VBOOT_REFERENCE_VB2_ANDROID_BOOTIMG_H_ */
diff --git a/firmware/lib/cgptlib/cgptlib.c b/firmware/lib/cgptlib/cgptlib.c
index c6fd5f8b..6ab2f9ee 100644
--- a/firmware/lib/cgptlib/cgptlib.c
+++ b/firmware/lib/cgptlib/cgptlib.c
@@ -47,7 +47,7 @@ GptEntry *GptNextKernelEntry(GptData *gpt)
 		for (i = gpt->current_kernel + 1;
 		     i < header->number_of_entries; i++) {
 			e = entries + i;
-			if (!IsKernelEntry(e))
+			if (!IsBootableEntry(e))
 				continue;
 			VB2_DEBUG("GptNextKernelEntry looking at same prio "
 				  "partition %d\n", i+1);
@@ -70,7 +70,7 @@ GptEntry *GptNextKernelEntry(GptData *gpt)
 	 */
 	for (i = 0, e = entries; i < header->number_of_entries; i++, e++) {
 		int current_prio = GetEntryPriority(e);
-		if (!IsKernelEntry(e))
+		if (!IsBootableEntry(e))
 			continue;
 		VB2_DEBUG("GptNextKernelEntry looking at new prio "
 			  "partition %d\n", i+1);
@@ -116,7 +116,7 @@ int GptUpdateKernelWithEntry(GptData *gpt, GptEntry *e, uint32_t update_type)
 {
 	int modified = 0;
 
-	if (!IsKernelEntry(e))
+	if (!IsBootableEntry(e))
 		return GPT_ERROR_INVALID_UPDATE_TYPE;
 
 	switch (update_type) {
@@ -225,3 +225,39 @@ GptEntry *GptFindNthEntry(GptData *gpt, const Guid *guid, unsigned int n)
 
 	return NULL;
 }
+
+bool GptEntryHasName(GptEntry *entry, const char *name,  const char *opt_suffix)
+{
+	for (int i = 0; i < ARRAY_SIZE(entry->name); i++) {
+		uint16_t wc = entry->name[i];
+		char c = '\0';
+
+		if (*name != '\0')
+			c = *name++;
+		else if (opt_suffix && *opt_suffix != '\0')
+			c = *opt_suffix++;
+
+		if (wc > 0x7f || (char)wc != c)
+			return false;
+
+		if (c == '\0')
+			return true;
+	}
+
+	return false;
+}
+
+GptEntry *GptFindEntryByName(GptData *gpt, const char *name, const char *opt_suffix)
+{
+	GptHeader *header = (GptHeader *)gpt->primary_header;
+	GptEntry *entries = (GptEntry *)gpt->primary_entries;
+	GptEntry *e;
+	int i;
+
+	for (i = 0, e = entries; i < header->number_of_entries; i++, e++) {
+		if (GptEntryHasName(e, name, opt_suffix))
+			return e;
+	}
+
+	return NULL;
+}
diff --git a/firmware/lib/cgptlib/cgptlib_internal.c b/firmware/lib/cgptlib/cgptlib_internal.c
index 17931370..dbc209ca 100644
--- a/firmware/lib/cgptlib/cgptlib_internal.c
+++ b/firmware/lib/cgptlib/cgptlib_internal.c
@@ -12,6 +12,19 @@
 
 static const int MIN_SECTOR_SIZE = 512;
 
+/* global types to compare against */
+const Guid guid_chromeos_firmware = GPT_ENT_TYPE_CHROMEOS_FIRMWARE;
+const Guid guid_chromeos_kernel = GPT_ENT_TYPE_CHROMEOS_KERNEL;
+const Guid guid_chromeos_rootfs = GPT_ENT_TYPE_CHROMEOS_ROOTFS;
+const Guid guid_android_vbmeta = GPT_ENT_TYPE_ANDROID_VBMETA;
+const Guid guid_basic_data = GPT_ENT_TYPE_BASIC_DATA;
+const Guid guid_linux_data = GPT_ENT_TYPE_LINUX_FS;
+const Guid guid_chromeos_reserved = GPT_ENT_TYPE_CHROMEOS_RESERVED;
+const Guid guid_efi = GPT_ENT_TYPE_EFI;
+const Guid guid_unused = GPT_ENT_TYPE_UNUSED;
+const Guid guid_chromeos_minios = GPT_ENT_TYPE_CHROMEOS_MINIOS;
+const Guid guid_chromeos_hibernate = GPT_ENT_TYPE_CHROMEOS_HIBERNATE;
+
 size_t CalculateEntriesSectors(GptHeader* h, uint32_t sector_bytes)
 {
 	size_t bytes = h->number_of_entries * h->size_of_entry;
@@ -153,10 +166,19 @@ int CheckHeader(GptHeader *h, int is_secondary,
 	return 0;
 }
 
-int IsKernelEntry(const GptEntry *e)
+bool IsChromeOS(const GptEntry *e)
+{
+	return !memcmp(&e->type, &guid_chromeos_kernel, sizeof(Guid));
+}
+
+bool IsAndroid(const GptEntry *e)
+{
+	return !memcmp(&e->type, &guid_android_vbmeta, sizeof(Guid));
+}
+
+bool IsBootableEntry(const GptEntry *e)
 {
-	static Guid chromeos_kernel = GPT_ENT_TYPE_CHROMEOS_KERNEL;
-	return !memcmp(&e->type, &chromeos_kernel, sizeof(Guid));
+	return IsChromeOS(e) || IsAndroid(e);
 }
 
 int CheckEntries(GptEntry *entries, GptHeader *h)
diff --git a/firmware/lib/cgptlib/include/cgptlib.h b/firmware/lib/cgptlib/include/cgptlib.h
index e2f5d34b..df9fd400 100644
--- a/firmware/lib/cgptlib/include/cgptlib.h
+++ b/firmware/lib/cgptlib/include/cgptlib.h
@@ -20,4 +20,18 @@
  */
 GptEntry *GptNextKernelEntry(GptData *gpt);
 
+/**
+ * Checks if entry name field is equal to name+suffix.
+ *
+ * Returns true if equal, else false.
+ */
+bool GptEntryHasName(GptEntry *entry, const char *name,  const char *opt_suffix);
+
+/**
+ * Gets GPT entry for specified partition name and suffix.
+ *
+ * Returns pointer to GPT entry if successful, else NULL
+ */
+GptEntry *GptFindEntryByName(GptData *gpt, const char *name, const char *opt_suffix);
+
 #endif  /* VBOOT_REFERENCE_CGPTLIB_H_ */
diff --git a/firmware/lib/cgptlib/include/cgptlib_internal.h b/firmware/lib/cgptlib/include/cgptlib_internal.h
index 29f84f0f..74e537aa 100644
--- a/firmware/lib/cgptlib/include/cgptlib_internal.h
+++ b/firmware/lib/cgptlib/include/cgptlib_internal.h
@@ -73,6 +73,19 @@
 #define GPT_PMBR_SECTORS 1  /* size (in sectors) of PMBR */
 #define GPT_HEADER_SECTORS 1
 
+/* Global types to compare against */
+extern const Guid guid_chromeos_firmware;
+extern const Guid guid_chromeos_kernel;
+extern const Guid guid_chromeos_rootfs;
+extern const Guid guid_android_vbmeta;
+extern const Guid guid_basic_data;
+extern const Guid guid_linux_data;
+extern const Guid guid_chromeos_reserved;
+extern const Guid guid_efi;
+extern const Guid guid_unused;
+extern const Guid guid_chromeos_minios;
+extern const Guid guid_chromeos_hibernate;
+
 /*
  * Alias name of index in internal array for primary and secondary header and
  * entries.
@@ -155,9 +168,20 @@ void GptRepair(GptData *gpt);
 void GptModified(GptData *gpt);
 
 /**
- * Return 1 if the entry is a Chrome OS kernel partition, else 0.
+ * Return true if the entry is a Android VBMETA partition, else false.
+ */
+bool IsAndroid(const GptEntry *e);
+
+/**
+ * Return true if the entry is a ChromeOS kernel partition, else false.
+ */
+bool IsChromeOS(const GptEntry *e);
+
+/**
+ * Return true if the entry is a ChromeOS or Android partition,
+ * else false.
  */
-int IsKernelEntry(const GptEntry *e);
+bool IsBootableEntry(const GptEntry *e);
 
 /**
  * Copy the current kernel partition's UniquePartitionGuid to the dest.
diff --git a/firmware/lib/gpt_misc.c b/firmware/lib/gpt_misc.c
index 79ff6cde..b8e759bc 100644
--- a/firmware/lib/gpt_misc.c
+++ b/firmware/lib/gpt_misc.c
@@ -247,3 +247,23 @@ uint64_t GptGetEntrySizeBytes(const GptData *gpt, const GptEntry *e)
 {
 	return GptGetEntrySizeLba(e) * gpt->sector_bytes;
 }
+
+void GptGuidToStr(const Guid *guid, char *str, unsigned int buflen,
+		  GptGuidLetterCase case_type)
+{
+	VB2_ASSERT(buflen >= GUID_STRLEN);
+
+	const char *format_string;
+	if (case_type == GPT_GUID_LOWERCASE)
+		format_string = "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x";
+	else
+		format_string = "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X";
+
+	snprintf(str, buflen, format_string,
+		 le32toh(guid->u.Uuid.time_low), le16toh(guid->u.Uuid.time_mid),
+		 le16toh(guid->u.Uuid.time_high_and_version),
+		 guid->u.Uuid.clock_seq_high_and_reserved, guid->u.Uuid.clock_seq_low,
+		 guid->u.Uuid.node[0], guid->u.Uuid.node[1], guid->u.Uuid.node[2],
+		 guid->u.Uuid.node[3], guid->u.Uuid.node[4],
+		 guid->u.Uuid.node[5]);
+}
diff --git a/futility/cmd_dump_fmap.c b/futility/cmd_dump_fmap.c
index dcb77dab..2abc6911 100644
--- a/futility/cmd_dump_fmap.c
+++ b/futility/cmd_dump_fmap.c
@@ -345,9 +345,9 @@ static int human_fmap(const FmapHeader *fmh, bool gaps, int overlap)
 	}
 	/* Now add the root node */
 	all_nodes[numnodes].name = strdup("-entire flash-");
-	all_nodes[numnodes].start = fmh->fmap_base;
+	all_nodes[numnodes].start = 0;
 	all_nodes[numnodes].size = fmh->fmap_size;
-	all_nodes[numnodes].end = fmh->fmap_base + fmh->fmap_size;
+	all_nodes[numnodes].end = fmh->fmap_size;
 
 	/* First, coalesce any duplicates */
 	for (uint16_t i = 0; i < numnodes; i++) {
@@ -401,7 +401,8 @@ static int human_fmap(const FmapHeader *fmh, bool gaps, int overlap)
 			add_child(all_nodes[i].parent, i);
 
 	/* Ready to go */
-	printf("# name                     start       end         size\n");
+	printf("# %-25s%-12s%-12s%s  // address relative to base=0x%" PRIx64 "\n",
+	       "name", "start", "end", "size", fmh->fmap_base);
 	int gapcount = 0;
 	show(all_nodes + numnodes, 0, gaps, gaps, &gapcount);
 
diff --git a/futility/updater.c b/futility/updater.c
index 7511b3d0..8cfe48ca 100644
--- a/futility/updater.c
+++ b/futility/updater.c
@@ -264,7 +264,7 @@ static const char *decide_rw_target(struct updater_config *cfg,
 static int set_try_cookies(struct updater_config *cfg, const char *target,
 			   int has_update)
 {
-	int tries = 17;
+	int tries = 15;
 	const char *slot;
 
 	if (!has_update)
diff --git a/host/arch/x86/lib/crossystem_arch.c b/host/arch/x86/lib/crossystem_arch.c
index c61f1163..a5608145 100644
--- a/host/arch/x86/lib/crossystem_arch.c
+++ b/host/arch/x86/lib/crossystem_arch.c
@@ -813,6 +813,10 @@ static const struct GpioChipset chipsets_supported[] = {
 	{ "INTC1083:00", FindGpioChipOffsetByLabel },
 	/* INTC10Bx are for Panther Lake */
 	{ "INTC10BC:00", FindGpioChipOffsetByLabel },
+	{ "INTC10BC:01", FindGpioChipOffsetByLabel },
+	{ "INTC10BC:02", FindGpioChipOffsetByLabel },
+	{ "INTC10BC:03", FindGpioChipOffsetByLabel },
+	{ "INTC10BC:04", FindGpioChipOffsetByLabel },
 	/* INT3453 are for GLK */
 	{ "INT3453:00", FindGpioChipOffsetByLabel },
 	{ "INT3453:01", FindGpioChipOffsetByLabel },
diff --git a/host/include/vboot_host.h b/host/include/vboot_host.h
index 90d5c563..a0552f3f 100644
--- a/host/include/vboot_host.h
+++ b/host/include/vboot_host.h
@@ -45,9 +45,7 @@ int CgptLegacy(CgptLegacyParams *params);
  * At least GUID_STRLEN bytes should be reserved in 'str' (included the tailing
  * '\0').
  */
-#define GUID_STRLEN 37
-int StrToGuid(const char *str, Guid *guid);
-void GuidToStr(const Guid *guid, char *str, unsigned int buflen);
+int GptStrToGuid(const char *str, Guid *guid);
 int GuidEqual(const Guid *guid1, const Guid *guid2);
 int GuidIsZero(const Guid *guid);
 
diff --git a/host/lib/util_misc.c b/host/lib/util_misc.c
index 070ceb44..60a17a2b 100644
--- a/host/lib/util_misc.c
+++ b/host/lib/util_misc.c
@@ -211,9 +211,19 @@ int vb_keyb_from_rsa(struct rsa_st *rsa_private_key, uint8_t **keyb_data, uint32
 int vb_keyb_from_private_key(struct vb2_private_key *private_key, uint8_t **keyb_data,
 			     uint32_t *keyb_size)
 {
+	int err;
 	switch (private_key->key_location) {
 	case PRIVATE_KEY_P11:
-		return vb_keyb_from_p11_key(private_key->p11_key, keyb_data, keyb_size);
+		err = vb_keyb_from_p11_key(private_key->p11_key, keyb_data, keyb_size);
+		if (!err) {
+			/* Since ID is not populated in PKCS11, copy the sha into the ID
+			 * field.
+			 */
+			struct vb2_hash hash;
+			vb2_hash_calculate(false, *keyb_data, *keyb_size, VB2_HASH_SHA1, &hash);
+			memcpy(private_key->id.raw, hash.sha1, sizeof(private_key->id.raw));
+		}
+		return err;
 	case PRIVATE_KEY_LOCAL:
 		return vb_keyb_from_rsa(private_key->rsa_private_key, keyb_data, keyb_size);
 	}
diff --git a/scripts/image_signing/lib/keycfg.sh b/scripts/image_signing/lib/keycfg.sh
index 288999fe..c4fa448c 100644
--- a/scripts/image_signing/lib/keycfg.sh
+++ b/scripts/image_signing/lib/keycfg.sh
@@ -56,6 +56,9 @@ setup_default_keycfg() {
   export KEYCFG_ACCESSORY_RWSIG_VBPRIK2=""
   # update payload key
   export KEYCFG_UPDATE_KEY_PEM="${key_dir}/update_key.pem"
+  # ti50 keys
+  export KEYCFG_CR50_KEY="${key_dir}/cr50.pem"
+  export KEYCFG_TI50_KEY="${key_dir}/ti50.pem"
 }
 
 # Setup the key configuration. This setups the default configuration and source
diff --git a/scripts/image_signing/sign_gsc_firmware.sh b/scripts/image_signing/sign_gsc_firmware.sh
index bfa1dff1..2272bcb2 100755
--- a/scripts/image_signing/sign_gsc_firmware.sh
+++ b/scripts/image_signing/sign_gsc_firmware.sh
@@ -3,6 +3,7 @@
 # Use of this source code is governed by a BSD-style license that can be
 # found in the LICENSE file.
 
+# shellcheck source=common.sh
 . "$(dirname "$0")/common.sh"
 
 load_shflags || exit 1
@@ -10,9 +11,11 @@ load_shflags || exit 1
 DEFINE_boolean override_keyid "${FLAGS_TRUE}" \
   "Override keyid from manifest." ""
 
-FLAGS_HELP="Usage: ${PROG} [options] <input_dir> <key_dir> <output_image>
+# shellcheck disable=SC2154
+FLAGS_HELP="Usage: ${PROG} [options] <input_dir> <cr50 key> `
+                   `<ti50 key> <output_image>
 
-Signs <input_dir> with keys in <key_dir>.
+Signs <input_dir> with keys specified.
 "
 
 # Parse command line.
@@ -70,10 +73,10 @@ parse_segment() {
 
     case "${type}" in
       (02)
-        segment=$(( value << 4 ))
+        segment=$(( value * 16 ))
         ;;
       (04)
-        segment=$(( value << 16 ))
+        segment=$(( value * 65536 ))
         ;;
       (*)
         error "unknown segment record type ${type}"
@@ -496,10 +499,10 @@ verify_ro() {
   die "RO key (${key_byte}) in ${ro_bin} does not match type prod"
 }
 
-# This function prepares a full GSC image, consisting of two ROs and two RWs
-# placed at their respective offsets into the resulting blob. It invokes the
-# bs (binary signer) script to actually convert ELF versions of RWs into
-# binaries and sign them.
+# This function prepares a full H1 or DT GSC image, consisting of two ROs and
+# two RWs placed at their respective offsets into the resulting blob. It
+# invokes the bs (binary signer) script to actually convert ELF versions of
+# RWs into binaries and sign them.
 #
 # The signed image is placed in the directory named as concatenation of RO and
 # RW version numbers and board ID fields, if set to non-default. The ebuild
@@ -583,15 +586,171 @@ sign_gsc_firmware() {
   info "Image successfully signed to ${output_file}"
 }
 
+# Given a file containing an ECDSA signature in ASN.1 wrapping extract the R
+# and S components, change their endianness and concatenate them together in
+# a single 64 byte blob.
+ecdsa_sig_to_raw() {
+  if [[ $# -ne 2 ]]; then
+    die "Usage: ecdsa_sig_to_raw <ASN.1 DER ECDSA sig> <RAW ECDSA SIG>"
+  fi
+
+  local asn1_sig="$1"
+  local raw_sig="$2"
+
+  # When parsing the signature, the two components are printed as 32 byte hex
+  # numbers in the following format:
+  #    2:d=1  hl=2 l=  33 prim: INTEGER :<hex ascii value>
+  # let's pick them up, reverse the values and save in a single blob
+  for line in $(openssl asn1parse -inform der -in "${asn1_sig}" |
+               awk -F: '/INTEGER/ {print $4}'); do
+    echo "${line}" |
+      xxd -r -p |
+      /usr/bin/od -An -tx1 -w32 |
+      tr ' ' '\n' |
+      tac |
+      xargs |
+      sed 's/ //g'
+  done | xxd -r -p > "${raw_sig}"
+}
+
+make_nt_image() {
+  if [[ $# -ne 4 ]]; then
+    die "Usage: `
+        `make_nt_image <rom_ext_{a,b}> <signed_rw_bin> <output>"
+  fi
+
+  local rom_ext_a="$1"
+  local rom_ext_b="$2"
+  local signed_rw_bin="$3"
+  local output="$4"
+
+  local full_image_size_kb=1024
+  local rw_kb_offset=64
+
+  # Now build a full OT image
+  tr '\000' '\377' < /dev/zero | dd of="${output}.tmp" \
+                                        bs=1K count="${full_image_size_kb}" status=none
+  for x in "${rom_ext_a}:0" "${rom_ext_b}:$(( full_image_size_kb/2 ))" \
+                                "${signed_rw_bin}:${rw_kb_offset}" \
+                                "${signed_rw_bin}:$(( full_image_size_kb/2 + rw_kb_offset ))"
+  do
+    local tuple
+
+    # shellcheck disable=SC2206
+    IFS=: tuple=( ${x} )
+    dd if="${tuple[0]}" of="${output}.tmp" bs=1k seek="${tuple[1]}" \
+       conv=notrunc status=none
+  done
+  mv "${output}.tmp" "${output}"
+}
+
+# Sign image with a cloud KMS key using openssl with a PKCS#11 plugin. This
+# function expects KMS_PKCS11_CONFIG env variable to be the name of the
+# appropriate yaml file, and KEYCFG_TI50_KEY to be the name of the key to pass
+# to the openssl invocation.
+openssl_sign_firmware() {
+  if [[ $# -ne 5 ]]; then
+    die "Usage: openssl_sign_firmware <rom_ext_{a,b}> <rw_bin> <ti50 key> <output>"
+  fi
+
+  if [[ -z ${KMS_PKCS11_CONFIG:-} ]]; then
+    die "KMS_PKCS11_CONFIG must be defined in the environment"
+  fi
+  local rom_ext_a="$1"
+  local rom_ext_b="$2"
+  local rw_bin="$3"
+  local ti50_key="$4"
+  local output="$5"
+
+  local hex_code_end
+  local ot_tbs
+  local sig_space_size
+  local signature
+  local signed_rw_bin
+  local tmpd
+
+  tmpd=$(make_temp_dir)
+
+  ot_tbs="${tmpd}/tbs"
+  signature="${tmpd}/signature"
+  signed_rw_bin="${tmpd}/signed.bin"
+
+  # Read the code end location from the manifest, where it is placed at offset
+  # of 828 hardcoded below.
+  hex_code_end="$(dd if="${rw_bin}"  bs=1 count=4 skip=828 status=none | \
+                     /usr/bin/od -An -tx4 | awk '{print "0x"$1}')"
+
+  # Signature space is allocated at offset zero of the image.
+  sig_space_size=384
+  # Extract the TBS section of the binary which is everything above the
+  # signature until code end.
+  dd if="${rw_bin}" of="${ot_tbs}" bs=1 skip="${sig_space_size}" \
+     count=$(( hex_code_end - sig_space_size )) status=none
+
+  (
+    export KMS_PKCS11_CONFIG
+    export PKCS11_MODULE_PATH
+
+    openssl dgst -sha256 \
+            -engine pkcs11 -keyform engine \
+            -sign "${ti50_key}" \
+            -out "${signature}" < "${ot_tbs}"
+  )
+
+  plug_in_signatures "${signature}" ""  "${rw_bin}" "${signed_rw_bin}"
+
+  make_nt_image "${rom_ext_a}" "${rom_ext_b}" "${signed_rw_bin}" "${output}"
+
+  # Tell the signer how to rename the @CHIP@ portion of the output.
+  echo "ti50" > "${output}.rename"
+}
+
+plug_in_signatures() {
+  local ecdsa_sig="$1"
+  local spx_sig="$2"
+  local rw_bin="$3"
+  local signed_bin="$4"
+
+  local tmp_signed_bin="${signed_bin}.tmp"
+
+  cp "${rw_bin}" "${tmp_signed_bin}"
+
+  if [[ -n ${ecdsa_sig} ]]; then
+    local ecdsa_sig_raw="${ecdsa_sig}.raw"
+
+    ecdsa_sig_to_raw "${ecdsa_sig}" "${ecdsa_sig_raw}"
+
+    # ECDSA signature is at the very bottom of the binary
+    dd if="${ecdsa_sig_raw}" of="${tmp_signed_bin}" conv=notrunc status=none
+  fi
+
+  if [[ -n ${spx_sig} ]]; then
+    # During the build process, when SPX key is added to the image, the signature
+    # space is also allocated so the image is extended to cover the space
+    # which will eventually be taken by the SPX signature.
+    #
+    # We expect the manifest to point at the SPX signature at the very end of
+    # the extended input binary blob.
+    local spx_sig_offset
+
+    spx_sig_offset=$(( "$(stat -c '%s' "${rw_bin}")" -
+                       "$(stat -c '%s' "${spx_sig}")" ))
+    dd if="${spx_sig}" of="${tmp_signed_bin}" seek="${spx_sig_offset}" bs=1 \
+       conv=notrunc status=none
+  fi
+  mv "${tmp_signed_bin}" "${signed_bin}"
+}
+
 # Sign the directory holding GSC firmware.
 sign_gsc_firmware_dir() {
-  if [[ $# -ne 3 ]]; then
-    die "Usage: sign_gsc_firmware_dir <input> <key dir> <output>"
+  if [[ $# -ne 4 ]]; then
+    die "Usage: sign_gsc_firmware_dir <input> <cr_50 key> <ti50 key> <output>"
   fi
 
   local input="${1%/}"
-  local key_dir="$2"
-  local output="$3"
+  local cr50_key="$2"
+  local ti50_key="$3"
+  local output="$4"
   local generation
   local rw_a
   local rw_b
@@ -600,6 +759,13 @@ sign_gsc_firmware_dir() {
   local key_file
   local base_name
 
+   # shellcheck disable=SC2012
+  if [[  -n $(ls "${input}"/pao* 2>/dev/null) ]]; then
+    # This is an Opentitan tarball, sign it for ECDSA with Cloud KMS.
+    openssl_sign_firmware "${input}/rom_ext.A" "${input}/rom_ext.B" \
+                          "${input}/rw.bin.ecdsa" "${ti50_key}" "${output}"
+    return
+  fi
   manifest_source="${input}/prod.json"
   manifest_file="${manifest_source}.updated"
 
@@ -614,11 +780,13 @@ sign_gsc_firmware_dir() {
     (h|null)
       generation="h"
       base_name="cr50"
+      key_file="${cr50_key}"
       rw_a="${input}/ec.RW.elf"
       rw_b="${input}/ec.RW_B.elf"
       ;;
     (d)
       base_name="ti50"
+      key_file="${ti50_key}"
       rw_a="${input}/rw_A.hex"
       rw_b="${input}/rw_B.hex"
       ;;
@@ -627,7 +795,6 @@ sign_gsc_firmware_dir() {
       ;;
   esac
 
-  key_file="${key_dir}/${base_name}.pem"
   if [[ ! -e "${key_file}" ]]; then
     die "Missing key file: ${key_file}"
   fi
@@ -650,14 +817,15 @@ sign_gsc_firmware_dir() {
 }
 
 main() {
-  if [[ $# -ne 3 ]]; then
+  if [[ $# -ne 4 ]]; then
     flags_help
     exit 1
   fi
 
   local input="${1%/}"
-  local key_dir="$2"
-  local output="$3"
+  local cr50_key="$2"
+  local ti50_key="$3"
+  local output="$4"
 
   local signing_instructions="${input}/signing_instructions.sh"
 
@@ -671,6 +839,6 @@ main() {
     die "Missing input directory: ${input}"
   fi
 
-  sign_gsc_firmware_dir "${input}" "${key_dir}" "${output}"
+  sign_gsc_firmware_dir "${input}" "${cr50_key}" "${ti50_key}" "${output}"
 }
 main "$@"
diff --git a/scripts/image_signing/sign_official_build.sh b/scripts/image_signing/sign_official_build.sh
index 27d6c238..ce5faa9d 100755
--- a/scripts/image_signing/sign_official_build.sh
+++ b/scripts/image_signing/sign_official_build.sh
@@ -909,14 +909,15 @@ verify_uefi_signatures() {
 }
 
 # Sign a GSC firmware image with the given keys.
-# Args: CONTAINER KEY_DIR [OUTPUT_CONTAINER]
+# Args: CONTAINER CR50_KEY TI50_KEY [OUTPUT_CONTAINER]
 sign_gsc_firmware() {
   local image=$1
-  local key_dir=$2
-  local output=$3
+  local cr50_key=$2
+  local ti50_key=$3
+  local output=$4
 
   "${SCRIPT_DIR}/sign_gsc_firmware.sh" \
-    "${image}" "${key_dir}" "${output}"
+    "${image}" "${cr50_key}" "${ti50_key}" "${output}"
 }
 
 # Verify an image including rootfs hash using the specified keys.
@@ -1479,7 +1480,8 @@ main() {
     do_futility sign --type rwsig --prikey "${PRIV_KEY}" \
              --version "${FIRMWARE_VERSION}" "${OUTPUT_IMAGE}"
   elif [[ "${TYPE}" == "gsc_firmware" ]]; then
-    sign_gsc_firmware "${INPUT_IMAGE}" "${KEY_DIR}" "${OUTPUT_IMAGE}"
+    sign_gsc_firmware "${INPUT_IMAGE}" "${KEYCFG_CR50_KEY}" \
+      "${KEYCFG_TI50_KEY}" "${OUTPUT_IMAGE}"
   elif [[ "${TYPE}" == "hps_firmware" ]]; then
     hps-sign-rom --input "${INPUT_IMAGE}" --output "${OUTPUT_IMAGE}" \
       --private-key "${KEY_DIR}/key_hps.priv.pem"
diff --git a/scripts/image_signing/swap_ec_rw b/scripts/image_signing/swap_ec_rw
index 202e868c..53db0ec0 100755
--- a/scripts/image_signing/swap_ec_rw
+++ b/scripts/image_signing/swap_ec_rw
@@ -15,6 +15,8 @@ Swap the EC RW (ecrw) within an AP firmware (BIOS) image.
 # Flags.
 DEFINE_string image "" "The AP firmware file (e.g 'image-steelix.bin') to swap out ecrw" i
 DEFINE_string ec "" "The EC firmware file (e.g 'ec.bin')" e
+DEFINE_string ec_config "" "The EC config file (default is 'ec.config')"
+DEFINE_string ap_for_ec "" "The AP firmware file (e.g 'image-steelix.bin') as source of EC firmware file" a
 
 # Parse command line.
 FLAGS "$@" || exit 1
@@ -30,29 +32,128 @@ CBFS_ECRW_HASH_NAME="ecrw.hash"
 CBFS_ECRW_VERSION_NAME="ecrw.version"
 CBFS_ECRW_CONFIG_NAME="ecrw.config"
 
+cbfstool_check_exist() {
+  local ap_file="$1"
+  local region="$2"
+  local name="$3"
+  cbfstool "${ap_file}" print -r "${region}" -k | grep -q "^${name}"$'\t'
+}
+
+cbfstool_try_extract() {
+  local ap_file="$1"
+  local region="$2"
+  local name="$3"
+  local output="$4"
+
+  if cbfstool_check_exist "${ap_file}" "${region}" "${name}"; then
+    if [[ -e "${output}" ]]; then
+      die "Extracting should not override file. ${output} already exists."
+    fi
+    cbfstool "${ap_file}" extract -r "${region}" -n "${name}" -f "${output}"
+    return 0
+  fi
+  return 1
+}
+
+cbfstool_try_remove() {
+  local ap_file="$1"
+  local region="$2"
+  local name="$3"
+
+  if cbfstool_check_exist "${ap_file}" "${region}" "${name}"; then
+    cbfstool "${ap_file}" remove -r "${region}" -n "${name}"
+    return 0
+  fi
+  return 1
+}
+
+extract_ecrw_files_from_ap() {
+  local ecrw_file=$1
+  local ecrw_hash_file=$2
+  local ecrw_ver_file=$3
+  local ecrw_config_file=$4
+  local ap_for_ec_file=$5
+
+  local region="${FMAP_REGIONS[0]}"
+
+  cbfstool "${ap_for_ec_file}" extract -r "${region}" -n "${CBFS_ECRW_NAME}" \
+    -f "${ecrw_file}"
+  info "EC RW extracted to ${ecrw_file}"
+
+  cbfstool "${ap_for_ec_file}" extract -r "${region}" \
+    -n "${CBFS_ECRW_HASH_NAME}" -f "${ecrw_hash_file}"
+  info "EC RW hash extracted to ${ecrw_hash_file}"
+
+  cbfstool_try_extract "${ap_for_ec_file}" "${region}" \
+    "${CBFS_ECRW_VERSION_NAME}" "${ecrw_ver_file}" \
+    || warn "${CBFS_ECRW_VERSION_NAME} not found in source AP file."
+
+  cbfstool_try_extract "${ap_for_ec_file}" "${region}" \
+    "${CBFS_ECRW_CONFIG_NAME}" "${ecrw_config_file}" \
+    || warn "${CBFS_ECRW_CONFIG_NAME} not found in source AP file."
+}
+
+extract_ecrw_files_from_ec() {
+  local ecrw_file=$1
+  local ecrw_hash_file=$2
+  local ecrw_ver_file=$3
+  local ec_file=$4
+
+  if ! futility dump_fmap -x "${ec_file}" "RW_FW:${ecrw_file}" >/dev/null ; then
+    info "Falling back to EC_RW section"
+    futility dump_fmap -x "${ec_file}" "EC_RW:${ecrw_file}" >/dev/null
+  fi
+  info "EC RW extracted to ${ecrw_file}"
+
+  openssl dgst -sha256 -binary "${ecrw_file}" > "${ecrw_hash_file}"
+  info "EC RW hash saved to ${ecrw_hash_file}"
+
+  futility dump_fmap -x "${ec_file}" "RW_FWID:${ecrw_ver_file}" >/dev/null
+}
+
 swap_ecrw() {
   local ap_file=$1
   local ec_file=$2
+  local ec_config_file=$3
+  local ap_for_ec_file=$4
+
   local temp_dir
-  local info
   local ecrw_file
   local ecrw_hash_file
   local ecrw_ver_file
+  local ecrw_config_file
+
+  local region
+  local info
   local ecrw_comp_type
+
   local ecrw_ver
   local apro_ver
   local aprw_ver
-  temp_dir=$(mktemp -d)
-  ecrw_file="${temp_dir}/ecrw"
-  futility dump_fmap -x "${ec_file}" "RW_FW:${ecrw_file}" >/dev/null
-  info "EC RW extracted to ${ecrw_file}"
-
-  ecrw_hash_file="${temp_dir}/ecrw.hash"
-  openssl dgst -sha256 -binary "${ecrw_file}" > "${ecrw_hash_file}"
-  info "EC RW hash saved to ${ecrw_hash_file}"
 
-  ecrw_ver_file="${temp_dir}/ecrw.version"
-  futility dump_fmap -x "${ec_file}" "RW_FWID:${ecrw_ver_file}" >/dev/null
+  temp_dir=$(mktemp -d)
+  ecrw_file="${temp_dir}/${CBFS_ECRW_NAME}"
+  ecrw_hash_file="${temp_dir}/${CBFS_ECRW_HASH_NAME}"
+  ecrw_ver_file="${temp_dir}/${CBFS_ECRW_VERSION_NAME}"
+  ecrw_config_file="${temp_dir}/${CBFS_ECRW_CONFIG_NAME}"
+
+  if [[ -n "${ec_file}" ]]; then
+    extract_ecrw_files_from_ec \
+      "${ecrw_file}" \
+      "${ecrw_hash_file}" \
+      "${ecrw_ver_file}" \
+      "${ec_file}"
+    if [[ -n "${ec_config_file}" ]]; then
+      ecrw_config_file="${ec_config_file}"
+    fi
+  else
+    extract_ecrw_files_from_ap \
+      "${ecrw_file}" \
+      "${ecrw_hash_file}" \
+      "${ecrw_ver_file}" \
+      "${ecrw_config_file}" \
+      "${ap_for_ec_file}"
+  fi
 
   for region in "${FMAP_REGIONS[@]}"
   do
@@ -63,19 +164,29 @@ swap_ecrw() {
     ecrw_comp_type=${ecrw_comp_type:-none}
     cbfstool "${ap_file}" remove -r "${region}" -n "${CBFS_ECRW_NAME}"
     cbfstool "${ap_file}" remove -r "${region}" -n "${CBFS_ECRW_HASH_NAME}"
-    cbfstool "${ap_file}" remove -r "${region}" -n "${CBFS_ECRW_VERSION_NAME}" \
-      || warn "${CBFS_ECRW_VERSION_NAME} not found, but will be added"
-    # TODO(b/307788351): Update ecrw.config. Right now the config info cannot
-    # be obtained from ec.bin.
-    cbfstool "${ap_file}" remove -r "${region}" \
-      -n "${CBFS_ECRW_CONFIG_NAME_NAME}" || true
+    cbfstool_try_remove "${ap_file}" "${region}" "${CBFS_ECRW_VERSION_NAME}" \
+      || true
+    cbfstool_try_remove "${ap_file}" "${region}" "${CBFS_ECRW_CONFIG_NAME}" \
+      || true
     cbfstool "${ap_file}" expand -r "${region}"
     cbfstool "${ap_file}" add -r "${region}" -t raw \
       -c "${ecrw_comp_type}" -f "${ecrw_file}" -n "${CBFS_ECRW_NAME}"
     cbfstool "${ap_file}" add -r "${region}" -t raw \
       -c none -f "${ecrw_hash_file}" -n "${CBFS_ECRW_HASH_NAME}"
-    cbfstool "${ap_file}" add -r "${region}" -t raw \
-      -c none -f "${ecrw_ver_file}" -n "${CBFS_ECRW_VERSION_NAME}"
+    if [[ -e "${ecrw_ver_file}" ]]; then
+      cbfstool "${ap_file}" add -r "${region}" -t raw \
+        -c none -f "${ecrw_ver_file}" -n "${CBFS_ECRW_VERSION_NAME}"
+    else
+      warn "${CBFS_ECRW_VERSION_NAME} is missing from source file."
+    fi
+    # Add ecrw.config if provided.
+    if [[ -e "${ecrw_config_file}" ]]; then
+      cbfstool "${ap_file}" add -r "${region}" -t raw \
+        -c "${ecrw_comp_type}" -f "${ecrw_config_file}" \
+        -n "${CBFS_ECRW_CONFIG_NAME}"
+    else
+      warn "${CBFS_ECRW_CONFIG_NAME} is missing from source file."
+    fi
   done
 
   local keyset
@@ -86,8 +197,15 @@ swap_ecrw() {
   # 'futility sign' will call 'cbfstool truncate' if needed
   futility sign "${ap_file}" --keyset "${keyset}"
 
-  ecrw_ver=$(futility update --manifest -e "${ec_file}" \
-    | jq -r '.default.ec.versions.rw')
+  if [[ -n "${ec_file}" ]]; then
+    ecrw_ver=$(futility update --manifest -e "${ec_file}" \
+      | jq -r '.default.ec.versions.rw')
+  else
+    # As some old `ap_for_ec_file` image may not have `ecrw_ver_file`, use
+    # the `ap_for_ec_file` AP version as the EC RW version.
+    ecrw_ver=$(futility update --manifest -i "${ap_for_ec_file}" \
+      | jq -r '.default.host.versions.ro')
+  fi
   apro_ver=$(futility update --manifest -i "${ap_file}" \
     | jq -r '.default.host.versions.ro')
   aprw_ver=$(futility update --manifest -i "${ap_file}" \
@@ -99,14 +217,30 @@ swap_ecrw() {
 main() {
   if [[ -z "${FLAGS_image}" ]]; then
     flags_help
-    die "-i or --image required."
+    die "-i or --image are required."
   fi
-  if [[ -z "${FLAGS_ec}" ]]; then
+
+  if [[ -z "${FLAGS_ec}" ]] && [[ -z "${FLAGS_ap_for_ec}" ]]; then
+    flags_help
+    die "-e/--ec or -a/--ap_for_ec are required."
+  fi
+  if [[ -n "${FLAGS_ec}" ]] && [[ -n "${FLAGS_ap_for_ec}" ]]; then
     flags_help
-    die "-e or --ec required."
+    die "-e/--ec conflicts with -a/--ap_for_ec."
+  fi
+
+  if [[ -n "${FLAGS_ec}" ]] &&
+     [[ -z "${FLAGS_ec_config}" ]] &&
+     [[ -f "$(dirname ${FLAGS_ec})/ec.config" ]]; then
+    FLAGS_ec_config="$(dirname ${FLAGS_ec})/ec.config"
+    info "Using ec.config from ${FLAGS_ec_config}"
+  fi
+  if [[ -n "${FLAGS_ap_for_ec}" ]] &&
+     [[ -n "${FLAGS_ec_config}" ]]; then
+    die "-a/--ap_for_ec conflicts with --ec_config."
   fi
 
-  swap_ecrw "${FLAGS_image}" "${FLAGS_ec}"
+  swap_ecrw "${FLAGS_image}" "${FLAGS_ec}" "${FLAGS_ec_config}" "${FLAGS_ap_for_ec}"
 }
 
 main "$@"
diff --git a/tests/cgptlib_test.c b/tests/cgptlib_test.c
index 4a6355c5..106456dc 100644
--- a/tests/cgptlib_test.c
+++ b/tests/cgptlib_test.c
@@ -26,9 +26,14 @@
  *     134    100  root A (index: 1)
  *     234    100  root B (index: 2)
  *     334    100  kernel B (index: 3)
- *     434     32  secondary partition entries
- *     466      1  secondary partition header
- *     467
+ *     434     10  boot A (index: 4)
+ *     444     10  boot B (index: 5)
+ *     454     10  init_boot A (index: 6)
+ *     464     10  init_boot B (index: 7)
+ *     474     10  init_boot B (index: 7)
+ *     484     32  secondary partition entries
+ *     516      1  secondary partition header
+ *     517
  */
 #define KERNEL_A 0
 #define KERNEL_B 1
@@ -36,16 +41,41 @@
 #define ROOTFS_B 3
 #define KERNEL_X 2 /* Overload ROOTFS_A, for some GetNext tests */
 #define KERNEL_Y 3 /* Overload ROOTFS_B, for some GetNext tests */
+#define BOOT_A 4
+#define BOOT_B 5
 
 #define DEFAULT_SECTOR_SIZE 512
 #define MAX_SECTOR_SIZE 4096
-#define DEFAULT_DRIVE_SECTORS 467
+#define DEFAULT_DRIVE_SECTORS 517
 #define TOTAL_ENTRIES_SIZE GPT_ENTRIES_ALLOC_SIZE /* 16384 */
 #define PARTITION_ENTRIES_SIZE TOTAL_ENTRIES_SIZE /* 16384 */
 
+enum kernel_type { NO_KERNEL, CHROMEOS, ANDROID };
+
 static const Guid guid_zero = {{{0, 0, 0, 0, 0, {0, 0, 0, 0, 0, 0}}}};
 static const Guid guid_kernel = GPT_ENT_TYPE_CHROMEOS_KERNEL;
 static const Guid guid_rootfs = GPT_ENT_TYPE_CHROMEOS_ROOTFS;
+static const Guid guid_vbmeta = GPT_ENT_TYPE_ANDROID_VBMETA;
+
+static const uint16_t kern_a_name[] = {0x004b, 0x0045, 0x0052, 0x004e, 0x002d,
+				       0x0041, 0x0000};
+static const uint16_t root_a_name[] = {0x0052, 0x004f, 0x004f, 0x0054, 0x002d,
+				       0x0041, 0x0000};
+static const uint16_t kern_b_name[] = {0x004b, 0x0045, 0x0052, 0x004e, 0x002d,
+				       0x0042, 0x0000};
+static const uint16_t root_b_name[] = {0x0052, 0x004f, 0x004f, 0x0054, 0x002d,
+				       0x0042, 0x0000};
+static const uint16_t boot_a_name[] = {0x0062, 0x006f, 0x006f, 0x0074, 0x005f,
+				       0x0061, 0x0000};
+static const uint16_t boot_b_name[] = {0x0062, 0x006f, 0x006f, 0x0074, 0x005f,
+				       0x0062, 0x0000};
+static const uint16_t init_boot_a_name[] = {0x0069, 0x006e, 0x0069, 0x0074, 0x005f,
+					    0x0062, 0x006f, 0x006f, 0x0074, 0x005f,
+					    0x0061, 0x0000};
+static const uint16_t init_boot_b_name[] = {0x0069, 0x006e, 0x0069, 0x0074, 0x005f,
+					    0x0062, 0x006f, 0x006f, 0x0074, 0x005f,
+					    0x0062, 0x0000};
+static const uint16_t misc_name[] = {0x006d, 0x0069, 0x0073, 0x0063, 0x0000};
 
 // cgpt_common.c requires these be defined if linked in.
 const char *progname = "CGPT-TEST";
@@ -146,6 +176,7 @@ static void BuildTestGptData(GptData *gpt)
 	GptEntry *entries, *entries2;
 	Guid chromeos_kernel = GPT_ENT_TYPE_CHROMEOS_KERNEL;
 	Guid chromeos_rootfs = GPT_ENT_TYPE_CHROMEOS_ROOTFS;
+	Guid linux_data = GPT_ENT_TYPE_LINUX_FS;
 
 	gpt->sector_bytes = DEFAULT_SECTOR_SIZE;
 	gpt->streaming_drive_sectors =
@@ -166,36 +197,65 @@ static void BuildTestGptData(GptData *gpt)
 	header->my_lba = 1;
 	header->alternate_lba = DEFAULT_DRIVE_SECTORS - 1;
 	header->first_usable_lba = 34;
-	header->last_usable_lba = DEFAULT_DRIVE_SECTORS - 1 - 32 - 1;  /* 433 */
+	header->last_usable_lba = DEFAULT_DRIVE_SECTORS - 1 - 32 - 1;
 	header->entries_lba = 2;
 	  /* 512B / 128B * 32sectors = 128 entries */
 	header->number_of_entries = 128;
 	header->size_of_entry = 128;  /* bytes */
+	memcpy(&entries[0].name, &kern_a_name, sizeof(kern_a_name));
 	memcpy(&entries[0].type, &chromeos_kernel, sizeof(chromeos_kernel));
 	SetGuid(&entries[0].unique, 0);
 	entries[0].starting_lba = 34;
 	entries[0].ending_lba = 133;
+	memcpy(&entries[1].name, &root_a_name, sizeof(root_a_name));
 	memcpy(&entries[1].type, &chromeos_rootfs, sizeof(chromeos_rootfs));
 	SetGuid(&entries[1].unique, 1);
 	entries[1].starting_lba = 134;
 	entries[1].ending_lba = 232;
+	memcpy(&entries[2].name, &root_b_name, sizeof(root_b_name));
 	memcpy(&entries[2].type, &chromeos_rootfs, sizeof(chromeos_rootfs));
 	SetGuid(&entries[2].unique, 2);
 	entries[2].starting_lba = 234;
 	entries[2].ending_lba = 331;
+	memcpy(&entries[3].name, &kern_b_name, sizeof(kern_b_name));
 	memcpy(&entries[3].type, &chromeos_kernel, sizeof(chromeos_kernel));
 	SetGuid(&entries[3].unique, 3);
 	entries[3].starting_lba = 334;
 	entries[3].ending_lba = 430;
+	memcpy(&entries[4].name, &boot_a_name, sizeof(boot_a_name));
+	memcpy(&entries[4].type, &chromeos_kernel, sizeof(chromeos_kernel));
+	SetGuid(&entries[4].unique, 4);
+	entries[4].starting_lba = 434;
+	entries[4].ending_lba = 443;
+	memcpy(&entries[5].name, &boot_b_name, sizeof(boot_b_name));
+	memcpy(&entries[5].type, &chromeos_kernel, sizeof(chromeos_kernel));
+	SetGuid(&entries[5].unique, 5);
+	entries[5].starting_lba = 444;
+	entries[5].ending_lba = 453;
+	memcpy(&entries[6].name, &init_boot_a_name, sizeof(init_boot_a_name));
+	memcpy(&entries[6].type, &linux_data, sizeof(linux_data));
+	SetGuid(&entries[6].unique, 6);
+	entries[6].starting_lba = 454;
+	entries[6].ending_lba = 463;
+	memcpy(&entries[7].name, &init_boot_b_name, sizeof(init_boot_b_name));
+	memcpy(&entries[7].type, &linux_data, sizeof(linux_data));
+	SetGuid(&entries[7].unique, 7);
+	entries[7].starting_lba = 464;
+	entries[7].ending_lba = 473;
+	memcpy(&entries[8].name, &misc_name, sizeof(misc_name));
+	memcpy(&entries[8].type, &linux_data, sizeof(linux_data));
+	SetGuid(&entries[8].unique, 8);
+	entries[8].starting_lba = 474;
+	entries[8].ending_lba = 483;
 
 	/* Build secondary */
 	header2 = (GptHeader *)gpt->secondary_header;
 	entries2 = (GptEntry *)gpt->secondary_entries;
 	memcpy(header2, header, sizeof(GptHeader));
 	memcpy(entries2, entries, PARTITION_ENTRIES_SIZE);
-	header2->my_lba = DEFAULT_DRIVE_SECTORS - 1;  /* 466 */
+	header2->my_lba = DEFAULT_DRIVE_SECTORS - 1;
 	header2->alternate_lba = 1;
-	header2->entries_lba = DEFAULT_DRIVE_SECTORS - 1 - 32;  /* 434 */
+	header2->entries_lba = DEFAULT_DRIVE_SECTORS - 1 - 32;
 
 	RefreshCrc32(gpt);
 }
@@ -677,16 +737,16 @@ static int FirstUsableLbaAndLastUsableLbaTest(void)
 		int primary_rv;
 		int secondary_rv;
 	} cases[] = {
-		{2,  34, 433,   34, 433, 434,  0, 0},
-		{2,  34, 432,   34, 430, 434,  0, 0},
-		{2,  33, 433,   33, 433, 434,  1, 1},
-		{2,  34, 434,   34, 433, 434,  1, 0},
-		{2,  34, 433,   34, 434, 434,  0, 1},
-		{2,  35, 433,   35, 433, 434,  0, 0},
-		{2, 433, 433,  433, 433, 434,  0, 0},
-		{2, 434, 433,  434, 434, 434,  1, 1},
-		{2, 433,  34,   34, 433, 434,  1, 0},
-		{2,  34, 433,  433,  34, 434,  0, 1},
+		{2,  34, 483,   34, 483, 484,  0, 0},
+		{2,  34, 482,   34, 480, 484,  0, 0},
+		{2,  33, 483,   33, 483, 484,  1, 1},
+		{2,  34, 484,   34, 483, 484,  1, 0},
+		{2,  34, 483,   34, 484, 484,  0, 1},
+		{2,  35, 483,   35, 483, 484,  0, 0},
+		{2, 483, 483,  483, 483, 484,  0, 0},
+		{2, 484, 483,  484, 484, 484,  1, 1},
+		{2, 483,  34,   34, 483, 484,  1, 0},
+		{2,  34, 483,  483,  34, 484,  0, 1},
 	};
 
 	for (i = 0; i < ARRAY_SIZE(cases); ++i) {
@@ -1208,16 +1268,26 @@ static int EntryTypeTest(void)
 	GptEntry *e = (GptEntry *)(gpt->primary_entries);
 
 	memcpy(&e->type, &guid_zero, sizeof(Guid));
-	EXPECT(1 == IsUnusedEntry(e));
-	EXPECT(0 == IsKernelEntry(e));
+	EXPECT(true == IsUnusedEntry(e));
+	EXPECT(false == IsChromeOS(e));
 
 	memcpy(&e->type, &guid_kernel, sizeof(Guid));
-	EXPECT(0 == IsUnusedEntry(e));
-	EXPECT(1 == IsKernelEntry(e));
+	EXPECT(false == IsUnusedEntry(e));
+	EXPECT(true == IsChromeOS(e));
+	EXPECT(false == IsAndroid(e));
+	EXPECT(true == IsBootableEntry(e));
+
+	memcpy(&e->type, &guid_vbmeta, sizeof(Guid));
+	EXPECT(false == IsUnusedEntry(e));
+	EXPECT(false == IsChromeOS(e));
+	EXPECT(true == IsAndroid(e));
+	EXPECT(true == IsBootableEntry(e));
 
 	memcpy(&e->type, &guid_rootfs, sizeof(Guid));
-	EXPECT(0 == IsUnusedEntry(e));
-	EXPECT(0 == IsKernelEntry(e));
+	EXPECT(false == IsUnusedEntry(e));
+	EXPECT(false == IsChromeOS(e));
+	EXPECT(false == IsAndroid(e));
+	EXPECT(false == IsBootableEntry(e));
 
 	return TEST_OK;
 }
@@ -1229,10 +1299,21 @@ static void FreeEntry(GptEntry *e)
 }
 
 /* Set up an entry. */
-static void FillEntry(GptEntry *e, int is_kernel,
-		      int priority, int successful, int tries)
+static void FillEntry(GptEntry *e, enum kernel_type type, int priority, int successful,
+		      int tries)
 {
-	memcpy(&e->type, (is_kernel ? &guid_kernel : &guid_zero), sizeof(Guid));
+	switch (type) {
+	case CHROMEOS:
+		memcpy(&e->type, &guid_kernel, sizeof(Guid));
+		break;
+	case ANDROID:
+		memcpy(&e->type, &guid_vbmeta, sizeof(Guid));
+		break;
+	case NO_KERNEL:
+	default:
+		memcpy(&e->type, &guid_zero, sizeof(Guid));
+		break;
+	}
 	SetEntryPriority(e, priority);
 	SetEntrySuccessful(e, successful);
 	SetEntryTries(e, tries);
@@ -1264,8 +1345,8 @@ static int GetNextNormalTest(void)
 
 	/* Normal case - both kernels successful */
 	BuildTestGptData(gpt);
-	FillEntry(e1 + KERNEL_A, 1, 2, 1, 0);
-	FillEntry(e1 + KERNEL_B, 1, 2, 1, 0);
+	FillEntry(e1 + KERNEL_A, CHROMEOS, 2, 1, 0);
+	FillEntry(e1 + KERNEL_B, CHROMEOS, 2, 1, 0);
 	RefreshCrc32(gpt);
 	GptInit(gpt);
 
@@ -1298,10 +1379,10 @@ static int GetNextPrioTest(void)
 
 	/* Priority 3, 4, 0, 4 - should boot order B, Y, A */
 	BuildTestGptData(gpt);
-	FillEntry(e1 + KERNEL_A, 1, 3, 1, 0);
-	FillEntry(e1 + KERNEL_B, 1, 4, 1, 0);
-	FillEntry(e1 + KERNEL_X, 1, 0, 1, 0);
-	FillEntry(e1 + KERNEL_Y, 1, 4, 1, 0);
+	FillEntry(e1 + KERNEL_A, CHROMEOS, 3, 1, 0);
+	FillEntry(e1 + KERNEL_B, CHROMEOS, 4, 1, 0);
+	FillEntry(e1 + KERNEL_X, CHROMEOS, 0, 1, 0);
+	FillEntry(e1 + KERNEL_Y, CHROMEOS, 4, 1, 0);
 	RefreshCrc32(gpt);
 	GptInit(gpt);
 
@@ -1323,10 +1404,10 @@ static int GetNextTriesTest(void)
 
 	/* Tries=nonzero is attempted just like success, but tries=0 isn't */
 	BuildTestGptData(gpt);
-	FillEntry(e1 + KERNEL_A, 1, 2, 1, 0);
-	FillEntry(e1 + KERNEL_B, 1, 3, 0, 0);
-	FillEntry(e1 + KERNEL_X, 1, 4, 0, 1);
-	FillEntry(e1 + KERNEL_Y, 1, 0, 0, 5);
+	FillEntry(e1 + KERNEL_A, CHROMEOS, 2, 1, 0);
+	FillEntry(e1 + KERNEL_B, CHROMEOS, 3, 0, 0);
+	FillEntry(e1 + KERNEL_X, CHROMEOS, 4, 0, 1);
+	FillEntry(e1 + KERNEL_Y, CHROMEOS, 0, 0, 5);
 	RefreshCrc32(gpt);
 	GptInit(gpt);
 
@@ -1348,9 +1429,9 @@ static int GptUpdateTest(void)
 
 	/* Tries=nonzero is attempted just like success, but tries=0 isn't */
 	BuildTestGptData(gpt);
-	FillEntry(e + KERNEL_A, 1, 4, 1, 0);
-	FillEntry(e + KERNEL_B, 1, 3, 0, 2);
-	FillEntry(e + KERNEL_X, 1, 2, 0, 2);
+	FillEntry(e + KERNEL_A, CHROMEOS, 4, 1, 0);
+	FillEntry(e + KERNEL_B, CHROMEOS, 3, 0, 2);
+	FillEntry(e + KERNEL_X, ANDROID, 2, 0, 2);
 	RefreshCrc32(gpt);
 	GptInit(gpt);
 	gpt->modified = 0;  /* Nothing modified yet */
@@ -1605,6 +1686,66 @@ static int CheckHeaderOffDevice(void)
 	return TEST_OK;
 }
 
+static int GptFindEntryByNameTest(void)
+{
+	GptData *gpt = GetEmptyGptData();
+	Guid guid;
+	GptEntry *e;
+
+	BuildTestGptData(gpt);
+
+	e = GptFindEntryByName(gpt, "non_exist", NULL);
+	EXPECT(e == NULL);
+	e = GptFindEntryByName(gpt, "non_exist", "misc");
+	EXPECT(e == NULL);
+	e = GptFindEntryByName(gpt, "misc", "_a");
+	EXPECT(e == NULL);
+	e = GptFindEntryByName(gpt, "boot", NULL);
+	EXPECT(e == NULL);
+	e = GptFindEntryByName(gpt, "non_exist", NULL);
+	EXPECT(e == NULL);
+	e = GptFindEntryByName(gpt, "miscabcd", NULL);
+	EXPECT(e == NULL);
+	e = GptFindEntryByName(gpt, "boot", "_abcd");
+	EXPECT(e == NULL);
+	SetGuid(&guid, 4);
+	e = GptFindEntryByName(gpt, "boot", "_a");
+	EXPECT(e != NULL);
+	EXPECT(!memcmp(&e->unique, &guid, sizeof(Guid)));
+	EXPECT(e->starting_lba == 434);
+	EXPECT(GptGetEntrySizeLba(e) == 10);
+
+	SetGuid(&guid, 5);
+	e = GptFindEntryByName(gpt, "boot", "_b");
+	EXPECT(e != NULL);
+	EXPECT(!memcmp(&e->unique, &guid, sizeof(Guid)));
+	EXPECT(e->starting_lba == 444);
+	EXPECT(GptGetEntrySizeLba(e) == 10);
+
+	SetGuid(&guid, 6);
+	e = GptFindEntryByName(gpt, "init_boot", "_a");
+	EXPECT(e != NULL);
+	EXPECT(!memcmp(&e->unique, &guid, sizeof(Guid)));
+	EXPECT(e->starting_lba == 454);
+	EXPECT(GptGetEntrySizeLba(e) == 10);
+
+	SetGuid(&guid, 7);
+	e = GptFindEntryByName(gpt, "init_boot", "_b");
+	EXPECT(e != NULL);
+	EXPECT(!memcmp(&e->unique, &guid, sizeof(Guid)));
+	EXPECT(e->starting_lba == 464);
+	EXPECT(GptGetEntrySizeLba(e) == 10);
+
+	SetGuid(&guid, 8);
+	e = GptFindEntryByName(gpt, "misc", NULL);
+	EXPECT(e != NULL);
+	EXPECT(!memcmp(&e->unique, &guid, sizeof(Guid)));
+	EXPECT(e->starting_lba == 474);
+	EXPECT(GptGetEntrySizeLba(e) == 10);
+
+	return TEST_OK;
+}
+
 int main(int argc, char *argv[])
 {
 	int i;
@@ -1645,6 +1786,7 @@ int main(int argc, char *argv[])
 		{ TEST_CASE(GetKernelGuidTest), },
 		{ TEST_CASE(ErrorTextTest), },
 		{ TEST_CASE(CheckHeaderOffDevice), },
+		{ TEST_CASE(GptFindEntryByNameTest), },
 	};
 
 	for (i = 0; i < sizeof(test_cases)/sizeof(test_cases[0]); ++i) {
diff --git a/tests/futility/data_fmap2_expect_hh.txt b/tests/futility/data_fmap2_expect_hh.txt
index acbb676b..f7dcfb71 100644
--- a/tests/futility/data_fmap2_expect_hh.txt
+++ b/tests/futility/data_fmap2_expect_hh.txt
@@ -1,7 +1,7 @@
 ERROR: RO_VPD and RO_UNUSED overlap
   RO_VPD: 0x1a0000 - 0x1b0000
   RO_UNUSED: 0x1af000 - 0x200000
-# name                     start       end         size
+# name                     start       end         size  // address relative to base=0x0
 RW_PRIVATE                 003fc000    00400000    00004000
 RW_ENVIRONMENT             003fc000    00400000    00004000  // DUPLICATE
 RW_SHARED                  003f8000    003fc000    00004000
diff --git a/tests/futility/data_fmap2_expect_hhH.txt b/tests/futility/data_fmap2_expect_hhH.txt
index e95a7b1b..907248ab 100644
--- a/tests/futility/data_fmap2_expect_hhH.txt
+++ b/tests/futility/data_fmap2_expect_hhH.txt
@@ -1,7 +1,7 @@
 ERROR: RO_VPD and RO_UNUSED overlap
   RO_VPD: 0x1a0000 - 0x1b0000
   RO_UNUSED: 0x1af000 - 0x200000
-# name                     start       end         size
+# name                     start       end         size  // address relative to base=0x0
 -entire flash-             00000000    00400000    00400000
   RW_PRIVATE                 003fc000    00400000    00004000
   RW_ENVIRONMENT             003fc000    00400000    00004000  // DUPLICATE
diff --git a/tests/futility/data_fmap_expect_h.txt b/tests/futility/data_fmap_expect_h.txt
index fe31c1ed..9ab6acf8 100644
--- a/tests/futility/data_fmap_expect_h.txt
+++ b/tests/futility/data_fmap_expect_h.txt
@@ -1,4 +1,4 @@
-# name                     start       end         size
+# name                     start       end         size  // address relative to base=0x0
 SI_BIOS                    00200000    00800000    00600000
   WP_RO                      00600000    00800000    00200000
     RO_SECTION                 00610000    00800000    001f0000
diff --git a/tests/futility/test_dump_fmap.sh b/tests/futility/test_dump_fmap.sh
index c148cfa6..6b60b6a1 100755
--- a/tests/futility/test_dump_fmap.sh
+++ b/tests/futility/test_dump_fmap.sh
@@ -6,21 +6,32 @@
 me=${0##*/}
 TMP="${me}.tmp"
 
+# Set to 1 to update the expected output
+UPDATE_MODE=0
+
 # Work in scratch directory
 cd "${OUTDIR}"
 
+check_diff()
+{
+  local wantfile="$1"
+  local gotfile="$2"
+  [[ "${UPDATE_MODE}" -gt 0 ]] && cp "${gotfile}" "${wantfile}"
+  diff "${wantfile}" "${gotfile}"
+}
+
 # Good FMAP
 "${FUTILITY}" dump_fmap -F "${SCRIPT_DIR}/futility/data_fmap.bin"  > "${TMP}"
-cmp "${SCRIPT_DIR}/futility/data_fmap_expect_f.txt" "${TMP}"
+check_diff "${SCRIPT_DIR}/futility/data_fmap_expect_f.txt" "${TMP}"
 
 "${FUTILITY}" dump_fmap -p "${SCRIPT_DIR}/futility/data_fmap.bin"  > "${TMP}"
-cmp "${SCRIPT_DIR}/futility/data_fmap_expect_p.txt" "${TMP}"
+check_diff "${SCRIPT_DIR}/futility/data_fmap_expect_p.txt" "${TMP}"
 
 "${FUTILITY}" dump_fmap -h "${SCRIPT_DIR}/futility/data_fmap.bin"  > "${TMP}"
-cmp "${SCRIPT_DIR}/futility/data_fmap_expect_h.txt" "${TMP}"
+check_diff "${SCRIPT_DIR}/futility/data_fmap_expect_h.txt" "${TMP}"
 
 "${FUTILITY}" dump_fmap -e "${SCRIPT_DIR}/futility/data_fmap3.bin"  > "${TMP}"
-cmp "${SCRIPT_DIR}/futility/data_fmap_expect_e.txt" "${TMP}"
+check_diff "${SCRIPT_DIR}/futility/data_fmap_expect_e.txt" "${TMP}"
 
 
 # This should fail because the input file is truncated and doesn't really
@@ -35,24 +46,24 @@ if "${FUTILITY}" dump_fmap -x "${SCRIPT_DIR}/futility/data_fmap.bin" NO_SUCH; \
 # However, this should work.
 "${FUTILITY}" dump_fmap -x "${SCRIPT_DIR}/futility/data_fmap.bin" SI_DESC > \
   "${TMP}"
-cmp "${SCRIPT_DIR}/futility/data_fmap_expect_x.txt" "${TMP}"
+check_diff "${SCRIPT_DIR}/futility/data_fmap_expect_x.txt" "${TMP}"
 
 # Redirect dumping to a different place
 "${FUTILITY}" dump_fmap -x "${SCRIPT_DIR}/futility/data_fmap.bin" SI_DESC:FOO \
   > "${TMP}"
-cmp "${SCRIPT_DIR}/futility/data_fmap_expect_x2.txt" "${TMP}"
-cmp SI_DESC FOO
+check_diff "${SCRIPT_DIR}/futility/data_fmap_expect_x2.txt" "${TMP}"
+diff SI_DESC FOO
 
 # This FMAP has problems, and should fail.
 if "${FUTILITY}" dump_fmap -h "${SCRIPT_DIR}/futility/data_fmap2.bin" > \
   "${TMP}"; then false; fi
-cmp "${SCRIPT_DIR}/futility/data_fmap2_expect_h.txt" "${TMP}"
+check_diff "${SCRIPT_DIR}/futility/data_fmap2_expect_h.txt" "${TMP}"
 
 "${FUTILITY}" dump_fmap -hh "${SCRIPT_DIR}/futility/data_fmap2.bin" > "${TMP}"
-cmp "${SCRIPT_DIR}/futility/data_fmap2_expect_hh.txt" "${TMP}"
+check_diff "${SCRIPT_DIR}/futility/data_fmap2_expect_hh.txt" "${TMP}"
 
 "${FUTILITY}" dump_fmap -hhH "${SCRIPT_DIR}/futility/data_fmap2.bin" > "${TMP}"
-cmp "${SCRIPT_DIR}/futility/data_fmap2_expect_hhH.txt" "${TMP}"
+check_diff "${SCRIPT_DIR}/futility/data_fmap2_expect_hhH.txt" "${TMP}"
 
 
 # cleanup
diff --git a/tests/swap_ec_rw_tests.sh b/tests/swap_ec_rw_tests.sh
index 18495cee..188d6c88 100755
--- a/tests/swap_ec_rw_tests.sh
+++ b/tests/swap_ec_rw_tests.sh
@@ -29,18 +29,30 @@ echo "Testing swap_ec_rw..."
 cp -f "${AP_IMAGE}" "${TMP}"
 if "${SWAP}" -i "${TMP}"; then false; fi
 
-# Good case: no ecrw.version
+# Good case: swap from EC source (--ec), no ecrw.version
 cp -f "${AP_IMAGE}" "${TMP}"
 "${SWAP}" -i "${TMP}" -e "${EC_IMAGE}"
 cmp "${TMP}" "${DATA}/bios.expect.bin"
 
-# Good case: swap ecrw.version
+# Good case: swap from EC source (--ec), with ecrw.version
 cp -f "${AP_IMAGE}" "${TMP}"
 cbfstool "${TMP}" extract -r "FW_MAIN_A" -n ecrw.version -f "${TMPD}/v.old"
 "${SWAP}" -i "${TMP}" -e "${EC_IMAGE}"
 cbfstool "${TMP}" extract -r "FW_MAIN_A" -n ecrw.version -f "${TMPD}/v.new"
 cmp -s "${TMPD}/v.old" "${TMPD}/v.new" && error "ecrw.version was not modified"
 
+# Good case: swap from AP source (--ap_for_ec)
+# For testing purposes, AP_IMAGE has different contents between FW_MAIN_A and
+# FW_MAIN_B.  Swap the EC and EC config into the source image to create
+# a normal AP image.
+cp -f "${AP_IMAGE}" "${TMP}.source"
+echo "testing config content" > "${TMPD}/ecrw.config"
+"${SWAP}" -i "${TMP}.source" -e "${EC_IMAGE}" --ec_config "${TMPD}/ecrw.config"
+# Swap the ecrw from source image to target image.
+cp -f "${AP_IMAGE}" "${TMP}.target"
+"${SWAP}" -i "${TMP}.target" -a "${TMP}.source"
+cmp "${TMP}.target" "${TMP}.source"
+
 # Cleanup
 rm -rf "${TMPD}"
 exit 0
diff --git a/tests/vb2_inject_kernel_subkey_tests.c b/tests/vb2_inject_kernel_subkey_tests.c
index 88e126ab..4d0487de 100644
--- a/tests/vb2_inject_kernel_subkey_tests.c
+++ b/tests/vb2_inject_kernel_subkey_tests.c
@@ -155,6 +155,16 @@ void GetCurrentKernelUniqueGuid(GptData *gpt, void *dest)
 	memcpy(dest, fake_guid, sizeof(fake_guid));
 }
 
+bool IsChromeOS(const GptEntry *e)
+{
+	return true;
+}
+
+bool IsAndroid(const GptEntry *e)
+{
+	return false;
+}
+
 vb2_error_t vb2_unpack_key_buffer(struct vb2_public_key *key,
 				  const uint8_t *buf, uint32_t size)
 {
diff --git a/tests/vb2_load_kernel_tests.c b/tests/vb2_load_kernel_tests.c
index e28a0481..1f3c10d1 100644
--- a/tests/vb2_load_kernel_tests.c
+++ b/tests/vb2_load_kernel_tests.c
@@ -213,6 +213,16 @@ void GetCurrentKernelUniqueGuid(GptData *gpt, void *dest)
 	memcpy(dest, fake_guid, sizeof(fake_guid));
 }
 
+bool IsChromeOS(const GptEntry *e)
+{
+	return true;
+}
+
+bool IsAndroid(const GptEntry *e)
+{
+	return false;
+}
+
 vb2_error_t vb2_unpack_key_buffer(struct vb2_public_key *key,
 				  const uint8_t *buf, uint32_t size)
 {
diff --git a/vboot.rc b/vboot.rc
index 96a20323..66ad5082 100644
--- a/vboot.rc
+++ b/vboot.rc
@@ -1,6 +1,9 @@
 # Create and mount working paths for vboot tools.
-on post-fs-data-checkpointed
+on post-fs-data
     mkdir /data/vendor/vboot
     mkdir /data/vendor/vboot/tmp
     mount tmpfs tmpfs /data/vendor/vboot/tmp nosuid nodev noexec rw context=u:object_r:firmware_tool_data_file:s0
     restorecon /data/vendor/vboot
+
+on shutdown
+    umount /data/vendor/vboot/tmp
```

