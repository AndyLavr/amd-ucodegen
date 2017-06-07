/*---------------------------------------------------------------------------
 * 
 * ucwrite.c 
 *     Copyright (c) 2017 Guenter Roeck <linux@roeck-us.net>
 *
 *---------------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

#define UCODE_MAGIC			0x00414d44
#define UCODE_EQUIV_CPU_TABLE_TYPE	0x00000000
#define UCODE_UCODE_TYPE		0x00000001

struct equiv_cpu_entry {
	u32     installed_cpu;
	u32     fixed_errata_mask;
	u32     fixed_errata_compare;
	u16     equiv_cpu;
	u16     res;
} __attribute__((packed));

struct file_header {
	u32 magic;
	u32 table_type;
	u32 size;
} __attribute__((packed));

struct section_header {
	u32 ucode_type;
	u32 ucode_size;
} __attribute__((packed));

struct microcode_header_amd {
	u32     data_code;
	u32     patch_id;
	u16     mc_patch_data_id;
	u8      mc_patch_data_len;
	u8      init_flag;
	u32	mc_patch_data_checksum;
	u32     nb_dev_id;
	u32	sb_dev_id;
	u16	processor_rev_id;
	u8	nb_rev_id;
	u8	sb_rev_id;
	u8	bios_api_rev;
	u8	reserved1[3];
	u32	match_reg[8];
} __attribute__((packed));

#define FILESIZE	(32*1024)

static void *malloc_nofail(size_t size)
{
	void *p = malloc(size);

	if (!p) {
		perror("malloc");
		exit(1);
	}
	memset(p, 0, size);
	return p;
}

int validate_mheader(struct microcode_header_amd *h, u16 proc_id)
{
	if (proc_id && (proc_id & 0xff00) != (h->processor_rev_id & 0xff00)) {
		fprintf(stderr, "Processor ID mismatch: 0x%x - 0x%x\n", proc_id,
			h->processor_rev_id);
		return 0;
	}
	if (h->processor_rev_id < 0x6000) {
		fprintf(stderr, "Bad processor ID 0x%xn", h->processor_rev_id);
		return 0;
	}
	if (h->nb_dev_id || h->sb_dev_id) {
		fprintf(stderr, "Bad dev ID NB 0x%x SB 0x%x\n",
			h->nb_dev_id, h->sb_dev_id);
		return 0;
	}
	if (h->nb_rev_id || h->sb_rev_id) {
		fprintf(stderr, "Bad rev ID NB 0x%x SB 0x%x\n",
			h->nb_rev_id, h->sb_rev_id);
		return 0;
	}
	if ((h->data_code & 0xffff) < 0x2010 ||
	    (h->data_code & 0xffff) >= 0x2100) {
		fprintf(stderr, "Bad date code 0x%xn", h->data_code);
		return 0;
	}
	return 1;
}

int main(int argc, char **argv)
{
	struct file_header fheader = { };
	char *outfile = NULL;
	FILE *fpin, *fpout;
	u16 *proc_ids;
	int num_entries;
	char *buffer;
	size_t size;
	u16 proc_id;
	int c, i;

	while ((c = getopt(argc, argv, "o:")) != -1) {
		switch(c) {
		case 'o':
			outfile = optarg;
			break;
		}
	}
	if (argc <= 1 || optind == argc) {
		fprintf(stderr, "Usage: %s [-o outfile] file ...\n", argv[0]);
		exit(1);
	}

	buffer = malloc_nofail(FILESIZE);

	num_entries = argc - optind;

	fheader.magic = UCODE_MAGIC;
	fheader.table_type = UCODE_EQUIV_CPU_TABLE_TYPE;
	fheader.size = ((num_entries + 1) & 0xfffe) * sizeof(struct equiv_cpu_entry);

	/*
	 * Stage 1:
	 * Read microcode headers from provided file names, and validate
	 * as much as possible.
	 */

	proc_ids = malloc_nofail(sizeof(u16) * num_entries);
	proc_id = 0;
	for (i = 0; i < num_entries; i++) {
		struct microcode_header_amd mheader;

		fpin = fopen(argv[optind + i], "r");
		if (!fpin) {
	    		perror(argv[optind + i]);
	    		exit(1);
		}
		size = fread(&mheader, 1, sizeof(mheader), fpin);
		if (size != sizeof(mheader)) {
			perror(argv[optind + i]);
			exit(1);
		}
		fclose(fpin);

		if (!validate_mheader(&mheader, proc_id))
			exit(1);
		proc_id = proc_ids[i] = mheader.processor_rev_id;
	}

	/*
	 * Stage 2:
	 * Generate default output filename unless provided. The generated file
	 * name matches the file name expected in /usr/lib/firmware/amd-ucode.
	 */
	if (!outfile) {
		outfile = malloc_nofail(32);
		sprintf(outfile, "microcode_amd_fam%02xh.bin",
			((proc_id >> 12) & 0x0f) + 0x0f);
	}

	/*
	 * Stage 3a:
	 * Write container header
	 */
	fpout = fopen(outfile, "w");
	if (!fpout) {
		perror(outfile);
		exit(1);
	}
	fwrite(&fheader, sizeof(fheader), 1, fpout);

	/*
	 * Stage 3b:
	 * Write directory of microcode blobs in container
	 */
	for (i = 0; i < num_entries; i++) {
		struct equiv_cpu_entry equiv = { };

		equiv.installed_cpu = ((proc_ids[i] & 0xff00) << 8) | 0x0f00 | (proc_ids[i] & 0xff);
		equiv.equiv_cpu = proc_ids[i];

		printf("CPU type 0x%x [0x%x], file %s\n",
		       equiv.installed_cpu, equiv.equiv_cpu, argv[optind + i]);

		fwrite(&equiv, sizeof(equiv), 1, fpout);
	}

	/*
	 * Stage 3c:
	 * Align directory size to even number of entries
	 */
	if (num_entries & 1) {
		struct equiv_cpu_entry equiv = { };

		fwrite(&equiv, sizeof(equiv), 1, fpout);
	}

	/*
	 * Stage 4: Write microcode blobs.
	 * Each blob has an 8-byte section header, followed by
	 * the actual microcode.
	 */
	for (i = 0; i < num_entries; i++) {
		struct section_header sheader = { };

		fpin = fopen(argv[optind + i], "r");
		if (!fpin) {
	    		perror(argv[optind + i]);
	    		exit(1);
		}
		size = fread(buffer, 1, FILESIZE, fpin);
		if (size < 0) {
			perror(argv[optind + i]);
			exit(1);
		}
		fclose(fpin);

		sheader.ucode_type = UCODE_UCODE_TYPE;
		sheader.ucode_size = size;

		fwrite(&sheader, sizeof(sheader), 1, fpout);
		fwrite(buffer, 1, size, fpout);
	}

	fclose(fpout);
}
