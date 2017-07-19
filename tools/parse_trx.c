#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
 
#define trx_magic 0x30524448 /* "hdr0" */
#define trx_max_len 0x720000
#define trx_no_header 1 /* do not write trx header */
 
typedef struct {
    uint32_t magic; /* "hdr0" */
    uint32_t len; /* length of file including header */
    uint32_t crc32; /* 32-bit crc from flag_version to end of file */
    uint32_t flag_version; /* 0:15 flags, 16:31 version */
    uint32_t offsets[4]; /* offsets of partitions from start of header */
} trx_header;
 
 
trx_header *readtrx(char* file_path)
{
    FILE *file = fopen(file_path, "rb");
 
    trx_header *p = malloc(sizeof(trx_header));
 
    if (file != NULL)
    {
        fread(p, sizeof(trx_header), 1, file);
        fclose(file);
    }
 
    return p;
};
 
 
int main(int argc, char **argv)
{
 
    if(argc != 2)
    {
        printf("usage: parse_trx <trx filename>\n\n");
        return 0;
    }
 
    trx_header *p = readtrx(argv[1]);
 
    printf("magic:\t\t\t0x%08x\n",p->magic);
    printf("length:\t\t\t0x%08x\n",p->len);
    printf("crc32:\t\t\t0x%08x\n",p->crc32);
    printf("flags:\t\t\t\t%d\n",p->flag_version & 0xff);
    printf("version:\t\t\t%d\n",(p->flag_version >> 16));
    printf("lzma loader offset:\t0x%08x\n",p->offsets[0]);
    printf("kernel offset:\t\t0x%08x\n",p->offsets[1]);
    printf("rootfs offset:\t\t0x%08x\n",p->offsets[2]);
    printf("bin header offset:\t0x%08x\n",p->offsets[3]);
    printf("\n\n");
    printf("run commands below to extract squashfs from trx:\n");
    printf("dd if=%s skip=%d ibs=1 count=%d of=hsqs\n\n", argv[1], p->offsets[1], (p->len - p->offsets[1]));
 
    printf("unsquashfs hsqs\n");
 
    free(p);
    return 0;
 
}
