#ifndef DOWNLOADER_API_H
#define DOWNLOADER_API_H

#include <stddef.h>
#include <stdint.h>

struct download_result {
    char *data;
    size_t size;
};

#endif
