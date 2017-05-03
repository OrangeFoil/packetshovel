#pragma once
#include <unistd.h>

int base64encode(const void *data_buf, size_t dataLength, char *result,
                 size_t resultSize);