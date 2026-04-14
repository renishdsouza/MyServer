#ifndef XPS_MIME_H
#define XPS_MIME_H

#include "../xps.h"

const char *xps_get_mime(const char *file_path);

struct xps_keyval_s {
  char *key;
  char *val;
};

#endif