#include "../xps.h"

void file_source_handler(void *ptr);
void file_source_close_handler(void *ptr);

static char *resolve_public_path(void) {
  char *resolved_public = realpath("public", NULL);
  if (resolved_public != NULL)
    return resolved_public;

  return realpath("../public", NULL);
}

static char *resolve_file_path(const char *file_path) {
  char *resolved = realpath(file_path, NULL);
  if (resolved != NULL)
    return resolved;

  if (file_path[0] == '/')
    return NULL;

  char alt_path[PATH_MAX];
  int written = snprintf(alt_path, sizeof(alt_path), "../%s", file_path);
  if (written <= 0 || written >= (int)sizeof(alt_path))
    return NULL;

  return realpath(alt_path, NULL);
}

xps_file_t *xps_file_create(xps_core_t *core, const char *file_path, int *error) {
  /*assert*/
  assert(core != NULL);
  assert(file_path != NULL);
  assert(error != NULL);

  *error = E_FAIL;
  /*check if file is inside the public directory*/
  char *resolved_path = resolve_file_path(file_path);
  char *resolved_public = resolve_public_path();/*find realpath of "../public"*/

  if (resolved_path == NULL || resolved_public == NULL) {
    logger(LOG_ERROR, "xps_file_create()", "realpath() failed");
    /*free both path*/
    free(resolved_path);
    /*close file object*/
    free(resolved_public);
    return NULL;
  }

  size_t public_len = strlen(resolved_public);
  bool inside_public = strncmp(resolved_path, resolved_public, public_len) == 0 && (resolved_path[public_len] == '/' || resolved_path[public_len] == '\0');

  if (!inside_public) {
    logger(LOG_WARNING, "xps_file_create()", "file requested is outside of public directory");
    *error = E_PERMISSION;
    /*free both path*/
    free(resolved_path);
    /*close file object*/
    free(resolved_public);
    return NULL;
  }

  /*free both path*/

  /*check if others have read permission*/
  struct stat file_stat;
  if (stat(file_path, &file_stat) != 0) {
    logger(LOG_ERROR, "xps_file_create()", "stat() failed");
    perror("Error message");
    /*close file object*/
    free(resolved_path);
    free(resolved_public);
    return NULL;
  }

  if (!(file_stat.st_mode & S_IROTH)) {
    logger(LOG_WARNING, "xps_file_create()", "others do not have read permission");
    *error = E_PERMISSION;
    /*close file object*/
    free(resolved_path);
    free(resolved_public);
    return NULL;
  }

  // Getting size of file from stat (already called above)
  long temp_size = file_stat.st_size;

  // Opening file
  FILE *file_struct = fopen(file_path, "rb");
  /*handle EACCES,ENOENT or any other error*/
  if (file_struct == NULL) {
    if(errno == EACCES) {
      logger(LOG_ERROR, "xps_file_create()", "fopen() failed with EACCES");
      *error = E_PERMISSION;
    } else if (errno == ENOENT) {
      logger(LOG_ERROR, "xps_file_create()", "fopen() failed with ENOENT");
    } else {
      logger(LOG_ERROR, "xps_file_create()", "fopen() failed with unknown error");
    }
    /*logs EACCES,ENOENT or any other error*/
    free(resolved_path);
    free(resolved_public);
    return NULL;
  }

  const char *mime_type = xps_get_mime(resolved_path);/*get mime type*/

  /*Alloc memory for instance of xps_file_t*/
  xps_file_t *file = malloc(sizeof(xps_file_t));
  if(file == NULL) {
    logger(LOG_ERROR, "xps_file_create()", "malloc() failed for xps_file_t");
    /*close file_struct and return*/
    fclose(file_struct);
    free(resolved_path);
    free(resolved_public);
    return NULL;
  }
  xps_pipe_source_t *source =
    xps_pipe_source_create((void *)file, file_source_handler, file_source_close_handler);
  /*if source is null, close file_struct and return*/
  if(source == NULL) {
    logger(LOG_ERROR, "xps_file_create()", "xps_pipe_source_create() failed");
    /*close file_struct and return*/
    fclose(file_struct);
    free(resolved_path);
    free(resolved_public);
    free(file);
    return NULL;
  }

  // Init values
  source->ready = true;
  /*initialise the fields of file instance*/
  file->file_struct = file_struct;
  file->size = (size_t)file_stat.st_size;
  file->mime_type = mime_type;
  file->source = source;
  file->core = core;
  file->file_path = resolved_path;

	*error = OK;

  logger(LOG_DEBUG, "xps_file_create()", "created file");

  return file;
}

void xps_file_destroy(xps_file_t *file) {
  /*assert*/
  assert(file != NULL);

  /*fill as mentioned above*/
  if(file->file_struct != NULL) {
    fclose(file->file_struct);
  }

  if(file->source != NULL) {
    /*close source*/
    xps_pipe_source_destroy(file->source);
  }

  free((void *)file->file_path);
  free(file);

  logger(LOG_DEBUG, "xps_file_destroy()", "destroyed file struct");
}

void file_source_handler(void *ptr) {
  /*assert*/
  assert(ptr != NULL);

  xps_pipe_source_t *source = ptr;
  xps_file_t *file = (xps_file_t *)source->ptr;
  /*get file from source ptr*/

  /*create buffer and handle any error*/
  xps_buffer_t *buff = xps_buffer_create(DEFAULT_PIPE_BUFF_THRESH, 0, NULL);
  if (buff == NULL) {
    logger(LOG_ERROR, "file_source_handler()", "xps_buffer_create() failed");
    /*close file_struct and return*/
    fclose(file->file_struct);
    return;
  }

  // Read from file
  size_t read_n = fread(buff->data, 1, buff->size, file->file_struct);
  buff->len = read_n;

  // Checking for read errors
  if (ferror(file->file_struct)) {
	  /*deallocate buff, file_struct and return*/
    logger(LOG_ERROR, "file_source_handler()", "fread() failed");
    xps_buffer_destroy(buff);
    xps_file_destroy(file);
    return;
  }

  // If end of file reached
  if (read_n == 0 && feof(file->file_struct)) {
    /*deallocate buff, file_struct and return*/
    logger(LOG_INFO, "file_source_handler()", "end of file reached");
    xps_buffer_destroy(buff);
    xps_file_destroy(file);
    return;
  }

  /*Write to pipe form buff*/
  if(xps_pipe_source_write(source, buff) != OK) {
    logger(LOG_ERROR, "file_source_handler()", "xps_pipe_source_write() failed");
    /*deallocate buff, file_struct and return*/
    xps_buffer_destroy(buff);
    return;
  }
	/*deallocate buff*/
  xps_buffer_destroy(buff);
}

void file_source_close_handler(void *ptr) {
  /*assert*/
  assert(ptr != NULL);
	xps_pipe_source_t *source = ptr;
  /*get file from source ptr*/
  xps_file_t *file = (xps_file_t *)source->ptr;
	/*deallocate file object*/
  xps_file_destroy(file);
}