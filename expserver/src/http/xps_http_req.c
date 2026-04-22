#include "../xps.h"

int http_process_request_line(xps_http_req_t *http_req, xps_buffer_t *buff) {
	int error = xps_http_parse_request_line(http_req, buff);/*parse request line*/
  if (error != OK){
    return error;
  }
  http_req->request_line = str_from_ptrs(http_req->request_line_start, http_req->request_line_end);
  printf("Request line: %s\n", http_req->request_line);
  /*similarly assign method, uri, schema, host, path, pathname*/
  http_req->method = str_from_ptrs(http_req->method_start, http_req->method_end);
  printf("Method: %s\n", http_req->method);
  http_req->uri = str_from_ptrs(http_req->uri_start, http_req->uri_end);
  printf("URI: %s\n", http_req->uri);
  if(http_req->schema_start != NULL && http_req->schema_end != NULL){
    http_req->schema = str_from_ptrs(http_req->schema_start, http_req->schema_end);
    printf("Schema: %s\n", http_req->schema);
  }
  else{
    printf("Schema: NULL\n");
  }
  if(http_req->host_start != NULL && http_req->host_end != NULL){
    http_req->host = str_from_ptrs(http_req->host_start, http_req->host_end);
    printf("Host: %s\n", http_req->host);
  }
  else{
    printf("Host: NULL\n");
  }
  http_req->port = -1;
  if(http_req->port_start != NULL && http_req->port_end != NULL){
    char *port_str = str_from_ptrs(http_req->port_start, http_req->port_end);
    if(port_str != NULL){
      http_req->port = atoi(port_str);
      free(port_str);
    }
  }
  else{
    if(http_req->schema != NULL && strcmp(http_req->schema, "https") == 0){
      http_req->port = 443;
    }
    else{
      http_req->port = 80;
    }
  }
  printf("Port: %d\n", http_req->port);
  if(http_req->path_start != NULL && http_req->path_end != NULL){
    http_req->path = str_from_ptrs(http_req->path_start, http_req->path_end);
    printf("Path: %s\n", http_req->path);
  }
  else{
    printf("Path: NULL\n");
  }
  if(http_req->pathname_start != NULL && http_req->pathname_end != NULL){
    http_req->pathname = str_from_ptrs(http_req->pathname_start, http_req->pathname_end);
    printf("Pathname: %s\n", http_req->pathname);
  }
  else{
    printf("Pathname: NULL\n");
  }

  http_req->http_version = str_from_ptrs(http_req->http_major, http_req->http_minor+1);
  /*find port_str from port start and end pointers*/
  /*if port_str is null assign default port number 80 for http and 443 for https
  if not null assign atoi(port_str)*/
  /*free port_str*/
  printf("HTTP Version: %s\n", http_req->http_version);
  return OK;
}

int http_process_headers(xps_http_req_t *http_req, xps_buffer_t *buff) {
  /*assert*/
  assert(http_req != NULL);
  assert(buff != NULL);
  /*initialize headers list of http_req*/
  vec_init(&http_req->headers);
  int error;
  while (1) {
    error = xps_http_parse_header_line(http_req, buff);/*parse header*/
    if (error == E_FAIL){
      return E_FAIL;
    }
    if(error == E_AGAIN){
      break;
    }
    if (error == OK || error == E_NEXT) {
      /* Alloc memory for new header*/
      xps_keyval_t *header = malloc(sizeof(*header));
      if(header == NULL){
        logger(LOG_ERROR, "http_process_headers()", "malloc() failed for 'header'");
        for(int i=0; i<http_req->headers.length; i++/*traverse through headers list of http_req*/){
          xps_keyval_t *header = (http_req->headers.data[i])/*fill this*/;
          free(header->key);
          free(header->val);
          free(header);
        }
        vec_deinit(&http_req->headers);
        return E_FAIL;
      }
      /*assign key,val from their corresponding start and end pointers*/
      header->key = str_from_ptrs(http_req->header_key_start, http_req->header_key_end);
      header->val = str_from_ptrs(http_req->header_val_start, http_req->header_val_end);
      /*push this header into headers list of http_req*/
      vec_push(&http_req->headers, header);
      /*if error is E_NEXT continue*/
      if(error == E_NEXT){
        continue;
      }
      break;
    }
    /*error occurs, thus iterate through header list, free each header*/
    printf("HEADERS\n");
    for(int i=0; i<http_req->headers.length; i++/*traverse through headers list of http_req*/){
      xps_keyval_t *header = (http_req->headers.data[i]);
      printf("%s: %s\n", header->key, header->val);
    }

		return OK;
  }
  /*deinitialize headers list*/
}

xps_buffer_t *xps_http_req_serialize(xps_http_req_t *http_req) {
  assert(http_req != NULL);
  /* Serialize headers into a buffer headers_str*/
  xps_buffer_t *headers_str = xps_http_serialize_headers(&http_req->headers);
  size_t final_len = strlen(http_req->request_line) + 1 + headers_str->len + 1;   /*Calculate length for final buffer*/
  /*Create instance for final buffer*/
  xps_buffer_t *buff = malloc(sizeof(xps_buffer_t));
  buff->pos = buff->data;
  /*Copy everything to final buffer*/
  memcpy(buff->pos, http_req->request_line, strlen(http_req->request_line));
  buff->pos += strlen(http_req->request_line);
  /*similarly copy "\n", headers_str, "\n"*/
  *buff->pos = '\n';
  buff->pos += 1;
  buff->len = final_len;
	/*destroy headers_str buffer*/
  xps_buffer_destroy(headers_str);
  buff->pos = buff->data;
  return buff;
}

xps_http_req_t *xps_http_req_create(xps_core_t *core, xps_buffer_t *buff, int *error) {
	/*assert*/
  *error = E_FAIL;
	/* Alloc memory for http_req instance*/
  xps_http_req_t *http_req = malloc(sizeof(*http_req));
  if (!http_req) {
    logger(LOG_ERROR, "xps_http_req_create()", "malloc() failed for 'http_req'");
    return NULL;
  }
  memset(http_req, 0, sizeof(xps_http_req_t));
	/*Set initial parser state*/
  http_req->parser_state = RL_START;
  /*Process request line and handle possible errors*/
  int err = http_process_request_line(http_req, buff);
  if (err != OK) {
    logger(LOG_ERROR, "xps_http_req_create()", "http_process_request_line() failed with error code %d", err);
    free(http_req);
    *error = HTTP_BAD_REQUEST;
    return NULL;
  }
  logger(LOG_DEBUG, "xps_http_req_create()", "processed request line successfully");
  /*Process headers and handle possible errors*/
  err = http_process_headers(http_req, buff);
  if (err != OK) {
    logger(LOG_ERROR, "xps_http_req_create()", "http_process_headers() failed with error code %d", err);
    *error = HTTP_BAD_REQUEST;
    free(http_req);
    return NULL;
  }
  logger(LOG_DEBUG, "xps_http_req_create()", "processed headers successfully");
	// Header length
  http_req->header_len = (size_t)(buff->pos - buff->data);
	// Body length is retrieved from header Content-Length
  http_req->body_len = 0;
  const char *body_len_str = xps_http_get_header(&http_req->headers, "Content-Length");/*get header value for key Content-Length*/
  if (body_len_str != NULL) {
    http_req->body_len = atoi(body_len_str);
  }

  /* Host header is mandatory in HTTP/1.1 */
  const char *host_str = xps_http_get_header(&http_req->headers, "Host");
  if (host_str == NULL) {
    logger(LOG_ERROR, "xps_http_req_create()", "Host header is missing");
    *error = HTTP_BAD_REQUEST;
    free(http_req);
    return NULL;
  }

  /*assign body_len*/
	*error = OK;
	return http_req;
}

void xps_http_req_destroy(xps_core_t *core, xps_http_req_t *http_req) {
  assert(http_req != NULL);
  /*Frees memory allocated for various components of the HTTP request line(request line, method,etc)*/
  free(http_req->request_line);
  free(http_req->method);
  free(http_req->uri);
  if(http_req->schema != NULL){
    free(http_req->schema);
  }
  if(http_req->host != NULL){
    free(http_req->host);
  }
  if(http_req->path != NULL){
    free(http_req->path);
  }
  if(http_req->pathname != NULL){
    free(http_req->pathname);
  }
  free(http_req->http_version);
  /*iterate through the headers list of http_req and free the memory*/
  for(int i=0; i<http_req->headers.length; i++/*traverse through headers list of http_req*/){
    xps_keyval_t *header = (http_req->headers.data[i])/*fill this*/;
    free(header->key);
    free(header->val);
    free(header);
  }
  /*de-intialize the headers list*/
  vec_deinit(&http_req->headers);
  /*free http_req*/
  free(http_req);
}