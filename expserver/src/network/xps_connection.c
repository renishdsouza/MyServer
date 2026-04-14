#include "../xps.h"
// Function declaration for read callback of listener
void connection_loop_close_handler(void *ptr);
void connection_source_handler(void* ptr);
void connection_sink_handler(void* ptr);
void connection_source_close_handler(void* ptr);
void connection_sink_close_handler(void* ptr);
void connection_close(xps_connection_t *connection, bool peer_closed);

// Function to reverse a string
void strrev(char *str) {
  for (int start = 0, end = strlen(str) - 2; start < end; start++, end--) {
    char temp = str[start];
    str[start] = str[end];
    str[end] = temp;
  }
}

void connection_source_handler(void *ptr) {
  /*assert ptr not null*/
  assert(ptr != NULL);
  xps_pipe_source_t *source = ptr;
  xps_connection_t *connection = source->ptr;

  xps_buffer_t *buff = xps_buffer_create(DEFAULT_BUFFER_SIZE, 0, NULL);/*create buffer to read data from socket into*/
  if (buff == NULL) {
    logger(LOG_DEBUG, "connection_source_handler()", "xps_buffer_create() failed");
    return;
  }
  

  if(buff->data == NULL){
    logger(LOG_DEBUG, "connection_source_handler()", "malloc() failed for buff->data %d bytes", buff->size);
  }
  /*Read from socket using recv()*/
  ssize_t read_n = recv(connection->sock_fd, buff->data, buff->size, 0);
  logger(LOG_DEBUG, "connection_source_handler()", "recv() called to read data from client %d bytes", read_n);
  if (read_n > 0) {
    logger(LOG_DEBUG, "connection_source_handler()", "recv() read data from client");
  }
  else{
    logger(LOG_DEBUG, "connection_source_handler()", "recv() did not read any data from client");
  }
  buff->len = read_n;

  // Socket would block
  if (read_n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
    xps_buffer_destroy(buff);
    /*ready flag of source*/
    source->ready = false;
    logger(LOG_DEBUG, "connection_source_handler()", "recv() would block");
    return;
  }

  // Socket error
  if (read_n < 0) {
    /*destroy buff*/
    xps_buffer_destroy(buff);
    logger(LOG_ERROR, "connection_source_handler()", "recv() failed");
    connection_close(connection, false);
    return;
  }

  // Peer closed connection
  if (read_n == 0) {
    /*destroy buff*/
    xps_buffer_destroy(buff);
    /*close connection*/
    connection_close(connection, true);
    return;
  }

  // strrev(buff->data);

  if (/*write into pipe*/xps_pipe_source_write(source, buff) != OK) {
    logger(LOG_ERROR, "connection_source_handler()", "xps_pipe_source_write() failed");
    /*destroy buff*/
    xps_buffer_destroy(buff);
    /*close connection*/
    connection_close(connection, false);
    return;
  }
  else{
    logger(LOG_DEBUG, "connection_source_handler()", "wrote data to pipe");
  }

  xps_buffer_destroy(buff);
}

void connection_source_close_handler(void *ptr) {
  /*assert*/
  assert(ptr != NULL);
  logger(LOG_DEBUG, "connection_source_close_handler()", "source close handler called");
  xps_pipe_source_t *source = ptr;
  xps_connection_t *connection = source->ptr;

  if (source->active == false && (source->pipe == NULL || source->pipe->sink->active == false/*source not active AND sink not active*/))
  /*close connection*/
  connection_close(connection, false);
}

void connection_sink_handler(void *ptr) {
  /*assert*/
  assert(ptr != NULL);
  xps_pipe_sink_t *sink = ptr;
  xps_connection_t *connection = sink->ptr;
  if(sink->pipe->buff_list->len == 0){
    logger(LOG_DEBUG, "connection_sink_handler()", "no data to be read from pipe");
    return;
  }

  xps_buffer_t *buff = xps_pipe_sink_read(sink, sink->pipe->buff_list->len);/*read from pipe*/
  if (buff == NULL) {
    logger(LOG_ERROR, "connection_sink_handler()", "xps_pipe_sink_read() failed");
    return;
  }

  logger(LOG_DEBUG, "connection_sink_handler()", "read data from pipe to write to client %d bytes", buff->len);
  // Write to socket
  int write_n = send(connection->sock_fd, buff->data, buff->len/*fill this*/, MSG_NOSIGNAL);

  /*destroy buff*/
  xps_buffer_destroy(buff);

  // Socket would block
  if (write_n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
    /*sink made not ready*/
    sink->ready = false;
    return;
  }

  // Socket error
  if (write_n < 0) {
    logger(LOG_ERROR, "connection_sink_handler()", "send() failed");
    /*close connection*/
    connection_close(connection, false);
    return;
  }

  if (write_n == 0){
    return;
  }

  if (/*Clear write_n length from pipe buff_list*/xps_pipe_sink_clear(sink, write_n) != OK) {
    logger(LOG_ERROR, "connection_sink_handler()", "failed to clear %d bytes from sink", write_n);
  }
}

void connection_sink_close_handler(void *ptr) {
  /*assert*/
  assert(ptr != NULL);
  logger(LOG_DEBUG, "connection_sink_close_handler()", "sink close handler called");
  xps_pipe_sink_t *sink = (xps_pipe_sink_t *)ptr;
  xps_connection_t *connection = (xps_connection_t *)sink->ptr;
  logger(LOG_DEBUG, "connection_sink_close_handler()", "sink active: %d", sink->active);
  if(sink->ptr == NULL){
    logger(LOG_DEBUG, "connection_sink_close_handler()", "sink ptr is null");
  }
  logger(LOG_DEBUG, "connection_sink_close_handler()", "connection sock fd: %d", connection->sock_fd);

  logger(LOG_DEBUG, "connection_sink_close_handler()", "checking if source and sink both are not active to close connection");
  if(sink->pipe == NULL){
    logger(LOG_DEBUG, "connection_sink_close_handler()", "sink pipe is null");
  }
  if(sink->pipe->source == NULL){
    logger(LOG_DEBUG, "connection_sink_close_handler()", "sink pipe source is null");
  }
  if (/*source not active AND sink not active*/(sink->active == false) && (connection->source == NULL || connection->source->active == false)) {
    logger(LOG_DEBUG, "connection_sink_close_handler()", "source and sink both not active");
    /*close connection*/
    connection_close(connection, false);
  }
  else{
    logger(LOG_DEBUG, "connection_sink_close_handler()", "source or sink still active. not closing connection");
  }
}

void connection_close(xps_connection_t *connection, bool peer_closed) {
  /*assert*/
  assert(connection != NULL);
  logger(LOG_INFO, "connection_close()",peer_closed ? "peer closed connection" : "closing connection");
  /*destroy connection*/
  xps_connection_destroy(connection);
}
void connection_loop_close_handler(void *ptr) {
  logger(LOG_INFO, "connection_loop_close_handler()", "peer closed connection");
  assert(ptr != NULL);
  xps_connection_t *connection = (xps_connection_t *)ptr;
  connection_close(connection, true);
}

void connection_loop_read_handler(void* ptr) {
  assert(ptr != NULL);
  /*set read_ready flag to true*/
  ((xps_connection_t *)ptr)->source->ready = true;
}

void connection_loop_write_handler(void* ptr) {
  assert(ptr != NULL);
  /*set write_ready flag to true*/
  ((xps_connection_t *)ptr)->sink->ready = true;
}

void connection_write_handler(void *ptr) {
  assert(ptr != NULL);
  xps_connection_t *connection = (xps_connection_t *)ptr;

  // Check if there is data to be written
  if (connection->sink->pipe->buff_list->len == 0) {
    logger(LOG_DEBUG, "connection_loop_write_handler()", "no data to be written");
    return;
  }

  // Read data from buffer list
  xps_buffer_t *buff = xps_buffer_list_read(connection->sink->pipe->buff_list, connection->sink->pipe->buff_list->len);
  if (buff == NULL) {
    logger(LOG_ERROR, "connection_loop_write_handler()", "xps_buffer_list_read() failed");
    return;
  }

  // Write data to client
  ssize_t write_n = send(connection->sock_fd, buff->data, buff->len, 0);/* send data to client using send() */
  logger(LOG_DEBUG, "connection_loop_write_handler()", "sent data to client");
  if (write_n < 0) {
    if(errno == EAGAIN || errno == EWOULDBLOCK) {
      logger(LOG_DEBUG, "connection_loop_write_handler()", "send() would block");
      connection->sink->active = false;
      return;
    }
    else{
      logger(LOG_ERROR, "connection_loop_write_handler()", "send() failed");
      perror("Error message");
      xps_connection_destroy(connection);
      xps_buffer_destroy(buff);
      return;
    }
  }
  logger(LOG_DEBUG, "connection_loop_write_handler()", "sent %ld bytes to client", write_n);
  // Clear written data from buffer list
  if(write_n>0 && xps_buffer_list_clear(connection->sink->pipe->buff_list, write_n) < 0) {
    logger(LOG_ERROR, "connection_loop_write_handler()", "xps_buffer_list_clear() failed");
    xps_connection_destroy(connection);
    return;
  }
  logger(LOG_DEBUG, "connection_loop_write_handler()", "cleared written data from buffer list");
  xps_buffer_destroy(buff);
}

void connection_read_handler(void *ptr) {

  /* validate params */
  assert(ptr != NULL);
  xps_connection_t *connection = ptr;

  char buff[1024];
  long read_n = recv(connection->sock_fd, buff, sizeof(buff) - 1, 0);/* read data from client using recv() */


  if (read_n < 0) {
    if( errno == EAGAIN || errno == EWOULDBLOCK) {
      logger(LOG_DEBUG, "xps_connection_loop_read_handler()", "recv() would block");
      connection->source->active = false;
      return;
    }
    else{ //if error is something else
      logger(LOG_ERROR, "xps_connection_loop_read_handler()", "recv() failed");
      perror("Error message");
      xps_connection_destroy(connection);
      return;
    }
  }

  if (read_n == 0) {
    logger(LOG_INFO, "connection_loop_read_handler()", "peer closed connection");
    xps_connection_destroy(connection);
    return;
  }

  buff[read_n] = '\0';

  /* print client message */
  printf("[CLIENT MESSAGE]: %s\n", buff);

  /* reverse client message */
  strrev(buff);

  /* append reversed message to write buffer list */
  xps_buffer_t *write_buff_obj = xps_buffer_create(read_n, read_n, NULL);
  if (write_buff_obj == NULL) {
    logger(LOG_ERROR, "xps_connection_loop_read_handler()", "xps_buffer_create() failed for 'write_buff_obj'");
    xps_connection_destroy(connection);
    return;
  }
  memcpy(write_buff_obj->data, buff, read_n);
  xps_buffer_list_append(connection->source->pipe->buff_list, write_buff_obj);
  connection->source->active = true;
}

xps_connection_t *xps_connection_create(xps_core_t *core, u_int sock_fd){

  xps_connection_t *connection = malloc(sizeof(xps_connection_t));/* allocate memory dynamically */
  if (connection == NULL) {
    logger(LOG_ERROR, "xps_connection_create()", "malloc() failed for 'connection'");
    return NULL;
  }
  
  /*Create source instance*/
  connection->source = xps_pipe_source_create(connection, connection_source_handler, connection_source_close_handler);
  if (connection->source == NULL) {
    logger(LOG_ERROR, "xps_connection_create()", "xps_pipe_source_create() failed for 'connection->source'");
    free(connection);
    return NULL;
  }

  /*Create sink instance*/
  connection->sink = xps_pipe_sink_create(connection, connection_sink_handler, connection_sink_close_handler);
  if (connection->sink == NULL) {
    logger(LOG_ERROR, "xps_connection_create()", "xps_pipe_sink_create() failed for 'connection->sink'");
    xps_pipe_source_destroy(connection->source);
    free(connection);
    return NULL;
  }

  /* attach sock_fd to epoll */
  if(xps_loop_attach(core->loop, sock_fd, EPOLLIN | EPOLLOUT | EPOLLET, connection, connection_loop_read_handler, connection_loop_write_handler, connection_loop_close_handler) < 0) {
    logger(LOG_ERROR, "xps_connection_create()", "xps_loop_attach() failed");
    xps_pipe_sink_destroy(connection->sink);
    xps_pipe_source_destroy(connection->source);
    free(connection);
    return NULL;
  }

  // Init values
  connection->core = core;
  connection->sock_fd = sock_fd;
  connection->listener = NULL;
  connection->remote_ip = get_remote_ip(sock_fd);

  /* add connection to 'connections' list */
  vec_push(&core->connections, connection);

  logger(LOG_DEBUG, "xps_connection_create()", "created connection");
  return connection;

}

void xps_connection_destroy(xps_connection_t *connection) {

  /* validate params */
  assert(connection != NULL);

  /* set connection to NULL in 'connections' list */
  for(int i=0; i<connection->core->connections.length; i++){
    if(connection->core->connections.data[i] == connection){
      connection->core->connections.data[i] = NULL;
      break;
    }
  }

  /* detach connection from loop */
  xps_loop_detach(connection->core->loop, connection->sock_fd);

  /* destroy pipe sources and sinks */
  xps_pipe_sink_destroy(connection->sink);
  xps_pipe_source_destroy(connection->source);

  /* close connection socket FD */
  close(connection->sock_fd);

  /* free connection->remote_ip */
  free(connection->remote_ip);

  /* free connection instance */
  free(connection);

  logger(LOG_DEBUG, "xps_connection_destroy()", "destroyed connection");

}
