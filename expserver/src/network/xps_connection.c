#include "../xps.h"
// Function declaration for read callback of listener
void connection_loop_close_handler(void *ptr);
void connection_loop_write_handler(void *ptr);
void connection_loop_read_handler(void *ptr);


// Function to reverse a string
void strrev(char *str) {
  for (int start = 0, end = strlen(str) - 2; start < end; start++, end--) {
    char temp = str[start];
    str[start] = str[end];
    str[end] = temp;
  }
}

void connection_close_handler(void *ptr) {
  assert(ptr != NULL);
  xps_connection_t *connection = (xps_connection_t *)ptr;
  logger(LOG_INFO, "connection_loop_close_handler()", "peer closed connection");
  xps_connection_destroy(connection);
}

void connection_loop_read_handler(void* ptr) {
    assert(ptr != NULL);
	  /*set read_ready flag to true*/
    ((xps_connection_t *)ptr)->read_ready = true;
}

void connection_loop_write_handler(void* ptr) {
    assert(ptr != NULL);
   /*set write_ready flag to true*/
    ((xps_connection_t *)ptr)->write_ready = true;
}

void connection_write_handler(void *ptr) {
  assert(ptr != NULL);
  xps_connection_t *connection = (xps_connection_t *)ptr;

  // Check if there is data to be written
  if (connection->write_buff_list->len == 0) {
    logger(LOG_DEBUG, "connection_loop_write_handler()", "no data to be written");
    return;
  }

  // Read data from buffer list
  xps_buffer_t *buff = xps_buffer_list_read(connection->write_buff_list, connection->write_buff_list->len);
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
      connection->write_ready = false;
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
  if(write_n>0 && xps_buffer_list_clear(connection->write_buff_list, write_n) < 0) {
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
    logger(LOG_ERROR, "xps_connection_loop_read_handler()", "recv() failed");
    perror("Error message");
    if( errno == EAGAIN || errno == EWOULDBLOCK) {
      logger(LOG_DEBUG, "xps_connection_loop_read_handler()", "recv() would block");
      connection->read_ready = false;
      return;
    }
    else{ //if error is something else
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
  memcpy(write_buff_obj->data, buff, read_n);
  if (write_buff_obj == NULL) {
    logger(LOG_ERROR, "xps_connection_loop_read_handler()", "xps_buffer_create() failed for 'write_buff_obj'");
    return;
  }
  xps_buffer_list_append(connection->write_buff_list, write_buff_obj);


}

xps_connection_t *xps_connection_create(xps_core_t *core, u_int sock_fd){

  xps_connection_t *connection = malloc(sizeof(xps_connection_t));/* allocate memory dynamically */
  if (connection == NULL) {
    logger(LOG_ERROR, "xps_connection_create()", "malloc() failed for 'connection'");
    return NULL;
  }

  connection->write_buff_list = xps_buffer_list_create();
  if (connection->write_buff_list == NULL) {
    logger(LOG_ERROR, "xps_connection_create()", "xps_buffer_list_create() failed");
    free(connection);
    return NULL;
  }

  /* attach sock_fd to epoll */
  xps_loop_attach(core->loop, sock_fd, EPOLLIN | EPOLLOUT | EPOLLET, connection, connection_read_handler, connection_write_handler, connection_loop_close_handler);

  // Init values
  connection->core = core;
  connection->sock_fd = sock_fd;
  connection->listener = NULL;
  connection->remote_ip = get_remote_ip(sock_fd);
  connection->read_ready = false;
  connection->write_ready = false;
  connection->send_handler = connection_write_handler;
  connection->recv_handler = connection_read_handler;

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

  /* close connection socket FD */
  close(connection->sock_fd);

  /* free connection->remote_ip */
  free(connection->remote_ip);

  /* free connection instance */
  free(connection);

  logger(LOG_DEBUG, "xps_connection_destroy()", "destroyed connection");

}
