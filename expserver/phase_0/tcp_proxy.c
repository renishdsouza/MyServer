#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/epoll.h>

#define PORT 8080
#define BUFF_SIZE 10000
#define MAX_ACCEPT_BACKLOG 5
#define MAX_EPOLL_EVENTS 10
#define UPSTREAM_PORT 3000
#define MAX_SOCKS 10

int listen_sock_fd, epoll_fd;
struct epoll_event events[MAX_EPOLL_EVENTS];
int route_table[MAX_SOCKS][2], route_table_size = 0; //Define MAX_SOCKS=10 as a global variable

// Function to reverse a string
void strrev(char *str) {
  for (int start = 0, end = strlen(str) - 2; start < end; start++, end--) {
    char temp = str[start];
    str[start] = str[end];
    str[end] = temp;
  }
}

int find_socket(int in_fd, int type){
  if(!type){
    for(int i=0; i<route_table_size; i++){
      if(route_table[i][0] == in_fd){
        return route_table[i][1];
      }
    }
  }
  else{
    for(int i=0; i<route_table_size; i++){
      if(route_table[i][1] == in_fd){
        return route_table[i][0];
      }
    }
  }
  return -1;
}

void loop_attach(int epoll_fd, int fd, int events) {
  /* attach fd to epoll */
  struct epoll_event event;
  event.events = events;
  event.data.fd = fd;/* listen socket FD */

  /* adding listening socket to epoll */
  epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd/* listen socket FD */, &event);
}

int connect_upstream() {

  int upstream_sock_fd = socket(AF_INET, SOCK_STREAM, 0);/* create a upstrem socket */

  struct sockaddr_in upstream_addr;
  /* add upstream server details */
  upstream_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  upstream_addr.sin_family = AF_INET;
  upstream_addr.sin_port = htons(UPSTREAM_PORT);

  connect(upstream_sock_fd,(struct sockaddr *) &upstream_addr, sizeof(upstream_addr)/* connect to upstream server */);

  return upstream_sock_fd;

}

void accept_connection(int listen_sock_fd) {

  struct sockaddr_in client_address;
  socklen_t client_address_len = sizeof(client_address);
  int conn_sock_fd = accept(listen_sock_fd, (struct sockaddr *) &client_address, &client_address_len);/* accept client connection */

  /* add conn_sock_fd to loop using loop_attach() */
  loop_attach(epoll_fd, conn_sock_fd, EPOLLIN);

  // create connection to upstream server
  int upstream_sock_fd = connect_upstream();

  /* add upstream_sock_fd to loop using loop_attach() */
  loop_attach(epoll_fd, upstream_sock_fd, EPOLLIN);

  // add conn_sock_fd and upstream_sock_fd to routing table
  route_table[route_table_size][0] = conn_sock_fd;/* fill this */
  route_table[route_table_size][1] = upstream_sock_fd;/* fill this */
  route_table_size += 1;

}

int create_loop() {
  /* return new epoll instance */ 

  /* epoll setup */
  int epoll_fd = epoll_create1(0);

  return epoll_fd;

}

int create_server() {
  /* create listening socket and return it */
  // Creating listening sock
  int listen_sock_fd = socket(AF_INET, SOCK_STREAM, 0);//AF_INET means IPv4. Sock stream is byte stream and 0 decides default here tcp.

  // Setting sock opt reuse addr
  int enable = 1;
  setsockopt(listen_sock_fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));//for making the socket reusable ie upon stopping it stays in wait to avoid confusion and finish nicely. We are asking to ignore that and reuse it.

  // Creating an object of struct socketaddr_in
  struct sockaddr_in server_addr;

  // Setting up server addr
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);//INADDR_ANY says my ip is anything and everything os says it to be, can be multiple will accpet in all as long as port number is correct.
  server_addr.sin_port = htons(PORT);

  // Binding listening sock to port
  bind(listen_sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));

  // Starting to listen
  listen(listen_sock_fd, MAX_ACCEPT_BACKLOG);//accept how much ever you can.
  printf("[INFO] Server listening on port %d\n", PORT);

  return listen_sock_fd;
}

void handle_client(int conn_sock_fd) {

  char buff[BUFF_SIZE];
  memset(buff, 0, BUFF_SIZE);
  int read_n = recv(conn_sock_fd, buff, sizeof(buff), 0);/* read message from client to buffer using recv */

  // client closed connection or error occurred
  if (read_n <= 0) {
    close(conn_sock_fd);
    return;
  }

  /* print client message (helpful for Milestone #2) */
  printf("[INFO] Client message %s\n", buff);

  /* find the right upstream socket from the route table */
  int up_fd = find_socket(conn_sock_fd, 0);

  // sending client message to upstream
  int bytes_written = 0;
  int message_len = read_n;
  while (bytes_written < message_len) {
    int n = send(up_fd/* found upstream socket */, buff + bytes_written, message_len - bytes_written, 0);
    bytes_written += n;
  }

}

void handle_upstream(int upstream_sock_fd) {

  char buff[BUFF_SIZE];
  memset(buff, 0, BUFF_SIZE);
  int read_n = recv(upstream_sock_fd, buff, sizeof(buff), 0);/* read message from upstream to buffer using recv */

  // Upstream closed connection or error occurred
  if (read_n <= 0) {
    close(upstream_sock_fd);
    return;
  }

  /* find the right client socket from the route table */
  int down_fd = find_socket(upstream_sock_fd, 1);

  /* send upstream message to client */
  int bytes_written = 0;
  int message_len = read_n;
  while(bytes_written < message_len){
    int n = send(down_fd, buff+bytes_written, message_len-bytes_written, 0);
    bytes_written += n;
  }

}

void loop_run(int epoll_fd) {
  /* infinite loop and processing epoll events */

  // Creating an object of struct socketaddr_in
  struct sockaddr_in client_addr;//for storing the data of the client.
  socklen_t client_addr_len;//client addr

  struct epoll_event event;

  while(1) {
    printf("[DEBUG] Epoll wait\n");
    int n_ready_fds = epoll_wait(epoll_fd, events, MAX_EPOLL_EVENTS, -1);

    for (int i=0; i<n_ready_fds; i++/* iterate from 0 to n_ready_fds */) {

      int curr_fd = events[i].data.fd;

      if (curr_fd == listen_sock_fd/* event is on listen socket */) {
        accept_connection(curr_fd);
      }
      else if(find_socket(curr_fd, 0) >= 0) { // It is a connection socket
        handle_client(curr_fd);
      }
      else{// event is on upstream socket
        handle_upstream(curr_fd);
      }
    }
  }
}

int main(){
  listen_sock_fd = create_server();
  epoll_fd = create_loop();
  loop_attach(epoll_fd, listen_sock_fd, EPOLLIN);
  loop_run(epoll_fd);
  return 0;
}