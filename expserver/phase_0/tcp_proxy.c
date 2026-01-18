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

int connect_upstream() {

  int upstream_sock_fd = socket(AF_INET, SOCK_STREAM, 0);/* create a upstrem socket */

  struct sockaddr_in upstream_addr;
  /* add upstream server details */
  upstream_addr.sin_addr.s_addr = hton(INADDR_ANY);
  upstream_addr.sin_family = AF_INET;
  upstream_addr.sin_port = htonl(UPSTREAM_PORT);


  connect(upstream_sock_fd,(struct sockaddr *) &upstream_addr, sizeof(upstream_addr)/* connect to upstream server */);

  return upstream_sock_fd;

}

void accept_connection(int listen_sock_fd) {

  struct sockaddr_in client_address;
  socklen_t client_address_len = sizeof(client_address);
  int conn_sock_fd = accept(listen_sock_fd, (struct sockaddr *) &client_address, &client_address_len);/* accept client connection */

  /* add conn_sock_fd to loop using loop_attach() */
  loop_attach(epoll_fd, listen_sock_fd, listen_sock_fd);

  // create connection to upstream server
  int upstream_sock_fd = connect_upstream();

  /* add upstream_sock_fd to loop using loop_attach() */
  loop_attach(epoll_fd, listen_sock_fd, listen_sock_fd);

  // add conn_sock_fd and upstream_sock_fd to routing table
  route_table[route_table_size][0] = conn_sock_fd;/* fill this */
  route_table[route_table_size][1] = listen_sock_fd;/* fill this */
  route_table_size += 1;

}

int create_loop() {
  /* return new epoll instance */ 

  /* epoll setup */
  int epoll_fd = epoll_create1(0);

  return epoll_fd;

}

void loop_attach(int epoll_fd, int fd, int events) {
  /* attach fd to epoll */
  struct epoll_event event;
  event.events = EPOLLIN;
  event.data.fd = events;/* listen socket FD */

  /* adding listening socket to epoll */
  epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd/* listen socket FD */, &event);
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

        /* accept connection */
        int client_sock_fd = accept(listen_sock_fd, (struct sockaddr *) &client_addr, &client_addr_len);

        /* add client socket to epoll */
        loop_attach(epoll_fd, client_sock_fd, client_sock_fd);

      }
      else if(curr_fd != upstream_socket) { // It is a connection socket

        /* read message from client */
        char buff[BUFF_SIZE];
        memset(buff,0,BUFF_SIZE);
        ssize_t read_n = recv(curr_fd, buff, sizeof(buff), 0);
        
        if(read_n <= 0){
          printf("[INFO] Client disconnected.\n");
          close(curr_fd);
          // break; //idk about this I think the fd gets cancelled so no need to exit for loop
        }

        // Print message from client
        printf("[CLIENT MESSAGE] %s", buff);

        /* reverse message */
        strrev(buff);

        /* send reversed message to client */
        send(curr_fd, buff, sizeof(buff), 0);

      }
    }
  }
}

int main(){
  listen_sock_fd = create_server();

  while(1){
    epoll_fd = create_loop();

    loop_attach(epoll_fd, listen_sock_fd, listen_sock_fd);

    loop_run(epoll_fd);

  }
}