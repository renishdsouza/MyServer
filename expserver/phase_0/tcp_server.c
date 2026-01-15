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

// Function to reverse a string
void strrev(char *str) {
  for (int start = 0, end = strlen(str) - 2; start < end; start++, end--) {
    char temp = str[start];
    str[start] = str[end];
    str[end] = temp;
  }
}

int main() {
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

  // Creating an object of struct socketaddr_in
  struct sockaddr_in client_addr;//for storing the data of the client.
  socklen_t client_addr_len;///client addr

  while(1){
    // Accept client connection
    // int conn_sock_fd = accept(listen_sock_fd, (struct sockaddr *)&client_addr, &client_addr_len);
    // printf("[INFO] Client connected to server\n");

    /* previous code till listen() */

    /* epoll setup */
    int epoll_fd = epoll_create1(0);
    struct epoll_event event, events[MAX_EPOLL_EVENTS];

    event.events = EPOLLIN;
    event.data.fd = listen_sock_fd;/* listen socket FD */

    /* adding listening socket to epoll */
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_sock_fd/* listen socket FD */, &event);

    while(1) {
      printf("[DEBUG] Epoll wait\n");
      int n_ready_fds = epoll_wait(epoll_fd, events, MAX_EPOLL_EVENTS, -1);

      for (int i=0; i<n_ready_fds; i++/* iterate from 0 to n_ready_fds */) {

        int curr_fd = events[i].data.fd;

        if (curr_fd == listen_sock_fd/* event is on listen socket */) {

          /* accept connection */
          int client_sock_fd = accept(listen_sock_fd, (struct sockaddr *) &client_addr, &client_addr_len);

          /* add client socket to epoll */
          
          event.data.fd = client_sock_fd;
          epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_sock_fd, &event);

        }
        else { // It is a connection socket

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
}
