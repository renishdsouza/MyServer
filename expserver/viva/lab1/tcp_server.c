#include <stdio.h>
#include <sys/socket.h>
// #include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#define PORT 5555
#define MAX_ACCEPT_BACKLOG 5

int main(){
  int server_sockfd = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in server;
  server.sin_family = AF_INET;
  server.sin_port = htons(PORT);
  server.sin_addr.s_addr = htonl(INADDR_ANY);
  
  int enable = 1;
  setsockopt(server_sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
  if(bind(server_sockfd, (struct sockaddr *) &server, sizeof(server)) < 0){
    printf("Bind failed\n");
    exit(1);
  }
  
  if(listen(server_sockfd, MAX_ACCEPT_BACKLOG) < 0){
    printf("Listen failed\n");
    exit(1);
  }

  printf("Server listening on port %d\n", PORT);

  while(1){
    struct sockaddr_in client;
    socklen_t client_len = sizeof(client);

    int client_sock_fd;
    if((client_sock_fd = accept(server_sockfd, (struct sockaddr *) &client, &client_len)) < 0){
      printf("Accept failed\n");
      exit(1);
    }
    printf("Client connected\n");
    printf("Client IP: %s\n", inet_ntoa(client.sin_addr));
    printf("Client port: %d\n", ntohs(client.sin_port));

    char buff[1000];
    while (1)
    {
      ssize_t n = recv(client_sock_fd, buff, sizeof(buff), 0);
      if (n == 0) {
        printf("[ANNOUNCEMENT] client disconnected\n");
        close(client_sock_fd);
        break;
      } else if (n < 0) {
        perror("recv failed");
        close(client_sock_fd);
        break;
      }
      printf("received %zd bytes\n", n);
      fwrite(buff, 1, n, stdout);
      if (n > 0 && buff[n-1] != '\n')
        putchar('\n');
    }
    
    
  }

}