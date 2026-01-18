#include <stdio.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define MAX_ACCEPT_BACKLOG 5

int main(){
  int client_sockfd = socket(AF_INET, SOCK_STREAM, 0);
  int port;
  char s[100];
  printf("Please enter server IP address: ");
  scanf("%s", s);
  printf("Please enter port number: ");
  scanf("%d", &port);

  struct sockaddr_in server;
  server.sin_family = AF_INET;
  server.sin_port = htons(port);
  server.sin_addr.s_addr = inet_addr(s);

  if(connect(client_sockfd, (struct sockaddr*)&server, sizeof(server)) < 0){
    perror("Connection failed");
    exit(1);
  }
  printf("Connected to server %s on port %d\n", s, port);
  char buff[1000];
  while(1)
  {
    memset(buff,0,1000);
    scanf("%s",buff);
  send(client_sockfd, buff, sizeof(buff), 0);
  }
  
  close(client_sockfd);
  return 0;
}
