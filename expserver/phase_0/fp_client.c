#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

#define BUFF_SIZE 100000

void send_file(int conn_sock_fd){
  // Open the file from the data is being read
  FILE *fp;
  const char *filename="t1.txt";
  fp = fopen(filename, "r");
  if (fp == NULL) {
    perror("[-]Error in opening file.");
    exit(1);
  }
  char data[BUFF_SIZE];
  memset(data, 0, BUFF_SIZE);
  printf("[INFO] Sending data to server...\n");

  while (fgets(data, BUFF_SIZE, fp) != NULL) {
    if (send(conn_sock_fd, data, sizeof(data), 0/* fill this */) == -1) {
      perror("[-]Error in sending data.");
      fclose(fp/* fill this */); // Ensure file is closed on error
      exit(1);
    }
    printf("[FILE DATA] %s", data);
    bzero(data, BUFF_SIZE); // clear the buffer
  }
  printf("[INFO] File data sent successfully.\n");
  fclose(fp/* fill this */); // Close the file after sending
}

int main(){
  int conn_sock_fd = socket(AF_INET, SOCK_STREAM, 0);

  struct sockaddr_in server_addr;
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(8080);

  connect(conn_sock_fd, (struct sockaddr *) &server_addr, sizeof(server_addr));

  send_file(conn_sock_fd);

  return 0;

}