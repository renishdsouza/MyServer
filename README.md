# MyServer
As part of Networks lab course, an attempt to construct a server from scratch in C.
# https://expserver.github.io
All documentaion is in the above website. The project is constructed based on the guidelines in this website.
For any clarification/issue/suggestion do create an issue and/or contact me via email at renishdsouza2005@gmail.com.
Do submit an pull request if you have done any work.
# Thankyou !!!

### Isuues with vec library
The vec_find function needs the same input as the array type i.e. You can't send a comparision function. So just use for loop.
### Issues in phase 0
netcat with -u flag(to send an udp datagram) uses ipv6 if the ip is sent as localhost which is not supported by our code.

### Issues in stage_6
Do not send INADDR_ANY when calling from main function to create listener as it won't be accepted. Send 0.0.0.0 as a string.

We need to include "../xps.h in all of the c files that we create. Also the libraries fcntl.h and errno.h need to be added.

In utils #define OK 0 and #define E_FAIL -1 need to be added.

void strrev(char *str) {
    int len = strlen(str);
    int start = 0;
    int end = len - 1;
    
    // Check if last char is newline
    if (len > 0 && str[end] == '\n') {
        end--;  // Don't reverse the newline
    }

    while (start < end) {
        char temp = str[start];
        str[start++] = str[end];
        str[end--] = temp;
    }
}
use this to make the tester work

### Issues in stage_7
You change some functions in .h files. The parameters are now changed, so change them in .c also. xps_listener_create. Remove epoll and make it core.
The build.sh is also incomplete add new files or use this gcc -g -o xps $(find . -name "*.c")

### Issues in stage_8
Add structs and typedef for xps_buffer and include path to xps_buffer.h in xps.h.
The make_socket_non_blocking function is already present.

docker compose use colon instead of hyphen 
When we use docker the containers will not work when using localhost.
Create .env.prod and copy the contents of.env.example in backend.
for the backend path just do pwd and paste

### Issues in stage_9
We are pushing into global listeners twice and because of this even after the epoll modification we are still getting high CPU usage.
As we are pushing it in xps_poll_attach, we do not need to push seperately in xps_listener_create.  // vec_push(&core->listeners, listener);
Many will get a doubt here why is my laptop crashing or the kernel is stopping xps saying oom issue.
Htop will show that memory is going to the max allowable ram capacity.
All this for a 4MB file. The size of the file does not matter.
The issue is in sender.c. In the code the while loop is like this.
while (1) {
printf("Enter message to send: ");
fgets(input, BUFFER_SIZE, stdin);

    // Send message to the server
    int send_result = send(sock, input, strlen(input), 0);
    if (send_result == -1)
      perror("Send failed");
    else
      printf("Message sent to server\n");

}
fgets reads from stdin, clears it and pastes it into input.
send function sends the input data but doesn't clear it.
When we reach end of file fgets returns NULL but we are not doing anything to input buff.
So the input buff still has the last 1kb data and the send function sends.
This is a never ending loop and this programme continuosly sends the last 1kb data repeatedly.
So reagardless of file size our xps will exhaust the ram available to it. 



### Issues in stage_10
The modifications to xps_connection.c file are incomplete wherever there is an error due to bufflist and write_ready flag change it to source/sink->active and source/sink->pipe->buff_list.
We are making pipes entries in core.h but in create core we are not creating vec_init of pipes please do that.

### Issues in stage_11
In close_cb we are only closing if sink and source active flags are false but we also call close_cb for source does not exist so instead of directly checking for flag first check for existenance of source.
