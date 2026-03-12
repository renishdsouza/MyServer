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
Do not send INADDR_ANY when calling from main function to create listener as it won't be accepted. Send 127.0.0.1 as a string.

We need to include "../xps.h in all of the c files that we create. Also the libraries fcntl.h and errno.h need to be added.

In utils #define OK 0 and #define E_FAIL -1 need to be added.

### Issues in stage_7
You change some functions in .h files. The parameters are now changed, so change them in .c also. xps_listener_create. Remove epoll and make it core.
The build.sh is also incomplete add new files or use this gcc -g -o xps $(find . -name "*.c")