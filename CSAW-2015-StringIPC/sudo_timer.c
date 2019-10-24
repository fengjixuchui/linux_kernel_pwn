/*************************************************************
 * File Name: sudo_timer.c
 * 
 * Created on: 2019-10-22 04:33:42
 * Author: raycp
 * 
 * Last Modified: 2019-10-24 01:14:29
 * Description: call gettimerofday in loop. 
************************************************************/

#include <stdio.h>
int main(){
    while(1){
        sleep(1);
        gettimeofday();
    }
}
