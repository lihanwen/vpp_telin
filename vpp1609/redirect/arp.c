#define ERRIN(s) {printf("error in s\n"); }
#include<stdio.h>
#include<sys/socket.h>
#include<string.h>
#include<unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>


// To return the position of the next segment in the line.
char * p2next(char *p) {
    if(!p) {
        fprintf(stderr,"p is NULL\n");
        return NULL;
    }
    if(*p == '\0') {
        return NULL;
    }
    if(*p == '\n') {
        return NULL;
    }
    while(*p != ' ' && *p != '\n' && *p != '\t')
        ++p;
//pass the spaces
    if(*p == '\n'||*p == '\0' ) {
        return NULL;
    }
    while(*p == ' '||*p == '\t')
        ++p;
    if(*p == '\n'||*p == '\0' ) {
        return NULL;
    }
// Now, p points to the non-space char of the next segment. We can just return p
    return p;
}

// Get the dotted decimal ip address
void getip(char *p, char *q) {
    while(*p != ' ' && *p != '\n' && *p != '\0' && *p != '\t')
        *q++ = *p++;
    *q = '\0';
}

void gethw(char *p, char *q) {
    p = p2next(p);
    p = p2next(p);
    p = p2next(p);
    while(*p != ' ' && *p != '\n' && *p != '\0' && *p != '\t')
        *q++ = *p++;
    *q = '\0';
}

int arp(char *hwaddr, struct in_addr ip_in) {
    FILE *fp = NULL;
    char ip[32], temp[64], buf[256];
    memset(ip,0,32);
    char *p = NULL;
    p = inet_ntoa((struct in_addr)ip_in);
    strcpy(ip,p);
    fp = fopen("/proc/net/arp","r");
    if(fp == NULL) return 0;
    while(fgets(buf, 256, fp)) {
        getip(buf, temp);
        if(!strcmp(temp, ip)) {
            gethw(buf, temp);
            strcpy(hwaddr, temp);
            return 1;
        }
    }
    return 0;
}

int main(int argc, char** argv) {
    char hwaddr[64];
    memset(hwaddr,0,64);
    if(argc != 2) return 0;
    struct in_addr ip;
    inet_aton(argv[1],&ip);
    if(!arp(hwaddr,ip)) {
        printf(" No item for this ip.\n");
        return 0;
    }
    else printf("hw address: %s\n", hwaddr);
    return 1;
    return 0;
}


