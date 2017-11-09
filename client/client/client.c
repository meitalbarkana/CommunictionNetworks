// client.c : Defines the entry point for the console application.
#pragma once
#include <stdio.h>
#include "utilities.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ws2tcpip.h>
#include <errno.h>
#include <stdbool.h>



#pragma comment(lib, "Ws2_32.lib")
#pragma warning(disable : 4996)

int main()
{

		int socketfd = socket(PF_INET, SOCK_STREAM, 0);
		if (socketfd < 0) {
			printf("Failed to open socket");
			printf("Error: %s\n", strerror(errno));
			return -1;
		}

		struct sockaddr_in serv_addr;
		serv_addr.sin_family = AF_INET;
		serv_addr.sin_port = htons(80);
		serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);


		if (connect(socketfd, &serv_addr, sizeof(serv_addr)) < 0) {
			printf("Failed to connect to server");
			close(socketfd);
			return -1;
		}

		

		int logedIn = FALSE;
		char username[26];
		char password[26];
		while (!logedIn) {
			printf("Please insert your Username\n");
			fgets(username, 25, stdin);
			printf("Please insert your Password\n");
			fgets(password, 25, stdin);
			char* logInMsg = malloc(sizeof(char)*(strlen(username) + strlen(password)) + 6);
			intToString(0, 4, logInMsg);
			intToString(0, 4, logInMsg);

		}

		unsigned char msgLength[4];
		intToString(503, 4, &msgLength);
		int i = 3;
	}

