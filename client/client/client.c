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
char* generateLoginMSG() {
	//send wellcome msg
	//int logedIn = FALSE;
	char username[MAX_USERNAME_LEN];
	char password[MAX_PASSWORD_LEN + 1];
		printf("Please insert your Username\n");
		fgets(username, MAX_USERNAME_LEN, stdin);
		printf("Please insert your Password\n");
		fgets(password, MAX_PASSWORD_LEN, stdin);
		unsigned int sizeOfStr = (strlen(username) + strlen(password)  + SIZE_OF_PREFIX);
		char* logInMsg = malloc(sizeOfStr);
		intToString(sizeOfStr-SIZE_OF_PREFIX, SIZE_OF_LEN, logInMsg);
		intToString(CLIENT_LOGIN_MSG, SIZE_OF_TYPE, logInMsg + SIZE_OF_LEN);
		strncpy(logInMsg + SIZE_OF_PREFIX, username, strlen(username));
		strncpy(logInMsg + SIZE_OF_PREFIX + strlen(username), password, strlen(password));
		return logInMsg;

}
int main() {
	

	//create socket 
	int socketfd = socket(PF_INET, SOCK_STREAM, 0);
	if (socketfd < 0) {
		printf("Failed to open socket");
		printf("Error: %s\n", strerror(errno));
		return -1;
	}

	// define target adress
	struct sockaddr_in serv_addr;
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(80);
	serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	//connect socket to target
	if (connect(socketfd, &serv_addr, sizeof(serv_addr)) < 0) {
		printf("Failed to connect to server");
		close(socketfd);
		return -1;
	}




}



