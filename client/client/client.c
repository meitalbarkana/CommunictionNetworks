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

bool generateCloseRequestMSG(char** msg) {
	*msg = (char*)malloc(SIZE_OF_PREFIX);
	if (*msg == NULL) {
		printf("malloc failed");
		return false;
	}
	intToString(0, SIZE_OF_LEN, *msg);
	intToString(CLIENT_CLOSE_MSG, SIZE_OF_TYPE, *msg + SIZE_OF_LEN);
	return true;
}

bool generateFileDownloadRequestMSG(char** msg, char* filePath, int size) {
	*msg = (char*)malloc(SIZE_OF_PREFIX + size);
	if (*msg == NULL) {
		printf("malloc failed");
		return false;
	}
	intToString(size, SIZE_OF_LEN, *msg);
	intToString(CLIENT_FILE_DOWNLOAD_MSG, SIZE_OF_TYPE, *msg + SIZE_OF_LEN);
	strncpy(*msg + SIZE_OF_PREFIX, filePath, size);
	return true;
}

bool generateFileAddRequestMSG(char** msg, char* filepath) {
	char* txt;
	long size;
	if (fileToString(&txt, filepath, &size) == false) {
		return false;
	}
	*msg = (char*)malloc(SIZE_OF_PREFIX + size);
	if (*msg == NULL) {
		printf("malloc failed");
		return false;
	}
	intToString(size, SIZE_OF_LEN, *msg);
	intToString(CLIENT_FILE_ADD_MSG, SIZE_OF_TYPE, *msg + SIZE_OF_LEN);
	strncpy(*msg + SIZE_OF_PREFIX, txt, size);
	free(txt);
	return true;
}
bool generateFileDeleteRequestMSG(char** msg, char* filePath, int size) {
	*msg = (char*)malloc(SIZE_OF_PREFIX + size);
	if (*msg == NULL) {
		printf("malloc failed");
		return false;
	}
	intToString(size, SIZE_OF_LEN, *msg);
	intToString(CLIENT_FILE_DELETE_MSG, SIZE_OF_TYPE, *msg + SIZE_OF_LEN);
	strncpy(*msg + SIZE_OF_PREFIX, filePath, size);
	return true;
}

bool generateFileListMSG(char** msg) {
	*msg = (char*)malloc(SIZE_OF_PREFIX);
	if (*msg == NULL) {
		printf("malloc failed");
		return false;
	}
	intToString(0, SIZE_OF_LEN, *msg);
	intToString(CLIENT_FILES_LIST_MSG, SIZE_OF_TYPE, *msg + SIZE_OF_LEN);
	return true;
}

bool generateLoginMSG(char** msg) {
	char username[MAX_USERNAME_LEN];
	char password[MAX_PASSWORD_LEN + 1];
	printf("User:");
	fgets(username, MAX_USERNAME_LEN, stdin);
	printf("Password:");
	fgets(password, MAX_PASSWORD_LEN, stdin);
	unsigned int sizeOfStr = (strlen(username) + strlen(password) + SIZE_OF_PREFIX);
	*msg = malloc(sizeOfStr);
	if (*msg == NULL) {
		printf("malloc failed");
		return false;
	}

	intToString(sizeOfStr - SIZE_OF_PREFIX, SIZE_OF_LEN, *msg);
	intToString(CLIENT_LOGIN_MSG, SIZE_OF_TYPE, *msg + SIZE_OF_LEN);
	strncpy(*msg + SIZE_OF_PREFIX, username, strlen(username));
	strncpy(*msg + SIZE_OF_PREFIX + strlen(username), password, strlen(password));
	return true;

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



