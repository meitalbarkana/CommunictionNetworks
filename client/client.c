
#include <stdio.h>
#include "utilities.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>

bool generateCloseRequestMSG(unsigned char** msg) {
	*msg = (unsigned char*)malloc(SIZE_OF_PREFIX);
	if (*msg == NULL) {
		printf("malloc failed");
		return false;
	}
	intToString(0, SIZE_OF_LEN, *msg);
	intToString(CLIENT_CLOSE_MSG, SIZE_OF_TYPE, *msg + SIZE_OF_LEN);
	return true;
}

bool generateFileDownloadRequestMSG(unsigned char** msg, unsigned char* filePath, int size) {
	*msg = (unsigned char*)malloc(SIZE_OF_PREFIX + size);
	if (*msg == NULL) {
		printf("malloc failed");
		return false;
	}
	intToString(size, SIZE_OF_LEN, *msg);
	intToString(CLIENT_FILE_DOWNLOAD_MSG, SIZE_OF_TYPE, *msg + SIZE_OF_LEN);
	memcpy(*msg + SIZE_OF_PREFIX, filePath, size);
	return true;
}

bool generateFileAddRequestMSG(unsigned char** msg, const char* filepath) {
	unsigned char* txt;
	long size;
	if (fileToString(&txt, filepath, &size) == false) {
		return false;
	}
	*msg = (unsigned char*)malloc(SIZE_OF_PREFIX + size);
	if (*msg == NULL) {
		printf("malloc failed");
		return false;
	}
	intToString(size, SIZE_OF_LEN, *msg);
	intToString(CLIENT_FILE_ADD_MSG, SIZE_OF_TYPE, *msg + SIZE_OF_LEN);
	memcpy(*msg + SIZE_OF_PREFIX, txt, size);
	free(txt);
	return true;
}
bool generateFileDeleteRequestMSG(unsigned char** msg,unsigned char* filePath, int size) {
	*msg = (unsigned char*)malloc(SIZE_OF_PREFIX + size);
	if (*msg == NULL) {
		printf("malloc failed");
		return false;
	}
	intToString(size, SIZE_OF_LEN, *msg);
	intToString(CLIENT_FILE_DELETE_MSG, SIZE_OF_TYPE, *msg + SIZE_OF_LEN);
	memcpy(*msg + SIZE_OF_PREFIX, filePath, size);
	return true;
}

bool generateFileListMSG(unsigned char** msg) {
	*msg = (unsigned char*)malloc(SIZE_OF_PREFIX);
	if (*msg == NULL) {
		printf("malloc failed");
		return false;
	}
	intToString(0, SIZE_OF_LEN, *msg);
	intToString(CLIENT_FILES_LIST_MSG, SIZE_OF_TYPE, *msg + SIZE_OF_LEN);
	return true;
}

bool generateLoginMSG(unsigned char** msg) {
	char username[MAX_USERNAME_LEN];
	char password[MAX_PASSWORD_LEN + 1];
	printf("User:");
	fgets(username, MAX_USERNAME_LEN, stdin);
	printf("Password:");
	fgets(password, MAX_PASSWORD_LEN, stdin);
	size_t sizeOfStr = (strlen(username) + strlen(password) + SIZE_OF_PREFIX);
	*msg = malloc(sizeOfStr);
	if (*msg == NULL) {
		printf("malloc failed");
		return false;
	}

	intToString((unsigned int) sizeOfStr - SIZE_OF_PREFIX, SIZE_OF_LEN, *msg);
	intToString(CLIENT_LOGIN_MSG, SIZE_OF_TYPE, *msg + SIZE_OF_LEN);
	memcpy(*msg + SIZE_OF_PREFIX, username, strlen(username));
	memcpy(*msg + SIZE_OF_PREFIX + strlen(username), password, strlen(password));
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

	// define target address
	struct sockaddr_in dest_addr;
	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons( 80 );
	dest_addr.sin_addr.s_addr = htonl(0x8443FC64);


	//connect socket to target
	if(connect(socketfd, (struct sockaddr*) &dest_addr, sizeof(struct sockaddr)) <0){
		printf("Failed to connect to server");
				close(socketfd);
				return -1;
	}



}




