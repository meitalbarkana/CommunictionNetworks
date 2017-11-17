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
#include <arpa/inet.h>
#include <netdb.h>

bool getWelcomeMsg(int fd) {
	struct msg m = { NULL, -1, -1 };
	if (getMSG(fd, &m) != 0) {
		return false;
	}
	if (m.type == SERVER_WELCOME_MSG) {
		printf("%s", m.msg);
		free(m.msg);
		return true;

	}
	free(m.msg);
	return false;
}

bool GetServerLoginMsg(int df){
	//TODO Implementation
	return true;
}

bool listOfFilesRequest(int df){
	//TODO Implementation
	return true;
}

bool deleteFileRequest(int df, char* fileName){
	//TODO Implementation
	return true;
}

bool getFileRequest(int df, char* fileName, char* PathToSave){
	//TODO Implementation
	return true;
}

bool addFileRequest(int df, char* filePath, char* newFileName){
	//TODO Implementation
	return true;
}

bool quitRequest(int df){
	//TODO Implementation
	return true;
}


int generateCloseRequestMSG(unsigned char** msg) {
	*msg = (unsigned char*) malloc(SIZE_OF_PREFIX);
	if (*msg == NULL) {
		printf("malloc failed");
		return -1;
	}
	intToString(0, SIZE_OF_LEN, *msg);
	intToString(CLIENT_CLOSE_MSG, SIZE_OF_TYPE, *msg + SIZE_OF_LEN);
	return SIZE_OF_PREFIX;
}

int generateFileDownloadRequestMSG(unsigned char** msg, unsigned char* filePath,
		int size) {
	*msg = (unsigned char*) malloc(SIZE_OF_PREFIX + size);
	if (*msg == NULL) {
		printf("malloc failed");
		return -1;
	}
	intToString(size, SIZE_OF_LEN, *msg);
	intToString(CLIENT_FILE_DOWNLOAD_MSG, SIZE_OF_TYPE, *msg + SIZE_OF_LEN);
	memcpy(*msg + SIZE_OF_PREFIX, filePath, size);
	return SIZE_OF_PREFIX + size;
}

int generateFileAddRequestMSG(unsigned char** msg, const char* filepath) {
	unsigned char* txt;
	long size;
	if (fileToString(&txt, filepath, &size) == false) {
		return false;
	}
	*msg = (unsigned char*) malloc(SIZE_OF_PREFIX + size);
	if (*msg == NULL) {
		printf("malloc failed");
		return -1;
	}
	intToString(size, SIZE_OF_LEN, *msg);
	intToString(CLIENT_FILE_ADD_MSG, SIZE_OF_TYPE, *msg + SIZE_OF_LEN);
	memcpy(*msg + SIZE_OF_PREFIX, txt, size);
	free(txt);
	return SIZE_OF_PREFIX + size;
}
int generateFileDeleteRequestMSG(unsigned char** msg, unsigned char* filePath,
		int size) {
	*msg = (unsigned char*) malloc(SIZE_OF_PREFIX + size);
	if (*msg == NULL) {
		printf("malloc failed");
		return -1;
	}
	intToString(size, SIZE_OF_LEN, *msg);
	intToString(CLIENT_FILE_DELETE_MSG, SIZE_OF_TYPE, *msg + SIZE_OF_LEN);
	memcpy(*msg + SIZE_OF_PREFIX, filePath, size);
	return SIZE_OF_PREFIX + size;
}

int generateFileListMSG(unsigned char** msg) {
	*msg = (unsigned char*) malloc(SIZE_OF_PREFIX);
	if (*msg == NULL) {
		printf("malloc failed");
		return -1;
	}
	intToString(0, SIZE_OF_LEN, *msg);
	intToString(CLIENT_FILES_LIST_MSG, SIZE_OF_TYPE, *msg + SIZE_OF_LEN);
	return SIZE_OF_PREFIX;
}

int generateLoginMSG(unsigned char** msg) {
	char username[MAX_USERNAME_LEN + 1];
	char password[MAX_PASSWORD_LEN + 1];
	printf("User:");
	fgets(username, MAX_USERNAME_LEN, stdin);
	printf("Password:");
	fgets(password, MAX_PASSWORD_LEN, stdin);
	size_t sizeOfStr = (strlen(username) + strlen(password) + SIZE_OF_PREFIX);
	*msg = malloc(sizeOfStr);
	if (*msg == NULL) {
		printf("malloc failed");
		return -1;
	}

	intToString((unsigned int) sizeOfStr - SIZE_OF_PREFIX, SIZE_OF_LEN, *msg);
	intToString(CLIENT_LOGIN_MSG, SIZE_OF_TYPE, *msg + SIZE_OF_LEN);
	memcpy(*msg + SIZE_OF_PREFIX, username, strlen(username));
	memcpy(*msg + SIZE_OF_PREFIX + strlen(username), password,
			strlen(password));
	return sizeOfStr;

}
int main(int argc, char *argv[]) {

// define target address
	struct sockaddr_in dest_addr;
	struct hostent *he;
	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons(80);
	dest_addr.sin_addr.s_addr = htonl(0x8443FC64);
	if (argc > 1 && inet_pton(AF_INET, argv[1], &(dest_addr.sin_addr)) == 0) {
		if (isStringNumeric(argv[1])) {
			dest_addr.sin_addr.s_addr = htonl(atoi(argv[1]));
		} else {
			if ((he = gethostbyname(argv[1])) == NULL) {
				printf("Can't convert hostname to IP");
				exit(1); /* error */
			} else {
				memcpy(&dest_addr.sin_addr, he->h_addr_list[0], he->h_length);
			}
		}
	}
	if (argc > 2 && isStringNumeric(argv[2])) {
		dest_addr.sin_port = htons(atoi(argv[2]));
	}
//create socket
	int socketfd = socket(PF_INET, SOCK_STREAM, 0);
	if (socketfd < 0) {
		printf("Failed to open socket");
		printf("Error: %s\n", strerror(errno));
		return -1;
	}

//connect socket to target
	if (connect(socketfd, (struct sockaddr*) &dest_addr,
			sizeof(struct sockaddr)) < 0) {
		printf("Failed to connect to server");
		close(socketfd);
		return -1;
	}

	if (!getWelcomeMsg(socketfd)) {
		printf("Didn't get welcome msg");
		close(socketfd);
		return -1;
	}

	bool connected = false;
	while (!connected) {
		unsigned char* msg;
		int len;
		if ((len = generateLoginMSG(&msg)) == -1
				|| sendall(socketfd, msg, &len) == -1) {
			close(socketfd);
			return -1;
		}
		connected = GetServerLoginMsg(socketfd);
	}
	bool askedToQuit = false;
	while (!askedToQuit) {
		char CommandArr[MAX_COMMAND_LEN];
		fgets(CommandArr, MAX_COMMAND_LEN, stdin);
		char * pch;
		char* command = (pch = strtok(CommandArr, " "));
		char* arg1 = (pch == NULL ? NULL : (pch = strtok(CommandArr, " ")));
		char* arg2 = (pch == NULL ? NULL : (pch = strtok(CommandArr, " ")));

		if (strcmp(command, "list_of_files") == 0) {
			listOfFilesRequest(socketfd);
		} else if ((strcmp(command, "delete_file") == 0) && arg1 != NULL) {
			deleteFileRequest(socketfd, arg1);
		} else if (strcmp(command, "add_file")
				== 0&& arg1 != NULL && arg2 != NULL) {
			addFileRequest(socketfd, arg1, arg2);
		} else if (strcmp(command, "get_file")
				== 0&& arg1 != NULL && arg2 != NULL) {
			getFileRequest(socketfd, arg1, arg2);
		} else if (strcmp(command, "quit") == 0) {
			quitRequest(socketfd);
			askedToQuit = true;
		} else {
			printf("Could not parse command [%s]  \n", CommandArr);
		}
	}
	close(socketfd);
	return 0;
}

