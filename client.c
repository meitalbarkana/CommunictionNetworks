#include "client.h"

bool getWelcomeMsg(int fd) {
	struct msg m = { NULL, -1, -1 };
	if (getMSG(fd, &m) != 0) {
		return false;
	}
	if (m.type == SERVER_WELCOME_MSG) {
		printUnsignedCharArr(m.msg, m.len);
		free(m.msg);
		return true;

	}
	free(m.msg);
	return false;
}
bool getAndPrint(int fd, int msgType) {
	struct msg m;
	if (getMSG(fd, &m) < 0 || m.type != msgType) {
		free(m.msg);
		return false;
	}
	printUnsignedCharArr(m.msg, m.len);
	free(m.msg);
	return true;
}
int getAndReturnMsg(int fd, int msgType, unsigned char* msg) {
	struct msg m;
	if (getMSG(fd, &m) < 0 || m.type != msgType) {
		free(m.msg);
		msg = NULL;
		return -1;
	}
	msg = m.msg;
	return m.len;
}

bool GetServerLoginMsg(int fd) {
	return getAndPrint(fd, SERVER_LOGIN_PASS_MSG);
}

int generateCloseRequestMSG(unsigned char** msg) {
	*msg = (unsigned char*) malloc(SIZE_OF_PREFIX);
	if (*msg == NULL) {
		printf("malloc failed\n");
		return -1;
	}
	intToString(0, SIZE_OF_LEN, *msg);
	intToString(CLIENT_CLOSE_MSG, SIZE_OF_TYPE, *msg + SIZE_OF_LEN);
	return SIZE_OF_PREFIX;
}

int generateFileDownloadRequestMSG(unsigned char** msg, const char* filePath,
		int size) {
	*msg = (unsigned char*) malloc(SIZE_OF_PREFIX + size);
	if (*msg == NULL) {
		printf("malloc failed\n");
		return -1;
	}
	intToString(size, SIZE_OF_LEN, *msg);
	intToString(CLIENT_FILE_DOWNLOAD_MSG, SIZE_OF_TYPE, *msg + SIZE_OF_LEN);
	memcpy(*msg + SIZE_OF_PREFIX, filePath, size);
	return SIZE_OF_PREFIX + size;
}

int generateFileAddRequestMSG(unsigned char** msg, const char* filepath,
		const char* newFile) {
	unsigned char* txt;
	unsigned char newLine = '\n';
	long sizeOfFile;
	long sizeNewPath = strlen(newFile);
	if (fileToString(&txt, filepath, &sizeOfFile) == false) {
		return -1;
	}
	*msg = (unsigned char*) malloc(
	SIZE_OF_PREFIX + sizeOfFile + sizeNewPath + 1);
	if (*msg == NULL) {
		printf("malloc failed\n");
		return -1;
	}
	intToString(sizeOfFile + sizeNewPath + 1, SIZE_OF_LEN, *msg);
	intToString(CLIENT_FILE_ADD_MSG, SIZE_OF_TYPE, *msg + SIZE_OF_LEN);
	memcpy(*msg + SIZE_OF_PREFIX, newFile, sizeNewPath);
	memcpy(*msg + SIZE_OF_PREFIX + sizeNewPath, &newLine, 1);
	memcpy(*msg + SIZE_OF_PREFIX + sizeNewPath + 1, txt, sizeOfFile);
	free(txt);
	return SIZE_OF_PREFIX + sizeOfFile;
}
int generateFileDeleteRequestMSG(unsigned char** msg, const char* filePath,
		int size) {
	*msg = (unsigned char*) malloc(SIZE_OF_PREFIX + size);
	if (*msg == NULL) {
		printf("malloc failed\n");
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
		printf("malloc failed\n");
		return -1;
	}
	intToString(0, SIZE_OF_LEN, *msg);
	intToString(CLIENT_FILES_LIST_MSG, SIZE_OF_TYPE, *msg + SIZE_OF_LEN);
	return SIZE_OF_PREFIX;
}

int generateLoginMSG(unsigned char** msg) {
	
	char username[MAX_USERNAME_LEN + 2];
	char password[MAX_PASSWORD_LEN + 2];
	
	int len_username = get_line_from_stdin(username, (MAX_USERNAME_LEN + 2),STR_USERNAME);	
	int len_password = get_line_from_stdin(password, (MAX_PASSWORD_LEN + 2),STR_PASSWORD);
	
	if (len_password < 0) || (len_username < 0) {
		printf("Format username and paswword is invalid.\n");
		return -1;
	}

	size_t sizeOfStr = (len_username + len_password + SIZE_OF_PREFIX);
	*msg = malloc(sizeOfStr);
	if (*msg == NULL) {
		printf("malloc failed\n");
		return -1;
	}

	intToString((unsigned int) sizeOfStr - SIZE_OF_PREFIX, SIZE_OF_LEN, *msg);
	intToString(CLIENT_LOGIN_MSG, SIZE_OF_TYPE, *msg + SIZE_OF_LEN);
	memcpy(*msg + SIZE_OF_PREFIX, username, len_username);
	memcpy(*msg + SIZE_OF_PREFIX + len_username, password,
			len_password);
	return sizeOfStr;

}

bool handleFileMSG(int fd,const char* PathToSave){
	struct msg m;
	if(getMSG(fd,&m)<0){
		return false;
	}
	bool res = ((m.type==SERVER_FILE_DOWNLOAD_MSG)&& StringTofile(m.msg,PathToSave))||
			 ((m.type==SERVER_FILE_DOWNLOAD_FAILED_MSG)&& printUnsignedCharArr(m.msg, m.len));
	free(m.msg);
	return res;
}

bool listOfFilesRequest(int fd) {
	unsigned char* msg;
	int len;
	if ((len = generateFileListMSG(&msg)) < 0 || sendall(fd, msg, &len) < 0) {
		free(msg);
		return false;
	}
	free(msg);
	return getAndPrint(fd, SERVER_FILES_LIST_MSG);
}

bool deleteFileRequest(int fd, const char* fileName, int len) {
	unsigned char* msg;
	int lenOfMsg;
	if ((lenOfMsg = generateFileDeleteRequestMSG(&msg, fileName, len)) < 0
			|| sendall(fd, msg, &lenOfMsg) < 0) {
		free(msg);
		return false;
	}
	free(msg);
	return getAndPrint(fd, SERVER_FILE_REMOVE_MSG);
}

bool getFileRequest(int fd, const char* fileName, int len,
		const char* PathToSave) {
	unsigned char* msg;
	int lenOfMsg;
	if ((lenOfMsg = generateFileDownloadRequestMSG(&msg, fileName, len))
			< 0 || (sendall(fd, msg, &lenOfMsg) < 0 )|| (handleFileMSG(fd,fileName)==false)){
		free(msg);
		return false;
	}
	free(msg);
	return true;
}

bool addFileRequest(int fd, const char* filePath, const char* newFileName) {
	unsigned char* msg;
	int lenOfMsg;
	if ((lenOfMsg = generateFileAddRequestMSG(&msg, filePath, newFileName))
			< 0 || sendall(fd, msg, &lenOfMsg) < 0) {
		free(msg);
		return false;
	}
	free(msg);
	return getAndPrint(fd, SERVER_FILE_ADD_MSG);
}

bool quitRequest(int fd) {
	unsigned char* msg;
	int lenOfMsg;
	if ((lenOfMsg = generateCloseRequestMSG(&msg)) < 0
			|| sendall(fd, msg, &lenOfMsg) < 0) {
		free(msg);
		return false;
	}
	free(msg);
	return true;
}

int main(int argc, char *argv[]) {

// define target address
	struct sockaddr_in dest_addr;
	struct hostent *he;
	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons(DEFAULT_PORT_NUM);
	dest_addr.sin_addr.s_addr = htonl(0x8443FC64);
	if (argc > 1 && inet_pton(AF_INET, argv[1], &(dest_addr.sin_addr)) == 0) {
		if (isStringNumeric(argv[1])) {
			dest_addr.sin_addr.s_addr = htonl(atoi(argv[1]));
		} else {
			if ((he = gethostbyname(argv[1])) == NULL) {
				printf("Can't convert hostname to IP\n");
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
		printf("Failed to open socket\n");
		printf("Error: %s\n", strerror(errno));
		return -1;
	}

//connect socket to target
	if (connect(socketfd, (struct sockaddr*) &dest_addr,
			sizeof(struct sockaddr)) < 0) {
		printf("Failed to connect to server\n");
		close(socketfd);
		return -1;
	}

	if (!getWelcomeMsg(socketfd)) {
		printf("Didn't get welcome msg\n");
		close(socketfd);
		return -1;
	}

	bool connected = false;
	for(int i=0;i<ALLOWED_TRIALS && !connected;i++){
		unsigned char* msg;
		int len;
		if ((len = generateLoginMSG(&msg)) == -1
				|| sendall(socketfd, msg, &len) == -1) {
			close(socketfd);
			return -1;
		}
		connected = GetServerLoginMsg(socketfd);
	}
	if(!connected){
		printf("Could not login to server\n");
				close(socketfd);
				return -1;
	}

	// action with the server
	bool askedToQuit = false;
	while (!askedToQuit) {
		char CommandArr[MAX_COMMAND_LEN];
		fgets(CommandArr, MAX_COMMAND_LEN, stdin);
		char * pch;
		char* command = (pch = strtok(CommandArr, " "));
		char* arg1 = (pch == NULL ? NULL : (pch = strtok(CommandArr, " ")));
		char* arg2 = (pch == NULL ? NULL : (pch = strtok(CommandArr, " ")));
		printf("%s\n",command);
		if (strcmp(command, "list_of_files\n") == 0) {
			listOfFilesRequest(socketfd);
		} else if ((strcmp(command, "delete_file\n") == 0) && arg1 != NULL) {
			deleteFileRequest(socketfd, arg1, strlen(arg1));
		} else if (strcmp(command, "add_file\n")
				== 0&& arg1 != NULL && arg2 != NULL) {
			addFileRequest(socketfd, arg1, arg2);
		} else if (strcmp(command, "get_file\n")
				== 0&& arg1 != NULL && arg2 != NULL) {
			getFileRequest(socketfd, arg1, strlen(arg1), arg2);
		} else if (strcmp(command, "quit\n") == 0) {
			quitRequest(socketfd);
			askedToQuit = true;
		} else {
			printf("Could not parse command [%s]  \n", CommandArr);
		}
	}
	close(socketfd);
	return 0;
}

