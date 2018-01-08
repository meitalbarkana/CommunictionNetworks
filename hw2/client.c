#include "client.h"

bool getWelcomeMsg(int fd) {
	struct msg m = { NULL, -1, -1 };
	if (getMSG(fd, &m) != 0) {
		return false;
	}
	if (m.type == SERVER_WELCOME_MSG) {
		printUnsignedCharArr(m.msg, m.len, false, false, true);
		free(m.msg);
		return true;

	}
	free(m.msg);
	return false;
}
bool getAndPrint(int fd, int msgType, bool printNewLine) {
	struct msg m;
	if (getMSG(fd, &m) < 0 || m.type != msgType) {
		free(m.msg);
		return false;
	}
	printUnsignedCharArr(m.msg, m.len, false, false, printNewLine);
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
	return getAndPrint(fd, SERVER_LOGIN_PASS_MSG, true);
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
	unsigned int sizeNewPath = strlen(newFile) - 1; //-1 because newFile's name includes \n
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
	printDebugString(
			"In generateFileAddRequestMSG. size of the file we're sending is:");
	printDebugInt(sizeOfFile);
	memcpy(*msg + SIZE_OF_PREFIX + sizeNewPath + 1, txt, sizeOfFile);
	free(txt);
	return SIZE_OF_PREFIX + sizeOfFile + 1 + sizeNewPath; //was SIZE_OF_PREFIX + sizeOfFile
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

int generateUsersListMSG(unsigned char** msg) {
	*msg = (unsigned char*) malloc(SIZE_OF_PREFIX);
	if (*msg == NULL) {
		printf("malloc failed\n");
		return -1;
	}
	intToString(0, SIZE_OF_LEN, *msg);
	intToString(CLIENT_GET_USERS_MSG, SIZE_OF_TYPE, *msg + SIZE_OF_LEN);
	return SIZE_OF_PREFIX;
}

int generateLoginMSG(unsigned char** msg) {

	char username[MAX_USERNAME_LEN + 2];
	char password[MAX_PASSWORD_LEN + 2];
	int len_username = -1;
	int len_password = -1;

	for (bool first = true; len_password < 0 || len_username < 0; first =
	false) {
		if (!first) {
			printf("Format username and paswword is invalid.\n");
		}
		len_username = get_line_from_stdin(username, (MAX_USERNAME_LEN + 2),
		STR_USERNAME);
		len_password = get_line_from_stdin(password, (MAX_PASSWORD_LEN + 2),
		STR_PASSWORD);
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
	memcpy(*msg + SIZE_OF_PREFIX + len_username, password, len_password);
	return sizeOfStr;

}

bool handleFileMSG(int fd, bool printToScreen, const char* PathToSave) {
	struct msg m;
	if (getMSG(fd, &m) < 0) {
		return false;
	}
	printDebugInt(m.type);
	printDebugString((char*) m.msg);
	printDebugString("m.len is:");
	printDebugInt(m.len);
	printDebugString("Path to save is:");
	printDebugString(PathToSave);
	bool res = ((m.type == SERVER_FILE_DOWNLOAD_MSG && !printToScreen)
			&& StringTofile(m.msg, PathToSave))
			|| ((m.type == SERVER_FILE_DOWNLOAD_FAILED_MSG || printToScreen)
					&& printUnsignedCharArr(m.msg, m.len, false, false, true));
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
	return getAndPrint(fd, SERVER_FILES_LIST_MSG, false);
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
	return getAndPrint(fd, SERVER_FILE_REMOVE_MSG, true);
}

bool getFileRequest(int fd, const char* fileName, int len, char* PathToSave,
bool printOnScreen) {
	unsigned char* msg;
	if (!printOnScreen) {
		PathToSave[strlen(PathToSave) - 1] = '\0'; //To delete the '\n' thats written there (according to protocol)
		printDebugString("PathToSave is:");
		printDebugString(PathToSave);
	}
	int lenOfMsg;
	if ((lenOfMsg = generateFileDownloadRequestMSG(&msg, fileName, len)) < 0
			|| (sendall(fd, msg, &lenOfMsg) < 0)
			|| (handleFileMSG(fd, printOnScreen, PathToSave) == false)) {
		free(msg);
		return false;
	}
	free(msg);
	return true;
}

bool addFileRequest(int fd, const char* filePath, const char* newFileName) {
	unsigned char* msg;
	int lenOfMsg;
	if ((lenOfMsg = generateFileAddRequestMSG(&msg, filePath, newFileName)) < 0
			|| sendall(fd, msg, &lenOfMsg) < 0) {
		free(msg);
		return false;
	}
	free(msg);
	return getAndPrint(fd, SERVER_FILE_ADD_MSG, true);
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
bool getUsersRequest(int iFd) {
	unsigned char* msg;
	int len;
	if ((len = generateUsersListMSG(&msg)) < 0 || sendall(iFd, msg, &len) < 0) {
		free(msg);
		return false;
	}
	free(msg);
	return getAndPrint(iFd, SERVER_ALL_CONNECTED_USERS_MSG, false);
}

int generateFriendlyMSG(unsigned char** msg, char* user, const char* msgToSend) {
	user[strlen(user) - 1] = '\n'; //replace ":" from username to "\n"
	size_t sizeOfStr = (strlen(user) + strlen(msgToSend) + SIZE_OF_PREFIX);
	*msg = malloc(sizeOfStr);
	if (*msg == NULL) {
		printf("malloc failed\n");
		return -1;
	}

	intToString((unsigned int) sizeOfStr - SIZE_OF_PREFIX, SIZE_OF_LEN, *msg);
	intToString(CLIENT_FRIENDLY_MSG, SIZE_OF_TYPE, *msg + SIZE_OF_LEN);
	memcpy(*msg + SIZE_OF_PREFIX, user, strlen(user));
	memcpy(*msg + SIZE_OF_PREFIX + strlen(user), msgToSend, strlen(msgToSend));
	return sizeOfStr;
}
bool sendFriendlyMSGRequest(int iFd, char* user, const char* msgToSend) {
	unsigned char* msg;
	int len;
	if ((len = generateFriendlyMSG(&msg,user,msgToSend)) < 0 || sendall(iFd, msg, &len) < 0) {
		free(msg);
		return false;
	}
	free(msg);
	return getAndPrint(iFd, SERVER_STATUS_FRIENDLY_MSG, true);
}

bool getSavedMSGS(int iFd) {
	return getFileRequest(iFd, STR_OFFLINE_FILE, strlen(STR_OFFLINE_FILE), NULL,
	true);
}

int main(int argc, char *argv[]) {
	initApprovedFriendly();
	// define target address
	struct sockaddr_in dest_addr;
	struct hostent *he;
	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons(DEFAULT_PORT_NUM);
	dest_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (argc > 1 && inet_pton(AF_INET, argv[1], &(dest_addr.sin_addr)) == 0) {
		if (isStringNumeric(argv[1])) {
			dest_addr.sin_addr.s_addr = htonl(atoi(argv[1]));
		} else if ((he = gethostbyname(argv[1])) != NULL) {
			memcpy(&dest_addr.sin_addr, he->h_addr_list[0], he->h_length);
		} else {
			dest_addr.sin_addr.s_addr = htonl((int) strtol(argv[1], NULL, 16));
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

	//init read_fds
	fd_set read_fds;
	FD_ZERO(&read_fds);
	FD_SET(STDIN_FILENO, &read_fds);
	FD_SET(socketfd, &read_fds);

	if (!getWelcomeMsg(socketfd)) {
		printf("Didn't get welcome msg\n");
		close(socketfd);
		return -1;
	}

	bool connected = false;
	for (int i = 0; i < ALLOWED_TRIALS && !connected; i++) {
		unsigned char* msg;
		int len;
		if ((len = generateLoginMSG(&msg)) == -1
				|| sendall(socketfd, msg, &len) == -1) {
			close(socketfd);
			free(msg);
			return -1;
		}
		free(msg);
		connected = GetServerLoginMsg(socketfd);
		if (!connected) {
			if (i != ALLOWED_TRIALS - 1) {
				printf(
						"Connection failed - try again. you have %d connection attempts left\n",
						(ALLOWED_TRIALS - (i + 1)));
			} else {
				printf(
						"Connection failed - that was your last attempt. Goodbye!\n");
			}
		}
	}
	if (!connected) {
		printf("Could not login to server\n");
		close(socketfd);
		return -1;
	}

	// action with the server
	bool askedToQuit = false;
	while (!askedToQuit) {
		char CommandArr[MAX_COMMAND_LEN];
		int activity = select(socketfd + 1, &read_fds, NULL, NULL, NULL);
		if (activity < 1) {
			printf("Error in select\n");
			close(socketfd);
			return -1;
		}

		if (FD_ISSET(socketfd, &read_fds)) {
			printFriendly(socketfd);
		}

		if (FD_ISSET(STDIN_FILENO, &read_fds)) {
			fgets(CommandArr, MAX_COMMAND_LEN, stdin);
			char * pch;
			char* command = (pch = strtok(CommandArr, " "));
			char* arg1 = (pch == NULL ? NULL : (pch = strtok(NULL, " ")));
			char* arg2 = (pch == NULL ? NULL : (pch = strtok(NULL, " ")));
			if (strcmp(command, "list_of_files\n") == 0) {
				listOfFilesRequest(socketfd);
			} else if ((strcmp(command, "delete_file") == 0) && arg1 != NULL) {
				deleteFileRequest(socketfd, arg1, strlen(arg1) - 1); //Since arg1 contains a '\n' at its end
			} else if (strcmp(command, "add_file")
					== 0&& arg1 != NULL && arg2 != NULL) {
				addFileRequest(socketfd, arg1, arg2);
			} else if (strcmp(command, "get_file")
					== 0&& arg1 != NULL && arg2 != NULL) {
				getFileRequest(socketfd, arg1, strlen(arg1), arg2, false);
			} else if (strcmp(command, "users_online\n") == 0) {
				getUsersRequest(socketfd);
			} else if (strcmp(command, "msg")
					== 0&& arg1 != NULL && arg2 != NULL) {
				sendFriendlyMSGRequest(socketfd, arg1, arg2);
			} else if (strcmp(command, "read_msgs\n") == 0) {
				getSavedMSGS(socketfd);
			} else if (strcmp(command, "quit\n") == 0) {
				quitRequest(socketfd);
				askedToQuit = true;
			} else {
				printf("Could not parse command [%s]  \n", CommandArr);
			}
		}
	}
	close(socketfd);
	return 0;
}

