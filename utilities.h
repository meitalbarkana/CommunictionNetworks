#include <stdio.h>
#include <sys/types.h>
# include <sys/socket.h>
#include <stdbool.h> // For booleans
#include <sys/stat.h> // For info about dierctory/file
#include <ctype.h> // For isdigit()
#include <string.h> // For strlen()
#include <stdlib.h> // For malloc()/calloc()

#define SIZE_OF_LEN 4
#define SIZE_OF_TYPE 2
#define SIZE_OF_PREFIX (SIZE_OF_TYPE+SIZE_OF_LEN)
#define MAX_FILES_FOR_USER 15
#define MAX_USERS 15
#define MAX_PASSWORD_LEN 25 //This doesn't include null-terminator
#define MAX_USERNAME_LEN 25 //This doesn't include null-terminator
#define MAX_FILE_SIZE 512 //Bytes. more than enough since each username+password line takes 52 bytes at most, *15 lines

#define CLIENT_LOGIN_MSG 0
#define CLIENT_FILES_LIST_MSG 1
#define CLIENT_FILE_DELETE_MSG 2
#define CLIENT_FILE_ADD_MSG 3
#define CLIENT_FILE_DOWNLOAD_MSG 4
#define CLIENT_CLOSE_MSG 5

#define SERVER_WELCOME_MSG 0
#define SERVER_PLEASE_LOGIN_MSG 1
#define SERVER_LOGIN_FAIL_MSG 2
#define SERVER_FILES_LIST_MSG 3
#define SERVER_FILE_REMOVE_MSG 4
#define SERVER_FILE_ADD_MSG 5
#define SERVER_FILE_DOWNLOAD_MSG 6

struct msg {
	char* msg;
	int type;
	int len;
};

void intToString(unsigned int iNum, unsigned int iSizeInBytes, unsigned char* iBuffer);
unsigned int stringToInt(unsigned char* iBuffer, unsigned int iSizeInBytes);
bool fileToString(unsigned char** msg, unsigned char* filepath, long* fsize);
bool StringTofile(unsigned char* msg,unsigned char* filepath);

bool doesPathExists(const char* path);
bool isValidFilePath(const char* path);
bool isStringNumeric(const char* str);

int sendall(int s, char *buf, int *len);
int recvall(int s, char *buf, int *len);
int getIntFromMsg(int iFd, int Isize, int* retVal);
int getMSG(int iFd, struct msg * msg);



