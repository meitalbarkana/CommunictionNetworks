#ifndef UTILITIES_H_
#define UTILITIES_H_
#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
# include <sys/socket.h>
#include <stdbool.h> // For booleans
#include <sys/stat.h> // For info about dierctory/file
#include <ctype.h> // For isdigit()
#include <string.h> // For strlen()
#include <stdlib.h> // For malloc()/calloc()
#include <errno.h>
#include <dirent.h> //For working with directories
#include <arpa/inet.h> //For htonl() etc..
#include <netinet/in.h> //For htonl() etc.
#include <unistd.h> //For close()
#include <math.h> //for pow(a,b)

#define DEBUG_MODE 0
#define SIZE_OF_LEN 4
#define SIZE_OF_TYPE 2
#define SIZE_OF_PREFIX (SIZE_OF_TYPE+SIZE_OF_LEN)
#define MAX_FILES_FOR_USER 15
#define MAX_USERS 15
#define MAX_PASSWORD_LEN 25 //This doesn't include null-terminator
#define MAX_USERNAME_LEN 25 //This doesn't include null-terminator
#define MAX_FILE_SIZE 512 //Bytes. more than enough since each username+password line takes 52 bytes at most, *15 lines. It's also maximum file size to send/get
#define MAX_FILE_PATH_LEN 255 //True for most file systems
#define MAX_COMMAND_LEN (10+MAX_FILE_PATH_LEN) //For adding files with long path

#define CLIENT_LOGIN_MSG 0
#define CLIENT_FILES_LIST_MSG 1
#define CLIENT_FILE_DELETE_MSG 2
#define CLIENT_FILE_ADD_MSG 3
#define CLIENT_FILE_DOWNLOAD_MSG 4
#define CLIENT_CLOSE_MSG 5
#define CLIENT_FRIENDLY_MSG 6
#define CLIENT_GET_USERS_MSG 7

#define SERVER_WELCOME_MSG 0
#define SERVER_LOGIN_PASS_MSG 1
#define SERVER_LOGIN_FAIL_MSG 2
#define SERVER_FILES_LIST_MSG 3
#define SERVER_FILE_REMOVE_MSG 4
#define SERVER_FILE_ADD_MSG 5
#define SERVER_FILE_DOWNLOAD_MSG 6
#define SERVER_FILE_DOWNLOAD_FAILED_MSG 7
#define SERVER_ALL_CONNECTED_USERS_MSG 8
#define SERVER_STATUS_FRIENDLY_MSG 9
#define SERVER_ACTUAL_FRIENDLY_MSG (pow(256,SIZE_OF_TYPE)-1)


#define ALLOWED_TRIALS 3

#define STR_USERNAME "User: "
#define STR_PASSWORD "Password: "

#define DEFAULT_PORT_NUM 1337

#define STR_OFFLINE_FILE "Messages_received_offline.txt" 

struct msg {
	unsigned char* msg;
	int type;
	int len;
};

void printDebugString(const char* str);
void printDebugInt(int n);
bool printUnsignedCharArr(const unsigned char* arr, int len,bool prefix, bool onlyDebug, bool printNewLine);
void intToString(unsigned int iNum, unsigned int iSizeInBytes, unsigned char* iBuffer);
unsigned int stringToInt(const unsigned char* iBuffer, unsigned int iSizeInBytes);
bool fileToString(unsigned char** msg, const char* filepath, long* fsize);
bool StringTofile(unsigned char* msg,const char* filepath);

bool doesPathExists(const char* path);
bool isValidFilePath(const char* path);
bool isStringNumeric(const char* str);
char* concat_strings(const char* str1, const char* str2, bool add_newline);
int number_of_files_in_directory(const char* dir_path, int max_val);

int sendall(int s, unsigned char *buf, int *len);
int recvall(int s, unsigned char *buf, int *len);
int getIntFromMsg(int iFd, int Isize, int* retVal);
int getMSG(int iFd, struct msg * msg);
int getMSGOrPrintFriendly(int iFd, struct msg * msg,bool justFriendly);
void printFriendly(int iFd);

int get_line_from_stdin(char* line, int max_length, const char* prefix);

#endif /*UTILITIES_H_*/
