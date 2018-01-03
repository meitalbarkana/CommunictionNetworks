#ifndef SERVER_H_
#define SERVER_H_
#include "utilities.h"
#include <stdlib.h> // For strtol()
#include <limits.h> // For constant USHRT_MAX

#define MAX_FILES_TO_CHECK 200	//Defines max number of files to check when trying to find an "exit" file
#define NO_SOCKFD (-1)

enum ServerErrors {
		USERS_FILE_NO_ERR,
		USERS_FILE_ERR,
		USERS_FILE_TOO_BIG,
		USERS_FILE_ALOC_FAIL,
		USERS_FILE_NOT_OPENED
};

enum ClientStatus{
	NO_CLIENT_YET,
	WELCOME_MSG_SENT,
	CLIENT_IS_CONNECTED,
	CLIENT_IS_OFFLINE
};

typedef struct{
	char* username;
	char* password;
} user_info;

typedef struct {
	int client_sockfd;
	struct sockaddr_in client_addr;
	user_info* client_info;
	//Represents client current status:
	enum ClientStatus client_status;
	//Holds number of trials to authenticate (of current sockfd):
	unsigned short num_authentication_attempts;
} active_fd;

enum DeleteFileStatus{
	FILE_DELETED_SUCCESSFULLY,
	FILE_WASNT_FOUND,
	FILE_DELETION_FAILED
};

enum AddFileStatus{
	FILE_ADDED_SUCCESSFULLY,
	FILE_ALREADY_EXIST,
	FILE_ADDITION_FAILED
};

enum GetFileStatus{
	FILE_CONTENT_IN_TXT_SUCCESSFULLY,
	FILE_DOESNT_EXIST,
	FILE_GET_FAILED
};

/**
 *  Helper function to free memory
 **/
void free_users_array(user_info*** ptr_to_all_users_info);

/**
 * 	Initiates server according to parameters provided by user (argc, argv).
 *  If server initiation succeeded returns an array of pointers to user_info,
 *  otherwise returns NULL.
 * 	*ptr_dir_path is updated so it will contain the address of directory in which all users-directories will be opened.	
 * 	Note: user of this functions should free space allocated to user_info**, *ptr_dir_path.
 **/ 
user_info** init_server(int argc, char* argv[], char** ptr_dir_path);

/**
 * 	Server starts waiting for clients
 **/
void start_service(user_info*** ptr_to_all_users_info, char*const *ptr_dir_path);

#endif /*SERVER_H_*/
