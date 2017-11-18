#ifndef SERVER_H_
#define SERVER_H_
#include "../utilities.h"
#include <stdlib.h> // For strtol()
#include <limits.h> // For constant USHRT_MAX

#define BACKLOG_CONST_VALUE 5 //To define maximum backlog size of the server

enum ServerErrors {
		USERS_FILE_NO_ERR,
		USERS_FILE_ERR,
		USERS_FILE_TOO_BIG,
		USERS_FILE_ALOC_FAIL,
		USERS_FILE_NOT_OPENED
};

typedef struct{
	char* username;
	char* password;
} user_info;

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
//void start_service(user_info*** ptr_to_all_users_info, char*const *ptr_dir_path);

#endif /*SERVER_H_*/
