#ifndef SERVER_H_
#define SERVER_H_
#include "../utilities.h"
#include <stdlib.h> // For strtol()
#include <limits.h> // For constant USHRT_MAX

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
 *  If server initiation succeeded returns an array of pointers to user_info,
 *  otherwise returns NULL.
 * 	Note: user of this functions should free space allocated user_info**.
 **/ 
user_info** init_server(int argc, char* argv[]);

#endif /*SERVER_H_*/
