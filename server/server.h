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

#endif /*SERVER_H_*/
