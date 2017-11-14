#include "../utilities.h"
#include <stdlib.h> // For strtol()
#include <limits.h> // For constant USHRT_MAX

enum serverErrors {
		NO_ERR,
		USERS_FILE_WRONG_FORMAT,
		USERS_FILE_ERR,
		USERS_FILE_ALOC_FAIL,
		USERS_FILE_NOT_OPENED,
		USERS_FILE_PERM_DENIED,
		USERS_FILE_CONTAIN_DUPL	
};

typedef struct{
	char* username;
	char* password;
} UserInfo;

/**
 *	Gets: 1. a (valid) path to a file that supposed to have a list of all usernames&passwords,
 * 			 in format: <username>\t<password>\n
 * 		  2. pointer to an array of UserInfo, it would be initiallized and filled during this function 
 * 
 * 	Returns enum serverErrors representing status. 
 **/
enum serverErrors getUsersInfoFromFile(const char* pathToFile,struct UserInfo** ptrToAllUsersInfo);

