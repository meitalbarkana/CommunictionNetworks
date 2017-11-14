#include "server.h"

/**enum errors {
	
}**/

static unsigned short portNumber = 1337; // Default value

enum serverErrors getUsersInfoFromFile(const char* pathToFile,struct UserInfo** ptrToAllUsersInfo){
	struct stat st;
	if ((stat(pathToFile, &st) != 0) || (st.st_size > MAX_FILE_SIZE) || (st.st_size <= 0)) { //st_size might be negative, if an error accured..
		return USERS_FILE_ERR;
	}
	
	// Because sizeof(char)=1 byte, and each user's name+password are at least of 1 character for each,
	// an array of this size is more than enough.
	*ptrToAllUsersInfo = (struct UserInfo*)malloc( sizeOf(struct UserInfo)*(st.st_size/2) ); 
	if (*ptrToAllUsersInfo == NULL) {
			return USERS_FILE_ALOC_FAIL;
	}
	
	FILE* fp;
	if((fp = fopen(pathToFile,"r")) == NULL){
			free(*ptrToAllUsersInfo); //TODO:: check this is the right way to free
			return USERS_FILE_NOT_OPENED;
	}
	
	//Read file line-by-line:
	/*while (){
		//TODO::
	}*/
}

int main(int argc, char* argv[]){
	
	if (argc < 3 || argc > 4) {
		printf("Wrong usage, format is: <file_server> <users_file> <directory file> [optional:port number]. Please try again\n");
		return -1;
	} 
	
	printf("users-file path provided is: %s\n", argv[1]); //TODO:: delete this line, only for tests
	if(!isValidFilePath(argv[1])){
		printf("File doesn't exist. Please try again\n");
		return -1;
	}
	
	printf("directory path provided is: %s\n", argv[2]);//TODO:: delete this line, only for tests
	if(!doesPathExists(argv[2])){
		printf("Path to directory doesn't exist or it's not a directory, uses default path\n");
	}
	
	/** 
	 * If a fourth argument (port number) was provided, checks if it's relevant (short unsigned, meaning in range of 1 to USHRT_MAX),
	 * if it isn't - uses default port number and reports it to the user.
	 * Note: we first check that the argument provided by the user is indeed a number - all digits
	 * 			(because strtol() "accepts" strings that we define as invalid, such as: "234a" -> "234"
	 * 			 and we don't want to allow this. In this case we'll use the default port number)   
	 **/
	if (argc==4) {
		long val = strtol(argv[3], NULL, 10);
		if (!(isStringNumeric(argv[3])) || (val <= 0) || (USHRT_MAX < val)){
			printf("Port number is wrong, uses default\n");
		} else {
			portNumber = (unsigned short) val;
		}
	}

	printf("port number is: %hu\n",portNumber);//TODO:: delete this line, only for tests
	
	
	return 0;
}
