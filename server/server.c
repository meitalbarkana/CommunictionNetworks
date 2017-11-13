#include "../utilities.h"
#include <stdlib.h> // For strtol()
#include <limits.h> // For constant USHRT_MAX

/**enum errors {
	
}**/

static unsigned short portNumber = 1337; // Default value

int main(int argc, char* argv[]){
	
	if (argc < 3 || argc > 4) {
		printf("Wrong usage, format is: <file_server> <users_file> <directory file> [optional:port number]. Please try again\n");
		return -1;
	} 
	
	printf("users-file path provided is: %s\n", argv[1]);	
	if(!isValidFilePath(argv[1])){
		printf("File doesn't exist. Please try again\n");
		return -1;
	}
	
	printf("directory path provided is: %s\n", argv[2]);
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

	printf("port number is: %hu\n",portNumber);
	return 0;
}
