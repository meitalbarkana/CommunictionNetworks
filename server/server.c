#include "server.h"

static size_t number_of_valid_users = 0;

static unsigned short port_number = 1337; // Default value

/**
 * 	Returns true if username_to_check already exists in the array of all users.
 **/
static bool check_if_username_already_exists(const char* username_to_check, user_info*** ptr_to_all_users_info){
	for (size_t i = 0; i < number_of_valid_users; ++i){
		if (strncmp(((*ptr_to_all_users_info)[i])->username, username_to_check, MAX_USERNAME_LEN+1) == 0){
			return true; //username already exists
		}
	}
	return false;
}

/**
 *  Helper function to free memory
 **/
void free_users_array(user_info*** ptr_to_all_users_info){
	for (size_t i = 0; i < number_of_valid_users; ++i){
		free(((*ptr_to_all_users_info)[i])->username);
		free(((*ptr_to_all_users_info)[i])->password);
		free((*ptr_to_all_users_info)[i]);
	}
	number_of_valid_users = 0;
	free(*ptr_to_all_users_info);
}

/**
 *  Helper function to print info - HUST FOR TESTING!
 **/
/*static void print_users_array(user_info*** ptr_to_all_users_info){
	for (size_t i = 0; i < number_of_valid_users; ++i){
		printf("***** Details of user number %zu *****\n", i);
		printf("Username: %s\nPassword: %s\n", ((*ptr_to_all_users_info)[i])->username, ((*ptr_to_all_users_info)[i])->password);
	}
	printf("\n");
}*/

/**
 * 	Allocates pointers-to-user_info-array, and 2 temporary strings
 * 	Returns true if allocation succeded, false otherwise
 **/
static bool alloc_userinfo_array_and_temps(user_info*** ptr_to_all_users_info,char** ptr_to_temp_username, char** ptr_to_temp_password, size_t alloc_size){
	// Because sizeof(char)=1 byte, and each user's name+password are at least of 1 character for each,
	// a pointer-to-user_info-array of this size (alloc_size=st.st_size/2) is more than enough.
	if(((*ptr_to_all_users_info) = malloc(sizeof(user_info*)*(alloc_size))) == NULL) {
		return false;
	}
	
	if (((*ptr_to_temp_username) = calloc(MAX_PASSWORD_LEN+MAX_USERNAME_LEN+1, sizeof(char)))==NULL){
		free(*ptr_to_all_users_info);
		return false;
	}
	
	if (((*ptr_to_temp_password) = calloc(MAX_PASSWORD_LEN+MAX_USERNAME_LEN+1, sizeof(char)))==NULL){
		free(*ptr_to_all_users_info);		
		free(*ptr_to_temp_username);
		return false;
	}
	
	return true;
	
}

/**
 *  Allocates enough place for user_info struct and it's fields,
 * 	According to parameters provided.
 * 	Returns true on success, false otherwise.
 **/
static bool alloc_userinfo(user_info*** ptr_to_all_users_info, size_t len_temp_username, size_t len_temp_password){

	if ((((*ptr_to_all_users_info)[number_of_valid_users]) = malloc(sizeof(user_info))) == NULL){// Allocation failed
		free_users_array(ptr_to_all_users_info);
		return false;
	}
	(*ptr_to_all_users_info)[number_of_valid_users]->username = calloc(len_temp_username+1, sizeof(char)); 
	(*ptr_to_all_users_info)[number_of_valid_users]->password = calloc(len_temp_password+1, sizeof(char));
	
	if (((*ptr_to_all_users_info)[number_of_valid_users]->username == NULL) || ((*ptr_to_all_users_info)[number_of_valid_users]->password  == NULL))
	{ // Allocation failed
		if ((*ptr_to_all_users_info)[number_of_valid_users]->username != NULL){
			free((*ptr_to_all_users_info)[number_of_valid_users]->username);
		}
		if ((*ptr_to_all_users_info)[number_of_valid_users]->password != NULL){
			free((*ptr_to_all_users_info)[number_of_valid_users]->password);
		}
		free_users_array(ptr_to_all_users_info);
		return false;
	}
	
	return true;
}

/**
 *	Gets: 1. A (valid) path to a file that supposed to have a list of all usernames&passwords,
 * 			 in format: <username>\t<password>\n
 * 			 If a line is not in that format - disregards it and prints a message to stdout.
 * 			 If user name isn't unique - disregards the second (or more) encounter with it, prints a message to stdout.
 * 		  2. pointer to an array of pointers-yo-user_info, it would be initiallized and filled during this function 
 * 
 * 	Returns enum ServerErrors representing status:
 * 			1. USERS_FILE_TOO_BIG - if a file is too big
 * 			2. USERS_FILE_ERR - if something went wrong when trying to get file's stat or if all lines were invalid (no user was added)
 * 			3. USERS_FILE_ALOC_FAIL - if any allocation failed
 * 			4. USERS_FILE_NOT_OPENED - opening the file to read failed
 * 			5. USERS_FILE_NO_ERR - if everyting went o.k
 **/
static enum ServerErrors get_users_info_from_file(const char* path_to_file,user_info*** ptr_to_all_users_info){
	struct stat st;
	if ((stat(path_to_file, &st) != 0) || (st.st_size <= 0)) { //st_size is of type off_t which is signed integer - so might be negative, if an error accured..
		return USERS_FILE_ERR;
	} else if (st.st_size > MAX_FILE_SIZE) {
		return USERS_FILE_TOO_BIG;
	}
	
	FILE* fp;
	char* buffer = NULL; 
	size_t bytes_allocated = 0;
	ssize_t line_length = 0;
	char *temp_username, *temp_password;
	
	if(!alloc_userinfo_array_and_temps(ptr_to_all_users_info, &temp_username, &temp_password, st.st_size/2)){
		return USERS_FILE_ALOC_FAIL;
	}
	
	if((fp = fopen(path_to_file,"r")) == NULL){
			free(*ptr_to_all_users_info);
			free(temp_username);
			free(temp_password);
			return USERS_FILE_NOT_OPENED;
	}
	
	//Read file line-by-line:
	while ((number_of_valid_users < MAX_USERS) && ( (line_length = getline(&buffer, &bytes_allocated, fp)) != -1)){
		if ((line_length > MAX_PASSWORD_LEN+MAX_USERNAME_LEN+1) || (line_length < 3)) //|char+'\t'+char| <= line_length <= MAX_PASSWORD_LEN+|'\t'|+MAX_USERNAME_LEN
		{ 
			printf("Invalid line in file, discarded it.\n");
		} 
		else 
		{
			if ((sscanf(buffer, "%s\t%s",temp_username,temp_password) != 2) || (strlen(temp_username) == 0) || 
				(strlen(temp_password) == 0) || (strlen(temp_username) > MAX_USERNAME_LEN) || (strlen(temp_password) > MAX_PASSWORD_LEN) )
			{
				printf("Invalid format line in file, discarded it.\n");
			} 
			else //temp_username contains current username, temp_password contains his password:
			{ 
				if(check_if_username_already_exists(temp_username, ptr_to_all_users_info))
				{
					printf("Username: %s appeared more than once in users-file, considered only first appearence.\n", temp_username);
				} 
				else // It's a valid new username:
				{
					if (!alloc_userinfo(ptr_to_all_users_info, strlen(temp_username), strlen(temp_password))){
						free(buffer);
						return USERS_FILE_ALOC_FAIL;
					}
					strncpy((*ptr_to_all_users_info)[number_of_valid_users]->username, temp_username, strlen(temp_username));
					strncpy((*ptr_to_all_users_info)[number_of_valid_users]->password, temp_password, strlen(temp_password));
					number_of_valid_users++;
				}
			}
		}
		free(buffer);
		buffer = NULL;
	}
	
	free(buffer);
	free(temp_username);
	free(temp_password);
	fclose(fp);
	if (number_of_valid_users==0){
		free((*ptr_to_all_users_info));
		return USERS_FILE_ERR;
	}
	return USERS_FILE_NO_ERR;
}

/**
 * Gets user name, and if it's in "ptr_to_all_users_info" - deletes that user_info from the array,
 * updates number_of_valid_users (and moves all pointers accordingly)
 **/
static void delete_user_from_list(const char* username_to_delete, user_info*** ptr_to_all_users_info){
	for (size_t i = 0; i < number_of_valid_users; ++i){
		if (strncmp(((*ptr_to_all_users_info)[i])->username, username_to_delete, MAX_USERNAME_LEN+1) == 0){
			free(((*ptr_to_all_users_info)[i])->username);
			free(((*ptr_to_all_users_info)[i])->password);
			free((*ptr_to_all_users_info)[i]);
			//update pointers:
			for (size_t j = 0; j < (number_of_valid_users-i-1); ++j){
				((*ptr_to_all_users_info)[j+i]) = ((*ptr_to_all_users_info)[j+i+1]);	
			}
			((*ptr_to_all_users_info)[number_of_valid_users-1]) = NULL;
			number_of_valid_users--;
			return;
		}
	}
}

/**
 *	Creates directory for each user in ptr_to_all_users_info,
 * 	at path "path". 
 *  Returns true if at least 1 directory was created.
 **/
static bool create_directories(user_info*** ptr_to_all_users_info, char*const *ptr_dir_path){
	bool res = false;
	
	for (size_t i = 0; i < number_of_valid_users; ++i){	
		char* dir_name = concat_strings((*ptr_dir_path), (((*ptr_to_all_users_info)[i])->username));
		if (dir_name == NULL) { //Allocation failed:
			printf("Creating directory for user: %s failed, deleting this user from user-list\n", ((*ptr_to_all_users_info)[i])->username);
			delete_user_from_list((((*ptr_to_all_users_info)[i])->username) ,ptr_to_all_users_info);
			continue;
		}
		if(mkdir(dir_name, (S_IRWXU||S_IRWXG||S_IRWXO)) ==0 ) { //If succeed creating the directory
			res = true;
		} else { //Creating directory failed
			printf("Creating directory for user: %s failed, deleting this user from user-list\n", ((*ptr_to_all_users_info)[i])->username);
			delete_user_from_list((((*ptr_to_all_users_info)[i])->username) ,ptr_to_all_users_info);
		}
		free(dir_name);
	}
	return res;
}


user_info** init_server(int argc, char* argv[], char** ptr_dir_path){
	char *file_path;
	if (argc < 3 || argc > 4) {
		printf("Wrong usage, format is: <file_server> <users_file> <directory file> [optional:port number]. Please try again\n");
		return NULL;
	} 
	
	//printf("users-file path provided is: %s\n", argv[1]); //Test Line
	if(!isValidFilePath(argv[1])){
		printf("File doesn't exist. Please try again\n");
		return NULL;
	}
	file_path = argv[1];
	
	if(!doesPathExists(argv[2])){
		printf("Path to directory doesn't exist or it's not a directory. Please try again.\n");
		return NULL;
	}
	//Make sure "*ptr_dir_path" includes character / at its end:
	if ( (argv[2])[strlen(argv[2])-1] != '/' ) {
		(*ptr_dir_path) = concat_strings(argv[2],"/");
	} else {
		(*ptr_dir_path) = concat_strings(argv[2],"");
	}
	if ((*ptr_dir_path) == NULL){
		return NULL;
	}
	//printf("Valid directory path provided is: %s\n", (*ptr_dir_path)); //Test Line
	
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
			port_number = (unsigned short) val;
		}
	}
	//printf("port number is: %hu\n",port_number); //Test Line
	
	user_info** ptr_all_users_info = NULL;
	enum ServerErrors answ = get_users_info_from_file(file_path, &ptr_all_users_info);
	if (answ != USERS_FILE_NO_ERR){
		switch (answ){
				case (USERS_FILE_TOO_BIG):
					printf("Provided file is too big\n");
					break;
				case (USERS_FILE_ALOC_FAIL):
					printf("Allocation failed when trying to create users-information from file\n");
					break;
				case (USERS_FILE_NOT_OPENED):
					printf("Opening user-file failed, couldn't proceed\n");
					break;
				default:
					printf("An error accured when trying to get file's stat or all lines were invalid (no user was added), couldn't proceed\n");
		}
		free((*ptr_dir_path));
		return NULL;
	}
	//print_users_array(&ptr_all_users_info); //Test Line
	
	if(!create_directories(&ptr_all_users_info, ptr_dir_path)) {
		printf("No directories were created for users\n");
		free_users_array(&ptr_all_users_info);
		free((*ptr_dir_path));
		return NULL;
	}
	
	return ptr_all_users_info;
}


int main(int argc, char* argv[]){
	
	char* dir_path = NULL;
	user_info** ptr_all_users_info = init_server(argc, argv, &dir_path);
	
	if(ptr_all_users_info == NULL) {
		printf("Initiating server failed\n");
		return -1;
	}
	
	//print_users_array(&ptr_all_users_info); //Test Line
	free_users_array(&ptr_all_users_info);
	free(dir_path);
	return 0;
}
