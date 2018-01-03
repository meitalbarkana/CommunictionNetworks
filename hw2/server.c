#include "server.h"

static size_t number_of_valid_users = 0;

static unsigned short port_number = (unsigned short) DEFAULT_PORT_NUM; // Default port value

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
 *  Helper function to print info - JUST FOR TESTING!
 **/
/*static void print_users_array(user_info*** ptr_to_all_users_info){
	for (size_t i = 0; i < number_of_valid_users; ++i){
		printf("***** Details of user number %zu *****\n", i);
		printf("Username: %s\nPassword: %s\n", ((*ptr_to_all_users_info)[i])->username, ((*ptr_to_all_users_info)[i])->password);
	}
	printf("\n");
}*/

/**
 * 	Helper function, that on success returns a string representing full path to file_name:
 * 	(in format: dir_path/user_name/file_name)
 * 	Note: dir_path already contains '/' at its end.
 *		  User of this function should free allocated memory of the string returned.
 * 	Returns NULL if failed.
 **/
static char* generate_path_to_file(const char* dir_path, const char* user_name, const char* file_name){
	char *temp1, *temp2, *path_to_file;
	if((dir_path == NULL) || (user_name == NULL) || (file_name == NULL)){
		printf("Error: generate_path_to_file got NULL argument!\n");
		return NULL;
	}
	if((temp1 = concat_strings(dir_path, user_name, false)) == NULL){ //Allocation failed
		return NULL;
	}
	if((temp2 = concat_strings(temp1, "/", false)) == NULL){
		free (temp1);
		return NULL;
	}
	free (temp1);
	if((path_to_file = concat_strings(temp2, file_name, false)) == NULL) {
		free (temp1);
		free (temp2);
		return NULL;
	}
	free(temp2);
	return path_to_file;
}


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
 *  Allocates enough space for user_info struct and it's fields,
 * 	According to parameters provided.
 *	Initiates fields to default values.
 * 
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
	
	(*ptr_to_all_users_info)[number_of_valid_users]->client_status = USER_IS_OFFLINE;
	(*ptr_to_all_users_info)[number_of_valid_users]->num_authentication_attempts = 0;
	(*ptr_to_all_users_info)[number_of_valid_users]->client_sockfd = NO_SOCKFD;
	memset( &((*ptr_to_all_users_info)[number_of_valid_users]->client_addr),
			0, sizeof(struct sockaddr_in) );
	
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
	if ((stat(path_to_file, &st) != 0) || (st.st_size <= 0)) { //st_size is of type off_t which is signed integer - so might be negative, if an error occurred..
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
 *	Creates a file named STR_OFFLINE_FILE in each user's directory.
 * 
 *  Returns true if at least 1 directory was created.
 **/
static bool create_directories(user_info*** ptr_to_all_users_info, char*const *ptr_dir_path){
	FILE* fp = NULL;
	bool res = false;
	
	for (size_t i = 0; i < number_of_valid_users; ++i){	
		char* dir_name = concat_strings((*ptr_dir_path), (((*ptr_to_all_users_info)[i])->username), false);
		if (dir_name == NULL) { //Allocation failed:
			printf("Creating directory for user: %s failed, deleting this user from user-list\n", ((*ptr_to_all_users_info)[i])->username);
			delete_user_from_list((((*ptr_to_all_users_info)[i])->username) ,ptr_to_all_users_info);
			i--; //Because delete_user_from_list() removes the current user, so next user is now placed in current position i
			continue;
		}
		if(mkdir(dir_name, (S_IRWXU | S_IRWXG | S_IRWXO)) == 0 ) { //If succeed creating the directory
			
			//Create the file STR_OFFLINE_FILE in that directory:
			char* offline_file_name = generate_path_to_file( (*ptr_dir_path),
					(((*ptr_to_all_users_info)[i])->username), STR_OFFLINE_FILE );
			
			if ( (offline_file_name == NULL) ||
				((fp = fopen(offline_file_name, "w")) == NULL) )
			{ //Allocation or creating file failed:
				if (offline_file_name){
					free(offline_file_name);
				}
				printf("Creating file for messages received offline for user: %s failed, deleting this user from user-list.\n", 
						((*ptr_to_all_users_info)[i])->username);
				delete_user_from_list((((*ptr_to_all_users_info)[i])->username) ,ptr_to_all_users_info);
				i--; //Because delete_user_from_list() removes the current user, so next user is now placed in current position i
				continue;
			}
			fclose(fp);
			free(offline_file_name);
			res = true;
			
		} else { //Creating directory failed
			printf("Creating directory for user: %s failed, deleting this user from user-list\n", ((*ptr_to_all_users_info)[i])->username);
			delete_user_from_list((((*ptr_to_all_users_info)[i])->username) ,ptr_to_all_users_info);
			i--; //Because delete_user_from_list() removes the current user, so next user is now placed in current position i
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
		(*ptr_dir_path) = concat_strings(argv[2],"/",false);
	} else {
		(*ptr_dir_path) = concat_strings(argv[2],"", false);
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
					printf("An error occurred when trying to get file's stat or all lines were invalid (no user was added), couldn't proceed\n");
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

/**
 * 	Returns true if usern_to_check & passw_to_check fits a valid user
 **/
bool is_username_password_correct (user_info*** ptr_to_all_users_info,const char* usern_to_check, const char* passw_to_check){
	for (size_t i = 0; i < number_of_valid_users; ++i){
		if ((strncmp(((*ptr_to_all_users_info)[i])->username, usern_to_check, MAX_USERNAME_LEN+1) == 0) &&
			(strncmp(((*ptr_to_all_users_info)[i])->password, passw_to_check, MAX_PASSWORD_LEN+1) == 0)){
			return true;
		}
	}
	return false;
}

/**
 * 	Gets: char** usern , char** passw - pointers to addresses allocted&nullified in sizes of MAX_USERNAME_LEN+1,MAX_PASSWORD_LEN+1 accordingly.
 * 	If buff is indeed of the format:
 * 	"<username>\n<password>\n"
 * 	updates (*usern), (*passw) to contain the relevant values and returns true.
 * 	Otherwise, returns false.
 **/
bool exstract_username_password_from_msg(const char* buff, char** usern , char** passw){
	size_t max_valid_len = MAX_PASSWORD_LEN+MAX_USERNAME_LEN+strlen("\n\n");
	if (strlen(buff)>max_valid_len){
		return false;
	}
	if (sscanf(buff, "%s\n%s\n", (*usern),(*passw)) != 2){
		return false;
	}
	return true;
} 

/**
 * 	Gets: char* file_name , char* txt - which will be allocted&nullified to size of msg_length+1.
 * 	If buff is indeed of the format:
 * 	"<file_name>\n<txt>"
 * 	updates (*file_name), (*txt) to contain the relevant values and returns true.
 * 	Otherwise, returns false.
 * 
 * Note: user of this function should free memory allocated in it
 **/
static bool exstract_fname_txt_from_msg(const char* buff, char** file_name , unsigned char** txt, size_t msg_len){
	if ((*file_name = calloc(msg_len+1,sizeof(char))) == NULL){
		return false;
	}
	if ((*txt = calloc(msg_len+1,sizeof(unsigned char))) == NULL){
		free(file_name);
		return false;
	}
	
	size_t i = 0;
    size_t counter = 0;
    while (i < msg_len){
        if (buff[i] == '\n' && counter == 0){
            counter++;
            i++;
            continue;
        }
        if (counter == 0){
            memcpy(&((*file_name)[i]), &buff[i], 1);
        } else {
            memcpy(&((*txt)[i-(strlen(*file_name))-1]), &buff[i], 1); //-1 for '\n'
        }
		++i;
    }

	if (strlen(*file_name) == 0){ //strlen(txt) might be 0 (if file is empty)
		free(*file_name);
		free(*txt);
		return false;
	}
	printDebugString("file name extracted from msg is:");
	printDebugString(*file_name);
	printDebugString("txt extracted from msg is:");
	printDebugString((char*)*txt);	
	return true;
} 


/**
 * 	Returns true if buff indeed == "<username>\n<password>\n" of a valid user
 * 	Updates *user_name to contain the valid username
 **/
static bool is_valid_user(user_info*** ptr_to_all_users_info, const char* buff, char** user_name){
	bool ans = false;
	char *passw_to_check;
	if (((*user_name) = calloc(MAX_USERNAME_LEN*2, sizeof(char))) == NULL){ //*2 to make sure no overflow would happen in "exstract_username_password_from_msg()"
		printf("Allocation failed\n");
		return false;
	}
	if ((passw_to_check = calloc(MAX_PASSWORD_LEN*2, sizeof(char))) == NULL){
		printf("Allocation failed\n");
		free (*user_name);
		return false;
	}
	if(!exstract_username_password_from_msg(buff, user_name, &passw_to_check)){
		printf("Invalid format. please try again, use format:\n<username>\nPassword\n");//ans = false
	} else {
		ans = is_username_password_correct(ptr_to_all_users_info, *user_name, passw_to_check);
	}
	free(passw_to_check);
	return ans;
}

/**
 * 	Gets a valid directory name, 
 * 	Returns a null-terminated string containing a list of (regular) files in directory,
 * 			in format: <nameoffile1>\n<nameoffile2>\n...
 * 	Number of files in that list would be <= MAX_FILES_FOR_USER
 *  Note: user should free allocated memory (of returned char*)
 **/
static char* get_list_of_files(const char* dir_path){
	char* ret_val = concat_strings("","",false); //Allocates an empty string
	char* temp_val = NULL;
	DIR *dp;
	struct dirent *ep;
	int i = 0;
	
	dp = opendir (dir_path);
	if (dp == NULL)
    {
		printf("Couldn't open the directory\n");
		return NULL;
    }
    
	while ((ep = (struct dirent*)readdir(dp)) && (i < MAX_FILES_FOR_USER)){
		if (ep->d_type == DT_REG){ //Insert only regular files to the list
			temp_val = concat_strings(ret_val,ep->d_name, true); 
			if (temp_val == NULL) { //Concat failed
				break;
			}
			free(ret_val);
			ret_val = temp_val;
			++i;
		}

	}
	if(closedir(dp)!=0){ //Closing directory failed 
		printf("Error: closing directory failed. error is: %s. Continue...\n", strerror(errno));
	}
	return ret_val;
}

/**
 *  Gets file_name of the file user asked to delete, and a path to the user's directory (that ends with '/')
 * 	Deletes the asked file.
 *  Returns: 1. FILE_DELETED_SUCCESSFULLY - on success
 *			 2. FILE_WASNT_FOUND - if there's no such file
 *			 3. FILE_DELETION_FAILED - if any other error occurred.
 **/
static enum DeleteFileStatus delete_users_file(const char* file_name, const char* user_dir_path){
	char* path_to_file = concat_strings(user_dir_path, file_name, false);
	if (path_to_file == NULL) {
		printf("Allocation error, couldn't create full path to file.\n");
		return FILE_DELETION_FAILED;
	}
	if (!isValidFilePath(path_to_file)){ //checks if this is a regular file indeed
		free(path_to_file);
		return FILE_WASNT_FOUND;
	}
	int succeed_delete = remove(path_to_file);
	free(path_to_file);
	if (succeed_delete == 0) {
		return FILE_DELETED_SUCCESSFULLY;
	}
	return FILE_DELETION_FAILED;
} 

/**
 * 	Gets a valid user_name, the directory-path that contains all users directories,
 *  adds to the user directory the file "file_name" which contains (*txt).
 * 	Returns:
 * 			1. FILE_ADDED_SUCCESSFULLY - on success,
 *			2. FILE_ALREADY_EXIST - if file already exists, it WON'T be overwritten.
 * 			3. FILE_ADDITION_FAILED - if failed
 **/
static enum AddFileStatus write_txt_to_file(const char* dir_path, const char* user_name, unsigned char** txt, const char* file_name){
	
	enum AddFileStatus ret =  FILE_ADDITION_FAILED;
	
	char* path_to_file;
	
	if((dir_path == NULL) || (user_name == NULL) || (file_name == NULL) || (txt==NULL) || (*txt==NULL)){
		printf("Error: write_txt_to_file got NULL argument!\n");//Never supposed to get here
		return FILE_ADDITION_FAILED;
	}
	
	if((path_to_file = generate_path_to_file(dir_path, user_name, file_name)) == NULL ){ //Couldn't generate full-path to the file
		return FILE_ADDITION_FAILED;
	}
	
	if(isValidFilePath(path_to_file)) { //Means this file already exist
		ret = FILE_ALREADY_EXIST;
	}
	else 
	{
		if (!StringTofile(*txt, path_to_file)){ //Means writing *txt to file failed 
			ret = FILE_ADDITION_FAILED;
		} else {
			ret = FILE_ADDED_SUCCESSFULLY;
		}
	}
	
	free(path_to_file);
	return ret;
}

/**
 * 	Helper function:
 *  	Allocates enough space so that (*txt) will contain a copy of the string str. 
 * 		If fails, (*txt) will be NULL
 *	Note: user of this function should free memory allocated in (*txt)
 **/
static void cpy_str_to_txt(unsigned char* str, unsigned char** txt){
	if (((*txt) = calloc(strlen((char*)str)+1, sizeof(unsigned char))) != NULL){
		memcpy((*txt), str, strlen((char*)str)); // used calloc, no need to copy null-terminator
	} 
}

/**
 * 	Gets a valid user_name, the directory-path that contains all users directories, and the name of the file asked by the client.
 * 	Updates (*txt) to contain:
 * 		 On success - the content of the file "file_name"
 * 		 On failure - the reason for failure/NULL
 *  Returns:
 * 		 1. FILE_CONTENT_IN_TXT_SUCCESSFULLY - if succeeded
 *		 2.	FILE_DOESNT_EXIST - if file doesn't exist 
 *		 3. FILE_GET_FAILED - if ant other error occurred
 * 	Note: user has to free memory allocated in (*txt)
 **/
static enum GetFileStatus get_txt_from_file(const char* dir_path, const char* user_name, unsigned char** txt, const char* file_name){
		char* path_to_file;
		long file_size;
		if ((path_to_file = generate_path_to_file(dir_path, user_name, file_name)) == NULL){ //Couldn't generate full-path to the file
			cpy_str_to_txt((unsigned char*)"get_file failed: server allocation error", txt);
			return FILE_GET_FAILED;
		}
		
		if(!isValidFilePath(path_to_file)){
			free(path_to_file);
			return FILE_DOESNT_EXIST;
		}
		
		if(!fileToString(txt, path_to_file, &file_size)){
			free(path_to_file);
			return FILE_GET_FAILED;
		}
		free(path_to_file);
		return FILE_CONTENT_IN_TXT_SUCCESSFULLY;
}

/**
 * 	Helper function - initiates socket for the server to use.
 * 	Updates (*server_addr) values
 *  Returns:
 * 		On success: the socketfd,
 * 		On failure: -1.
 **/
static int init_sock(struct sockaddr_in* server_addr){
	
	int sockfd;
	if ((sockfd = socket(AF_INET, SOCK_STREAM,0)) == -1){
		printf("Creating socket failed, error is: %s.\n Closing server.\n",strerror(errno));
		return -1;
	}

	memset(server_addr, 0, sizeof(struct sockaddr_in));
	
	(*server_addr).sin_family = AF_INET;
	(*server_addr).sin_port = htons(port_number);
	(*server_addr).sin_addr.s_addr = htonl(INADDR_ANY);

	if(bind(sockfd, server_addr, sizeof(struct sockaddr_in)) != 0){
		printf("Binding socket to IP failed, error is: %s.\n Closing server.\n",strerror(errno));
		return -1;
	}
	
	if (listen(sockfd, BACKLOG_CONST_VALUE) != 0){
		printf("Listen() failed, error is: %s.\n Closing server.\n",strerror(errno));
		return -1;
	}
	
	return sockfd;
}


/**
 * 	Generetes the welcome message to send client - updates (*wel_msg) to contain it (including prefix)
 * 	Returns: On success - length of the msg (including prefix)
 * 			 On failure - -1
 **/ 
static int generate_welcome_msg(unsigned char** wel_msg){
	char* str = "Welcome! Please log in.";
	(*wel_msg) = calloc(SIZE_OF_PREFIX+strlen(str), sizeof(unsigned char));
	if ((*wel_msg) == NULL) {
		printf("Generating welcome message failed\n");
		return -1;
	}
	intToString(strlen(str), SIZE_OF_LEN, *wel_msg); //Adds the length-prefix of welcome-msg (neto) to it
	intToString(SERVER_WELCOME_MSG, SIZE_OF_TYPE, (*wel_msg)+SIZE_OF_LEN);
	memcpy((*wel_msg)+SIZE_OF_PREFIX, str, strlen(str));
	return SIZE_OF_PREFIX+strlen(str);
}

/**
 * 	Returns true if succeeded sending a welcome message to sockfd, false otherwise
 **/
 
static bool send_welcome_msg(int sockfd){
	unsigned char* wel_msg;
	int lenOfMsg;
	
	if (((lenOfMsg = generate_welcome_msg(&wel_msg)) < 0) || (sendall(sockfd, wel_msg, &lenOfMsg) < 0)) {
		free(wel_msg);
		return false;
	}

	free(wel_msg);
	return true; 
}


/**
 * 	Generetes the status msg to send client - updates (*wel_msg) to contain it (including prefix)
 * 	Gets the USERs directory path, valid user's name.
 * 	Returns: On success: length of the msg (including prefix)
 * 			 On failure: -1
 **/ 
static int generate_status_msg(unsigned char** wel_msg, const char* user_dir_path, const char* user_name){
	size_t max_info_len = strlen("Hi , you have  files stored.") + MAX_USERNAME_LEN + 10; //Maximum int=2^32 decimal-representation uses 10 characters
	int num_files = number_of_files_in_directory(user_dir_path, MAX_FILES_FOR_USER);
	char* buff;
	if ((num_files < 0) || ((buff = calloc(max_info_len+1,sizeof(char))) == NULL)){
		printf("Couldn't generate status message\n");
		return -1;
	}
	
	sprintf(buff,"Hi %s, you have %d files stored.", user_name, num_files); //Since num_files>=0, it'll be safe to convert buff afterwards to unsigned
	
	(*wel_msg) = calloc(SIZE_OF_PREFIX+strlen(buff), sizeof(unsigned char));
	if ((*wel_msg) == NULL) {
		printf("Generating status message failed\n");
		free(buff);
		return -1;
	}
	intToString(strlen(buff), SIZE_OF_LEN, *wel_msg); //Adds the length-prefix of welcome-msg (neto) to it
	intToString(SERVER_LOGIN_PASS_MSG, SIZE_OF_TYPE, (*wel_msg)+SIZE_OF_LEN);
	memcpy((*wel_msg)+SIZE_OF_PREFIX, buff, strlen(buff));
	int ret_val = SIZE_OF_PREFIX+strlen(buff);
	free(buff);
	return ret_val;
}

/**
 * 	Gets an open socket fd, waits for client to authenticate.
 * 	If client sent valid info, updates user_name to contain clients' username.
 * 	Returns true if suceeded, false otherwise.
 **/
static bool get_user_details(int sockfd, char** user_name, user_info*** ptr_to_all_users_info){
	struct msg m = { NULL, -1, -1 };
	if(getMSG(sockfd, &m) < 0){
		return false; //Failed getting msg
	}
	if(m.type != CLIENT_LOGIN_MSG){ //msg is from wrong format
		free(m.msg);
		return false;
	}
	if(!is_valid_user(ptr_to_all_users_info, (char*)m.msg, user_name)){
		if (*user_name != NULL){
			free(*user_name);
		}
		free(m.msg);
		return false;
	}
	free(m.msg);
	return true;
}

/**
 * 	Sends client a message that login failed.
 * 	Returns true if succeded
 **/
static bool send_server_login_failed_msg(int sockfd){
	int len = SIZE_OF_PREFIX;
	unsigned char* msg = (unsigned char*) malloc(SIZE_OF_PREFIX);
	if (msg == NULL) {
		printf("Allocating msg space failed\n");
		return false;
	}
	intToString(0, SIZE_OF_LEN, msg);
	intToString(SERVER_LOGIN_FAIL_MSG, SIZE_OF_TYPE, msg + SIZE_OF_LEN);
	if (sendall(sockfd, msg, &len) < 0) {
		free(msg);
		return false;
	}
	free(msg);
	return true;
}

/**
 * Sends client a message with the status [format: "Hi <username>, you have <|files in users' directory|> files stored."]
 * Returns true if succeeded.
 **/
static bool send_status_msg(int sockfd, const char* user_dir_path, const char* user_name){
	unsigned char* wel_msg;
	int msg_len = generate_status_msg(&wel_msg, user_dir_path, user_name);
	if(msg_len < 0) {
		return false;
	}
	if (sendall(sockfd, wel_msg, &msg_len) < 0) {
		free(wel_msg);
		return false;
	}
	free(wel_msg);
	return true;
}

/**
 *  Gets a valid path to user's directory, and the socket fd.
 * 	Sends the client a list of his files, in format: 
 * 	<filename>\n<filename> ...
 * Returns true if succeeded
 **/
static bool send_listfiles_to_client(int sockfd, const char* user_dir_path){

	char* files_list = get_list_of_files(user_dir_path); //files_list is null-terminated.
	if (files_list == NULL) {
		return false;
	}
	size_t str_len = strlen(files_list);
	unsigned char* files_msg = calloc(SIZE_OF_PREFIX+str_len, sizeof(unsigned char));
	if (files_msg == NULL) {
		printf("Generating list-of-files msg failed.\n");
		free(files_list);
		return false;
	}
	
	intToString(str_len, SIZE_OF_LEN, files_msg);
	intToString(SERVER_FILES_LIST_MSG, SIZE_OF_TYPE, files_msg+SIZE_OF_LEN);
	memcpy(files_msg+SIZE_OF_PREFIX, files_list, str_len);
	free(files_list);
	
	int files_msg_len = SIZE_OF_PREFIX+str_len;
	if (sendall(sockfd, files_msg, &files_msg_len) < 0) {
		printf("Sending list-of-files to client failed.\n");
		free(files_msg);
		return false;
	}
	free(files_msg);
	return true;

}

/**
 *  Gets a valid path to user's directory(DOESN'T end with '/'), the socket fd,
 *  and the name of the user's file to be deleted.
 * 	Deletes & sends the client report about the deletion 
 * 	
 * 	Returns true if reporting client succeeded
 **/
static bool delete_file_and_report_client(int sockfd, const char* user_dir_path, const char* temp_fname){
	printDebugString("in delete_file_and_report_client, trying to delete file:");
	printDebugString(temp_fname);
	char* full_user_dir_path = concat_strings(user_dir_path, "/", false);
	if (full_user_dir_path == NULL) {
		printf("Allocation failed when trying to delete a file client has asked\n");
		return false;
	}
	enum DeleteFileStatus dfs = delete_users_file(temp_fname, full_user_dir_path);
	char* msg_txt;
	switch(dfs){
		case(FILE_DELETED_SUCCESSFULLY):
			msg_txt = "File removed";
			break;
		case(FILE_WASNT_FOUND):
			msg_txt = "No such file exists!";
			break;
		default: //case(FILE_DELETION_FAILED):
			msg_txt = "File deletion failed.";
	}
	free (full_user_dir_path);
	
	unsigned char* total_msg = calloc(SIZE_OF_PREFIX+strlen(msg_txt), sizeof(unsigned char));
	if (total_msg == NULL) {
		printf("Generating msg about file deletion failed.\n");
		return false;
	}
	
	intToString(strlen(msg_txt), SIZE_OF_LEN, total_msg);
	intToString(SERVER_FILE_REMOVE_MSG, SIZE_OF_TYPE, total_msg+SIZE_OF_LEN);
	memcpy(total_msg+SIZE_OF_PREFIX, msg_txt, strlen(msg_txt));

	int total_msg_len = SIZE_OF_PREFIX+strlen(msg_txt);
	if (sendall(sockfd, total_msg, &total_msg_len) < 0) {
		printf("Sending info about file-deletion to client failed.\n");
		free(total_msg);
		return false;
	}
	free(total_msg);
	return true;
}

/**
 * 	Helper function: sends client a message that adding file succeeded/failed.
 * 	@sockfd
 * 	@msg_txt - Null-terminated string describing the failure,
 * 				(what we want the client to know)
 * 
 * 	Returns true if succeeded
 **/
static bool send_client_add_msg_result(int sockfd, const char* msg_txt){
	
	unsigned char* total_msg = calloc(SIZE_OF_PREFIX+strlen(msg_txt), sizeof(unsigned char));
	if (total_msg == NULL) {
		printf("Generating msg about file addition failed.\n");
		return false;
	}
	
	intToString(strlen(msg_txt), SIZE_OF_LEN, total_msg);
	intToString(SERVER_FILE_ADD_MSG, SIZE_OF_TYPE, total_msg+SIZE_OF_LEN);
	memcpy(total_msg+SIZE_OF_PREFIX, msg_txt, strlen(msg_txt));

	int total_msg_len = SIZE_OF_PREFIX+strlen(msg_txt);
	if (sendall(sockfd, total_msg, &total_msg_len) < 0) {
		printf("Sending info about file-addition to client failed.\n");
		free(total_msg);
		return false;
	}
	free(total_msg);
	return true;
}

/**
 *  Gets: 	the socket fd,
 * 		 	a valid path to ALL users directory (ends with '/'),
 * 			the name of the user,
 * 			the content (txt) we want to write to the file,
 *  		the name of the file to be added. 
 * 	Adds & sends the client report about the addition 
 * 	
 * 	Returns true if succeeded sending report to client.
 **/
static bool add_file_and_report_client(int sockfd, const char* dir_path, const char* user_name, unsigned char** txt, const char* file_name){
	
	enum AddFileStatus afs = write_txt_to_file(dir_path, user_name, txt, file_name);
	char* msg_txt;
	switch(afs){
		case(FILE_ADDED_SUCCESSFULLY):
			msg_txt = "File added.";
			break;
		
		case(FILE_ALREADY_EXIST):
			msg_txt = "File already exists - no file was added.";
			break;
		
		default: //FILE_ADDITION_FAILED
			msg_txt = "Adding file failed.";
	}
	
	return (send_client_add_msg_result(sockfd, msg_txt));

}

/**
 *  Gets: 	the socket fd,
 * 		 	a valid path to ALL users directory (ends with '/'),
 * 			the name of the user,
 *  		the name of the file to be sent. 
 * 	Sends client a msg containing the file. 
 * 	
 * 	Returns true if succeeded sending to client.
 **/
static bool send_file_to_client(int sockfd, const char* dir_path, const char* user_name, const char* file_name){
	
	unsigned char* txt = NULL;
	unsigned char* msg_txt;
	enum GetFileStatus gfs = get_txt_from_file(dir_path, user_name, &txt, file_name);
	
	switch(gfs){
		case(FILE_CONTENT_IN_TXT_SUCCESSFULLY):
			break;
		case(FILE_DOESNT_EXIST):
			msg_txt = (unsigned char*)"File doesn't exist.";
			break;
		default: //FILE_GET_FAILED
			msg_txt = (unsigned char*)"Server failed getting file";
	}
	
	size_t str_len = (gfs == FILE_CONTENT_IN_TXT_SUCCESSFULLY) ? strlen((char*)(txt)) : strlen((char*)msg_txt);
	
	unsigned char* total_msg = calloc(SIZE_OF_PREFIX+str_len, sizeof(unsigned char));
	if (total_msg == NULL) {
		printf("Generating msg about downloading msg failed.\n");
		if (gfs == FILE_CONTENT_IN_TXT_SUCCESSFULLY) {
			free(txt);
		}
		return false;
	}
	
	intToString(str_len, SIZE_OF_LEN, total_msg);
	if(gfs == FILE_CONTENT_IN_TXT_SUCCESSFULLY) {
		intToString(SERVER_FILE_DOWNLOAD_MSG, SIZE_OF_TYPE, total_msg+SIZE_OF_LEN);
		memcpy(total_msg+SIZE_OF_PREFIX, txt, str_len);
		printDebugString("Inside send_file_to_client, txt is:");
		printDebugString((char*)txt);
		free(txt);
	} else {
		intToString(SERVER_FILE_DOWNLOAD_FAILED_MSG, SIZE_OF_TYPE, total_msg+SIZE_OF_LEN);
		memcpy(total_msg+SIZE_OF_PREFIX, msg_txt, str_len);
	}
	
	int total_msg_len = SIZE_OF_PREFIX+str_len;
	if (sendall(sockfd, total_msg, &total_msg_len) < 0) {
		printf("Sending downloaded file to client failed.\n");
		free(total_msg);
		return false;
	}
	free(total_msg);
	return true;

}



/**
 * 	Takes care of getting a message from client (that isn't the login message)
 * 	Gets:	the open socket fd,
 * 			pointer to all users' info,
 * 			path to the directory where all users' directories are,
 * 			path to this specific user's directory(that doesn't end with '/')
 * 			and the current user's name
 * 
 * 	Updates: (*end_connection) to true if client asked "quit"
 * 
 * 	Returns: true if msg was treated successfully,
 * 			 false when communication has ended:  some error happend / user sent invalid msg
 **/
static bool get_msg_and_answer_it(int sockfd, user_info*** ptr_to_all_users_info, char*const *ptr_dir_path,const char* user_dir_path, const char* user_name, bool* end_connection){
	printDebugString("inside get_msg_and_answer_it\n");
	char* temp_fname = NULL;
	char* buff = NULL;
	unsigned char* txt = NULL;
	struct msg m = { NULL, -1, -1 };
	if (getMSG(sockfd, &m) < 0){
		printf("Server failed to get response\n");
		return false; //failed getting msg
	}
	if (m.len < 0){
		printf("Recieved invalid message\n");
		free(m.msg);
		return false;
	}
	printDebugString("in get_msg_and_answer_it, msg type is:");
	printDebugInt((int)m.type);
	switch(m.type){
		
		case(CLIENT_FILES_LIST_MSG):
			if (!send_listfiles_to_client(sockfd, user_dir_path)){
				free(m.msg);
				return false;
			}
			break;
			
		case(CLIENT_FILE_DELETE_MSG):
			temp_fname = calloc(m.len, sizeof(char)); //Since m.len includes '\n' but doesn't include '\0', they'll be the same length
			if (temp_fname == NULL){
				printf("Allocation failed when trying to delete a file client has asked\n");
				free(m.msg);
				return false;
			}
			strncpy(temp_fname, (char*)m.msg, m.len);
			
			if(!delete_file_and_report_client(sockfd, user_dir_path, temp_fname)){
				free(temp_fname);
				free(m.msg);
				return false;
			}
			free (temp_fname);
			break;
			
		case(CLIENT_FILE_ADD_MSG):
					
			if(number_of_files_in_directory(user_dir_path, MAX_FILES_FOR_USER) >= MAX_FILES_FOR_USER){
				printf("User tried adding more files than allowed\n");
				free(m.msg);
				return(send_client_add_msg_result(sockfd, "Adding file failed: maximum amount of files, delete one to make room."));
			}
		
			buff = calloc(m.len+1, sizeof(char));
			if (buff == NULL){
				printf("Allocation failed when trying to add file client has asked\n");
				send_client_add_msg_result(sockfd, "Adding file failed: server error");
				free(m.msg);
				return false;
			}
			strncpy(buff, (char*)m.msg, m.len);
			
			size_t msg_len = (size_t)m.len; //Safe casting since m.len>=0
			printDebugString("msg_len value is:");
			printDebugInt(msg_len);
			if(!exstract_fname_txt_from_msg(buff, &temp_fname, &txt, msg_len)){
				printf("Extracting name of file and its content from clients' msg failed\n");
				send_client_add_msg_result(sockfd, "Adding file failed: extracting filename and its content failed.");
				free(buff);
				free(m.msg);
				return false;
			}
			free(buff);
			if (!add_file_and_report_client(sockfd, *ptr_dir_path, user_name, &txt, temp_fname)){
				printf("Adding file asked by client failed.\n");
				free(txt);
				free(temp_fname);
				free(m.msg);
				return false;
			}
			free(txt);
			free(temp_fname);
			break;
		
		case(CLIENT_FILE_DOWNLOAD_MSG):
		
			temp_fname = calloc(m.len+1, sizeof(char));
			if (temp_fname == NULL){
				printf("Allocation failed when trying to send file client has asked\n");
				free(m.msg);
				return false;
			}
			strncpy(temp_fname, (char*)m.msg, m.len);
			
			if(!send_file_to_client(sockfd, *ptr_dir_path, user_name, temp_fname)){
				free(temp_fname);
				free(m.msg);
				return false;
			}
			free(temp_fname);
			break;
		
		case(CLIENT_CLOSE_MSG):
			(*end_connection) = true;
			break;
		
		default: //Client sent invalid msg
			free(m.msg);
			return false;
	}
	free(m.msg);
	return true;
}

/**
 *	A helper function to stop server program from running:
 * 	Returns true if it finds a document named "exit.txt" in all-users-directory
 * (searches only thorugh MAX_FILES_TO_CHECK files)
 * It's only to make tests easier and memory-leak free :)
 **/
static bool stop_running(const char* dir_path){
	printDebugString("In function stop_running");
	DIR *dp;
	struct dirent *ep;
	int i = 0;
	
	dp = opendir (dir_path);
	if (dp == NULL)
   	{
		printf("Couldn't open the directory\n");
		return false;
    	}
    
	while ((ep = (struct dirent*)readdir(dp)) && (i < MAX_FILES_TO_CHECK)){
		if (ep->d_type == DT_REG){ //Insert only regular files to the list
			if(strcmp(ep->d_name, "exit.txt") == 0){
				return true;
			} 
			++i;
		}
	}
	closedir(dp);
	return false;
}



/**
 * Server's basic function: opens socket for connection, takes care of 1 client each time.
 **/
void start_service(user_info*** ptr_to_all_users_info, char*const *ptr_dir_path){
	
	bool asked_to_quit, is_authenticated;
	int sockfd, connected_sockfd;
	char *curr_username, *curr_user_dir_path;
	struct sockaddr_in server_addr, client_addr;
	socklen_t addr_len = sizeof(struct sockaddr_in);
	
	if((sockfd = init_sock(&server_addr)) == -1){ //Failed creating server's socket
		return;
	}
	
	while(true){
		// Here just for tests: stops server from running if file named "exit.txt" 
		// was found in all-users-directory:
		if(stop_running(*ptr_dir_path)){
			printf("exit.txt was found! ending program\n");
			return;
		}
		
		if((connected_sockfd = accept(sockfd, &client_addr, &addr_len)) == -1){
			printf("Failed accepting connection, error is: %s.\n Continue trying to accept connections.\n",strerror(errno));
			continue;
		}
		
		asked_to_quit = false;
		
		//Send hello message to client:
		if(!send_welcome_msg(connected_sockfd)){ //If failed sending hello message, continues to next client
			continue;
		}
		
		//Validate user: gives the user ALLOWED_TRIALS number of trials to authenticate
		for (size_t i = 0; i < ALLOWED_TRIALS; ++i){
			is_authenticated = get_user_details(connected_sockfd, &curr_username, ptr_to_all_users_info);
			if(!is_authenticated){
				send_server_login_failed_msg(connected_sockfd);
				continue;
			} else {
				break; //user validated, gets out of "for" loop
			}
		}

		if(!is_authenticated){
			continue; //To next client
		}
		
		//If gets here, user authenticated:
		if((curr_user_dir_path = concat_strings(*ptr_dir_path, curr_username, false)) == NULL){
			printf("Failed creating path to user directory\n");//Not supposed to get here.
			free(curr_username);
			continue;//To next client
		}
		//Sends status message:
		if (!send_status_msg(connected_sockfd, curr_user_dir_path, curr_username)){
			printf("Failed sending user the status message. Continuing to next client.\n");//Not supposed to get here.
			free(curr_user_dir_path);
			free(curr_username);
			continue;
		}
		
		//Waits for client requests	
		while(!asked_to_quit){
			printDebugString("inside inner while-loop");
			//For now, if client sends invalid messages we continue to serve him until he sends a valid 'quit'
			if(!get_msg_and_answer_it(connected_sockfd, ptr_to_all_users_info, ptr_dir_path, curr_user_dir_path, curr_username, &asked_to_quit)){
				printf("Getting or answering client's message failed, continues to next client\n");
				asked_to_quit = true;
			}
			else{
				printDebugString("Got msg.\n asked to quit value is:");
				printDebugString((asked_to_quit ? "true" : "false"));
			}
		}
		
		if(close(connected_sockfd) == -1){
			printf("Failed closing socket, error is: %s.\n Closing server.\n",strerror(errno));
			free(curr_username);
			free(curr_user_dir_path);
			return;
		}
		
		free(curr_username);
		free(curr_user_dir_path);
		curr_username = curr_user_dir_path = NULL;
	}

}


int main(int argc, char* argv[]){
	
	char* dir_path = NULL;
	user_info** ptr_all_users_info = init_server(argc, argv, &dir_path);
	
	if(ptr_all_users_info == NULL) {
		printf("Initiating server failed\n");
		return -1;
	}
	//print_users_array(&ptr_all_users_info); //Test Line
	
	start_service(&ptr_all_users_info, &dir_path);
		
	free_users_array(&ptr_all_users_info);
	free(dir_path);
	return 0;
}
