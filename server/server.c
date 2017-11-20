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
 *  Returns true if at least 1 directory was created.
 **/
static bool create_directories(user_info*** ptr_to_all_users_info, char*const *ptr_dir_path){
	bool res = false;
	
	for (size_t i = 0; i < number_of_valid_users; ++i){	
		char* dir_name = concat_strings((*ptr_dir_path), (((*ptr_to_all_users_info)[i])->username), false);
		if (dir_name == NULL) { //Allocation failed:
			printf("Creating directory for user: %s failed, deleting this user from user-list\n", ((*ptr_to_all_users_info)[i])->username);
			delete_user_from_list((((*ptr_to_all_users_info)[i])->username) ,ptr_to_all_users_info);
			i--; //Because delete_user_from_list() removes the current user, so next user is now placed in current position i
			continue;
		}
		if(mkdir(dir_name, (S_IRWXU | S_IRWXG | S_IRWXO)) ==0 ) { //If succeed creating the directory
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
 * 	Helper function - initiates socket for the server to use.
 * 	Updates *server_addr values
 *  Returns:
 * 		On success: the socketfd,
 * 		On failure: -1.
 **//*
static int init_sock(struct sockaddr_in* server_addr){
	
	int sockfd;
	if((sockfd = socket(AF_INET, SOCK_STREAM,0) == -1){
		printf("Creating socket failed, error is: %s.\n Closing server.\n",strerror(errno));
		return -1;
	}

	memset(server_addr, '0', sizeof(struct sockaddr_in));
	
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
}*/
/*
void start_service(user_info*** ptr_to_all_users_info, char*const *ptr_dir_path){
	
	bool is_connection_open;
	int sockfd, connected_sockfd;

	struct sockaddr_in server_addr, client_addr;

	if((sockfd = init_sock(&server_addr)) == -1){ //Failed creating the socket
		return;
	}
	
	while(true){
		
		if((connected_sockfd = accept(sockfd, &client_addr, sizeof(client_addr))) == -1){
			printf("Failed accepting connection, error is: %s.\n Continue trying to accept connections.\n",strerror(errno));
			continue;
		}
		
		is_connection_open = true;
		
		//TODO:: send hello message
		//send();
		while(is_connection_open){
			//TODO:: fill :)
			is_connection_open = false;
		}
		
		if(close(connected_sockfd) == -1){
			printf("Failed closing socket, error is: %s.\n Closing server.\n",strerror(errno));
			return;
		}
	}

}
*/

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
 * 	"User: <username>
 * 	 Password: <password>"
 * 	updates (*usern), (*passw) to contain the relevant values and returns true.
 * 	Otherwise, returns false.
 **/
bool exstract_username_password_from_msg(const char* buff, char** usern , char** passw){
	size_t max_valid_len = MAX_PASSWORD_LEN+MAX_USERNAME_LEN+strlen("User: \nPassword: ");
	if (strlen(buff)>max_valid_len){
		return false;
	}
	if (sscanf(buff, "User: %s\nPassword: %s", (*usern),(*passw)) !=2){
		return false;
	}
	return true;
} 

/**
 * 	Returns true if buff indeed == "User: <username>\nPassword: <password>" of a valid user
 **/
bool is_valid_user(user_info*** ptr_to_all_users_info, const char* buff){
	bool ans = false;
	char *usern_to_check, *passw_to_check;
	if ((usern_to_check = calloc(MAX_USERNAME_LEN*2, sizeof(char))) == NULL){ //*2 to make sure no overflow would happen in "exstract_username_password_from_msg()"
		printf("Allocation failed\n");
		return false;
	}
	if ((passw_to_check = calloc(MAX_PASSWORD_LEN*2, sizeof(char))) == NULL){
		printf("Allocation failed\n");
		free (usern_to_check);
		return false;
	}
	if(!exstract_username_password_from_msg(buff, &usern_to_check, &passw_to_check)){
		printf("Invalid format. please try again, use format:\nUser: <username>\nPassword: <password>\n");//ans = false
	} else {
		ans = is_username_password_correct(ptr_to_all_users_info, usern_to_check, passw_to_check);
	}
	free(passw_to_check);
	free(usern_to_check);
	return ans;
}

/**
 * 	Gets a valid directory name, 
 * 	Returns a list of (regular) files in it, in format: <nameoffile1>\n<nameoffile2>\n...
 * 	Number of files in that list would be <= MAX_FILES_FOR_USER
 *  Note: user should free allocated memory (of returned char*)
 **/
static char* get_list_of_files(char* dir_path){
	char* ret_val = concat_strings("","",false); //Allocates an empty string
	char* temp_val = NULL;
	DIR *dp;
	struct dirent *ep;
	int i = 0;
	
	dp = opendir (dir_path);
	if (dp == NULL)
    {
		perror ("Couldn't open the directory");
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
	closedir(dp);
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
 * 	Helper function, that on success returns a string representing full path to file_name:
 * 	(in format: dir_path/user_name/file_name)
 * 	Note: dir_path already contains '/' at its end.
 *		  User of this function should free allocated memory of the string returned.
 * 	Returns NULL if failed.
 **/
static char* generate_path_to_file(const char* dir_path, const char* user_name, const char* file_name){
	char *temp1, *temp2, *path_to_file;
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
 * 	Helper function:updates (*txt) to contain error described in err_msg. 
 * 	If fails, (*txt) will be NULL
 **/
static void update_error_in_txt(unsigned char* err_msg, unsigned char** txt){
	if (((*txt) = calloc(strlen((char*)err_msg)+1, sizeof(unsigned char))) != NULL){
		memcpy((*txt), err_msg, strlen((char*)err_msg)); // used calloc, no need to copy null-terminator
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
			update_error_in_txt((unsigned char*)"get_file failed: server allocation error", txt);
			return FILE_GET_FAILED;
		}
		
		if(!isValidFilePath(path_to_file)){
			update_error_in_txt((unsigned char*)"get_file failed: file doesn't exist or not regular file", txt);
			free(path_to_file);
			return FILE_DOESNT_EXIST;
		}
		
		if(!fileToString(txt, path_to_file, &file_size)){
			update_error_in_txt((unsigned char*)"get_file failed", txt);
			free(path_to_file);
			return FILE_GET_FAILED;
		}
		free(path_to_file);
		return FILE_CONTENT_IN_TXT_SUCCESSFULLY;
}


int main(int argc, char* argv[]){
	
	char* dir_path = NULL;
	user_info** ptr_all_users_info = init_server(argc, argv, &dir_path);
	
	if(ptr_all_users_info == NULL) {
		printf("Initiating server failed\n");
		return -1;
	}
	//print_users_array(&ptr_all_users_info); //Test Line
	
	//start_service(&ptr_all_users_info, &dir_path);
	
	/** Test for get_txt_from_file(const char* dir_path, const char* user_name, unsigned char** txt, const char* file_name)**/
	//Here to avoid errors of "defined but not used" and to create a file:
	unsigned char* txt = (unsigned char*)"Blue jeans\nWhite shirt\nWalked into the room you know you made my eyes burn\n";
	switch(write_txt_to_file(dir_path, ptr_all_users_info[0]->username, &txt, "Lana_Del_Rey")){
		case (FILE_ADDED_SUCCESSFULLY):
			printf("FILE ADDED SUCCESSFULLY!\n");
			break;
		case(FILE_ALREADY_EXIST):
			printf("FILE ALREADY EXIST\n");
			break;
		default: //==FILE_ADDITION_FAILED
			printf("Failed adding the file\n");
	}

	unsigned char* txt_ff;
	switch(get_txt_from_file(dir_path, ptr_all_users_info[0]->username, &txt_ff, "Lana_Del_Rey")){
			case (FILE_CONTENT_IN_TXT_SUCCESSFULLY):
			printf("Lana_Del_Rey: FILE_CONTENT_IN_TXT_SUCCESSFULLY\n");
			break;
		case(FILE_DOESNT_EXIST):
			printf("Lana_Del_Rey: FILE_DOESNT_EXIST\n");
			break;
		default: //==FILE_GET_FAILED
			printf("Lana_Del_Rey: FILE_GET_FAILED\n");	
	}
	printf("***********************************************************************\n");
	printf("File content is:\n%s\n***********************************************************************\n", txt_ff);
	free(txt_ff);
	
	switch(get_txt_from_file(dir_path, ptr_all_users_info[1]->username, &txt_ff, "Meow")){
			case (FILE_CONTENT_IN_TXT_SUCCESSFULLY):
			printf("Meow: FILE_CONTENT_IN_TXT_SUCCESSFULLY\n");
			break;
		case(FILE_DOESNT_EXIST):
			printf("Meow: FILE_DOESNT_EXIST\n");
			break;
		default: //==FILE_GET_FAILED
			printf("Meow: FILE_GET_FAILED\n");	
	}
	printf("***********************************************************************\n");
	printf("File content (Meow) is:\n%s\n***********************************************************************\n", txt_ff);
	free(txt_ff);
	
	free(get_list_of_files(dir_path)); //Here just to avoid errors of "defined but not used"
	delete_users_file("theres_no_such_file.txt", dir_path);//Here just to avoid errors of "defined but not used"
	/** END OF test**/
	
	free_users_array(&ptr_all_users_info);
	free(dir_path);
	return 0;
}
