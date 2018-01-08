#include "server.h"

static size_t number_of_valid_users = 0;
static active_fd active_fds[MAX_USERS];

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
 *	Gets a pointer to active_fd,
 *	Initializes all its fields to default (empty) values
 **/
static void init_active_fd(active_fd* afd){
	(*afd).client_sockfd = NO_SOCKFD;
	memset( &((*afd).client_addr), 0, sizeof(struct sockaddr_in) );
	(*afd).client_info = NULL;
	(*afd).client_status = NO_CLIENT_YET;
	(*afd).num_authentication_attempts = 0;
}

/**
 *	Initiates the global array active_fds to default values.
 **/
static void init_array_active_fds(){
	for (size_t i = 0; i < MAX_USERS; ++i) {
		init_active_fd(&active_fds[i]);
	}
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
 * 	Note: dir_path should already contain '/' at its end.
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
	char* dir_name = NULL;
	char* offline_file_name = NULL;
	bool res = false;
	
	for (size_t i = 0; i < number_of_valid_users; ++i){	
		dir_name = concat_strings((*ptr_dir_path), (((*ptr_to_all_users_info)[i])->username), false);
		if (dir_name == NULL) { //Allocation failed:
			printf("Creating directory for user: %s failed, deleting this user from user-list\n", ((*ptr_to_all_users_info)[i])->username);
			delete_user_from_list((((*ptr_to_all_users_info)[i])->username) ,ptr_to_all_users_info);
			i--; //Because delete_user_from_list() removes the current user, so next user is now placed in current position i
			continue;
		}
		if(mkdir(dir_name, (S_IRWXU | S_IRWXG | S_IRWXO)) == 0 ) { //If succeed creating the directory
			
			//Create the file STR_OFFLINE_FILE in that directory:
			offline_file_name = generate_path_to_file(
					(*ptr_dir_path),
					(((*ptr_to_all_users_info)[i])->username),
					STR_OFFLINE_FILE );
			
			if ( (offline_file_name == NULL) ||
				((fp = fopen(offline_file_name, "w")) == NULL) )
			{ //Allocation or creating file failed:
				if (offline_file_name){
					free(offline_file_name);
				}
				printf("Creating file for messages received offline for user: %s failed, deleting this user from user-list.\n", 
						((*ptr_to_all_users_info)[i])->username);
				delete_user_from_list( (((*ptr_to_all_users_info)[i])->username),
						ptr_to_all_users_info );
				i--; //Because delete_user_from_list() removes the current user, so next user is now placed in current position i
				continue;
			}
			fclose(fp);
			free(offline_file_name);
			res = true;
			
		} else { //Creating directory failed
			printf( "Creating directory for user: %s failed, deleting this user from user-list\n",
					((*ptr_to_all_users_info)[i])->username );
			delete_user_from_list( (((*ptr_to_all_users_info)[i])->username),
					ptr_to_all_users_info );
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
 *	Checks if usern_to_check & passw_to_check fits a valid user,
 *	if it does: 
 *		Updates (*fd_ptr).client_info to point at relevant user_info
 *		Returns true. 
 **/
bool is_username_password_correct (user_info*** ptr_to_all_users_info,
		const char* usern_to_check, const char* passw_to_check, active_fd* fd_ptr){
	for (size_t i = 0; i < number_of_valid_users; ++i){
		if ((strncmp(((*ptr_to_all_users_info)[i])->username, usern_to_check, MAX_USERNAME_LEN+1) == 0) &&
			(strncmp(((*ptr_to_all_users_info)[i])->password, passw_to_check, MAX_PASSWORD_LEN+1) == 0))
		{
			(*fd_ptr).client_info = ((*ptr_to_all_users_info)[i]);
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

	return true;
} 


/**
 * 	Returns true if buff indeed == "<username>\n<password>\n" of a valid user
 * 	Updates (*fd_ptr).client_info to point at valid user (in ptr_to_all_users_info)
 **/
static bool is_valid_user(user_info*** ptr_to_all_users_info, const char* buff, active_fd* fd_ptr){
	bool ans = false;
	char *passw_to_check, *user_name;
	if ((user_name = calloc(MAX_USERNAME_LEN*2, sizeof(char))) == NULL){ //*2 to make sure no overflow would happen in "exstract_username_password_from_msg()"
		printf("Allocation failed\n");
		return false;
	}
	if ((passw_to_check = calloc(MAX_PASSWORD_LEN*2, sizeof(char))) == NULL){
		printf("Allocation failed\n");
		free (user_name);
		return false;
	}
	if(!exstract_username_password_from_msg(buff, &user_name, &passw_to_check)){
		printf("User sent invalid username and password format.\n");//ans = false
	} else {
		ans = is_username_password_correct(ptr_to_all_users_info, user_name, passw_to_check, fd_ptr);
	}
	free(passw_to_check);
	free(user_name);
	if (ans == false) {
		(*fd_ptr).num_authentication_attempts =(*fd_ptr).num_authentication_attempts+1;
	}	
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
	if (strcmp(file_name, STR_OFFLINE_FILE) == 0) {
		return FILE_DELETION_DENIED;
	}
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
static enum AddFileStatus write_txt_to_file(const char* dir_path,
		const char* user_name, unsigned char** txt, const char* file_name)
{	
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
static int init_server_sock(struct sockaddr_in* server_addr){
	
	int sockfd;
	int opt = 1;
	if ((sockfd = socket(AF_INET, SOCK_STREAM,0)) == -1){
		printf("Creating socket failed, error is: %s.\n Closing server.\n",strerror(errno));
		return -1;
	}

	memset(server_addr, 0, sizeof(struct sockaddr_in));
	
	//set socket to allow multiple connections (this is just a good habit, it will work without this)
	if( setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) < 0 )
	{
		printf("setsockopt() failed, error is: %s.\n Closing server.\n",strerror(errno));
		return -1;
	}
	
	(*server_addr).sin_family = AF_INET;
	(*server_addr).sin_port = htons(port_number);
	(*server_addr).sin_addr.s_addr = htonl(INADDR_ANY);

	if(bind(sockfd, server_addr, sizeof(struct sockaddr_in)) != 0){
		printf("Binding socket to IP failed, error is: %s.\n Closing server.\n",strerror(errno));
		return -1;
	}
	
	//Defines maximum backlog size of the server as MAX_USERS:
	if (listen(sockfd, MAX_USERS) != 0){
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
 * 	Gets a pointer to an active_fd that is ready to be received from,
 *	checks if represent a valid user:
 * 
 * 	If client sent valid info, updates *fd_ptr to point at relevant user
 *	(from ptr_to_all_users_info)
 *
 *	If client sent invalid details, updates fd_ptr->num_authentication_attempts
 * 
 *	NOTE: if an error accured, won't change fd_ptr->num_authentication_attempts.
 * 
 * 	Returns true if suceeded, false otherwise.
 **/
static bool get_user_details(active_fd* fd_ptr, user_info*** ptr_to_all_users_info){
	
	if (fd_ptr == NULL || ptr_to_all_users_info == NULL){
		printf("Error: get_user_details() got NULL argument\n");
		return false;
	}
	
	struct msg m = { NULL, -1, -1 };
	
	if(getMSG(fd_ptr->client_sockfd, &m) < 0){
		return false; //Failed getting msg
	}
	
	if(m.type != CLIENT_LOGIN_MSG){ //msg is from wrong format
		free(m.msg);
		(*fd_ptr).num_authentication_attempts = (*fd_ptr).num_authentication_attempts+1;
		return false;
	}

	//(*fd_ptr).num_authentication_attempts updated inside is_valid_user():
	bool ans = is_valid_user(ptr_to_all_users_info, (char*)m.msg, fd_ptr);

	free(m.msg);
	return ans;
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
		case(FILE_DELETION_DENIED):
			msg_txt = "Access denied";
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
 * 	Takes care of deleting a file requested by client
 * 
 * 	Gets:	A pointer to the message from client,
 * 			pointer to relevant active_fd,
 * 			path to the user's directory
 * 
 * 	Returns: true if delete msg was treated successfully, false otherwise
 **/
static bool handle_delete_file_msg(struct msg* m, active_fd* afd, const char* user_dir_path){
	
	if (m == NULL || afd == NULL || user_dir_path== NULL) {
		printf ("Error: function handle_delete_file_msg() got NULL argument.\n");
		return false;
	}
	
	//+1 since m.len doesn't include '\0':
	char* temp_fname = calloc((*m).len+1, sizeof(char));
	
	if (temp_fname == NULL){
		printf("Allocation failed when trying to delete a file client has asked\n");
		return false;
	}
	strncpy(temp_fname, (char*)((*m).msg), (*m).len);
	
	bool ans = delete_file_and_report_client((*afd).client_sockfd, user_dir_path, temp_fname);
	free(temp_fname);
	
	return ans;
}

/**
 * 	Takes care of adding a file requested by client
 * 
 * 	Gets:	m - pointer to the message from client,
 * 			afd - pointer to relevant active_fd,
 * 			user_dir_path - path to the user's directory
 * 			ptr_dir_path - path to the directory where all users' directories are
 * 
 * 	Returns: true if adding a file msg was treated successfully, false otherwise
 **/
static bool handle_add_file_msg(struct msg* m, active_fd* afd,
		const char* user_dir_path, char*const *ptr_dir_path )
{
	unsigned char* txt = NULL;
	char* temp_fname = NULL;
	
	if( number_of_files_in_directory(user_dir_path, MAX_FILES_FOR_USER)
		>= MAX_FILES_FOR_USER )
	{
		printf("User tried adding more files than allowed\n");
		return(send_client_add_msg_result((*afd).client_sockfd,
				"Adding file failed: maximum amount of files, delete one to make room."));
	}

	char* buff = calloc((*m).len+1, sizeof(char));
	if (buff == NULL){
		printf("Allocation failed when trying to add a file client has asked\n");
		send_client_add_msg_result((*afd).client_sockfd, "Adding file failed: server error");
		return false;
	}
	strncpy(buff, (char*)((*m).msg), (*m).len);
	
	size_t msg_len = (size_t)((*m).len); //Safe casting since (*m).len>=0

	if(!exstract_fname_txt_from_msg(buff, &temp_fname, &txt, msg_len)){
		printf("Extracting name of file and its content from clients' msg failed\n");
		send_client_add_msg_result((*afd).client_sockfd,
				"Adding file failed: extracting filename and its content failed.");
		free(buff);
		free(temp_fname);
		free(txt);
		return false;
	}
	free(buff);
	if (!add_file_and_report_client((*afd).client_sockfd, *ptr_dir_path,
			(*afd).client_info->username, &txt, temp_fname))
	{
		printf("Adding file asked by client failed.\n");
		free(txt);
		free(temp_fname);
		return false;
	}
	free(txt);
	free(temp_fname);
	return true;
}

/**
 * 	Takes care of a request to download a file.
 * 
 * 	Gets:	m - pointer to the message from client,
 * 			afd - pointer to relevant active_fd,
 * 			ptr_dir_path - path to the directory where all users' directories are
 * 
 * 	Returns: true if download request treated successfully, false otherwise
 **/
static bool handle_download_file_msg(struct msg* m, active_fd* afd,
		char*const *ptr_dir_path )
{
	char* temp_fname = calloc((*m).len+1, sizeof(char));
	if (temp_fname == NULL){
		printf("Allocation failed when trying to send a file client has asked\n");
		return false;
	}
	
	strncpy(temp_fname, (char*)((*m).msg), (*m).len);
	
	if(!send_file_to_client((*afd).client_sockfd, *ptr_dir_path, (*afd).client_info->username, temp_fname)){
		free(temp_fname);
		return false;
	}
	free(temp_fname);
	return true;
	
}

/**
 *	Gets a pointer to user_info,
 *	Returns true if this user is online (means it has an active_fd and 
 *	its status is CLIENT_IS_CONNECTED)
 **/
static bool is_user_online(user_info* ptr_to_user_info){
	if (ptr_to_user_info == NULL) {
		printf("Error: function is_user_online() got NULL argument.\n");
		return false;
	}
	for (size_t i = 0; i < MAX_USERS; ++i){
		if (active_fds[i].client_info == ptr_to_user_info){
			if(active_fds[i].client_status == CLIENT_IS_CONNECTED){
				return true;
			} else {
				return false;
			}
		}
	}
	return false;
}

/**
 *	Returns a list off all connected users in format:
 *	<username0>'\n'<username1>'\n'...'\n'<last username>'\0'
 *
 *	Note:	1. Returns NULL if an error accured,
 * 			2. Returns an empty string if all users are not connected
 * 			3. USER SHOULD FREE MEMORY ALLOCATED for char* returned.
 **/
static char* build_all_online_users_str(user_info*** ptr_to_all_users_info){
	char* txt = calloc(((MAX_USERNAME_LEN+1)*MAX_USERS), sizeof(char)); //+2 for '\n' xor '\0'
	if (txt == NULL){
		printf("Allocation failed when trying to build users-online-list.\n");
		return NULL;
	}
	
	size_t len_txt = 0;
	for (size_t i = 0; i < number_of_valid_users; ++i){
		if(is_user_online((*ptr_to_all_users_info)[i])){
			if(len_txt > 0){
				txt[len_txt] = '\n';
				len_txt++;
			}
			memcpy( txt+len_txt, ((*ptr_to_all_users_info)[i])->username,
					strlen(((*ptr_to_all_users_info)[i])->username) );
			len_txt += strlen(((*ptr_to_all_users_info)[i])->username);
		}
	}

	return txt;
}

/**
 * 	Takes care of a requested for a list of all users online.
 * 
 * 	Gets:	m - pointer to the message from client,
 * 			afd - pointer to relevant active_fd,
 *			ptr_to_all_users_info - pointer to all users' info.
 * 
 * 	Returns: true if msg was treated successfully, false otherwise
 **/
static bool handle_get_users_online_msg(struct msg* m, active_fd* afd,
		user_info*** ptr_to_all_users_info)
{
	char* txt = build_all_online_users_str(ptr_to_all_users_info);
	if (txt == NULL) {
		//Creating list failed, errors already been printed in build_all_online_users_str()
		return false;
	}
	
	unsigned char* total_msg = calloc(SIZE_OF_PREFIX+strlen(txt), sizeof(unsigned char));
	if (total_msg == NULL) {
		printf("Generating msg containing a list of online users failed.\n");
		free(txt);
		return false;
	}

	intToString(strlen(txt), SIZE_OF_LEN, total_msg);
	intToString(SERVER_ALL_CONNECTED_USERS_MSG, SIZE_OF_TYPE, total_msg+SIZE_OF_LEN);
	memcpy(total_msg+SIZE_OF_PREFIX, txt, strlen(txt));

	int total_msg_len = SIZE_OF_PREFIX+strlen(txt);
	bool ans = true;
	if (sendall((*afd).client_sockfd, total_msg, &total_msg_len) < 0) {
		printf("Sending list of online users to client failed.\n");
		ans = false;
	}
	
	free(total_msg);
	free(txt);
	return ans;
}


/**
 * 	Takes care of getting a message from client (that isn't the login message)
 * 	Gets:	A pointer to an active_fd - a connection which is ready to be received from,
 * 			pointer to all users' info,
 * 			path to the directory where all users' directories are,
 * 			path to this specific user's directory(that doesn't end with '/')
 * 
 * 	Returns: true if msg was treated successfully,
 * 			 false when communication has ended: some error happend / user sent invalid msg
 **/
static bool get_msg_and_answer_it(active_fd* afd, user_info*** ptr_to_all_users_info,
		char*const *ptr_dir_path,const char* user_dir_path)
{
	bool ans = false;
	
	if (afd == NULL || ptr_to_all_users_info == NULL || 
			ptr_dir_path == NULL || user_dir_path== NULL)
	{
		printf ("Error: function get_msg_and_answer_it() got NULL argument.\n");
		return false;
	}
	
	struct msg m = { NULL, -1, -1 };
	if (getMSG((*afd).client_sockfd, &m) < 0){
		printf("Server failed to get client's message.\n");
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
			ans = send_listfiles_to_client((*afd).client_sockfd, user_dir_path);
			break;
			
		case(CLIENT_FILE_DELETE_MSG):
			ans = handle_delete_file_msg(&m, afd, user_dir_path);
			break;
			
		case(CLIENT_FILE_ADD_MSG):		
			ans = handle_add_file_msg(&m, afd, user_dir_path, ptr_dir_path);
			break;
		
		case(CLIENT_FILE_DOWNLOAD_MSG):
			ans = handle_download_file_msg(&m, afd, ptr_dir_path);
			break;
		
		case(CLIENT_CLOSE_MSG):
			if(close((*afd).client_sockfd) == -1){
				printf("Failed closing client's socket. error is: %s.\n",strerror(errno));
			} else {
				ans = true;
			}
			init_active_fd(afd);
			break;
			
		
		case(CLIENT_FRIENDLY_MSG):
			///TODO:: edit this new case:
			break;
		
		case(CLIENT_GET_USERS_MSG):
			ans = handle_get_users_online_msg(&m, afd, ptr_to_all_users_info);
			break;
		
		default: //Client sent invalid msg
			printf("Client sent invalid message.\n");
			ans = false;
	}
	
	free(m.msg);
	return ans;
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
	if (dp == NULL) {
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
 *	Initiates *read_fds, AND returns the highest fd in it:
 * 		1. Adds listening socket (server_listen_sockfd) to *read_fds
 * 		2. Adds all (active) client-server sockets to *read_fds
 * 
 **/
static int init_fd_set(fd_set* read_fds, int server_listen_sockfd){
	int highest_sockfd = server_listen_sockfd;
	FD_ZERO(read_fds);
	FD_SET(server_listen_sockfd, read_fds);
	
	for (size_t i = 0; i < MAX_USERS; ++i){
		if (active_fds[i].client_sockfd != NO_SOCKFD){
			FD_SET(active_fds[i].client_sockfd, read_fds);
			if (active_fds[i].client_sockfd > highest_sockfd){
				highest_sockfd = active_fds[i].client_sockfd;
			}
		}
	}
	
	return highest_sockfd;
}

/**
 *	Handles new connection attempt.
 *  
 *	NOTE:	if number of active_fd's already is MAX_USERS,
 * 			will close this new connection
 **/
static void handle_new_connection_attempt(int server_listen_sockfd){
	struct sockaddr_in temp_client_addr;
	memset(&temp_client_addr, 0, sizeof(temp_client_addr));
	socklen_t client_len = sizeof(temp_client_addr);
	int new_client_sock = accept(server_listen_sockfd,
					(struct sockaddr*)&temp_client_addr, &client_len);
	if (new_client_sock < 0) {
		printf("Failed accepting connection, error is: %s.\n Continue trying to accept connections.\n",strerror(errno));
		return;
	}

	for (size_t i = 0; i < MAX_USERS; ++i) {
		if (active_fds[i].client_sockfd == NO_SOCKFD) {
			
			//Send welcome message to client:
			if(!send_welcome_msg(new_client_sock)){
				//If failed sending hello message, continue to next client
				//No change in active_fds[i],errors already printed
				// inside send_welcome_msg()
				close(new_client_sock);
				return;
			}
			
			//Welcome message sent OK:
			active_fds[i].client_sockfd = new_client_sock;
			active_fds[i].client_addr = temp_client_addr;
			active_fds[i].client_info = NULL; //We don't know yet which client tries to connect using this socket
			active_fds[i].client_status = WELCOME_MSG_SENT;
			active_fds[i].num_authentication_attempts = 0;
			return;
		}
	}

	printf("Too much connections, new connection attemp denied.\n");
	close(new_client_sock);
}

/**
 *	Gets a pointer to an active_fd that is ready to be received from,
 *	And supposed to send a CLIENT_LOGIN_MSG.
 *	
 *	If authentication succeeded, updates:
 *		1. (*fd_ptr).client_info: to point at the relevant user
 * 		2. (*fd_ptr).client_status: to CLIENT_IS_CONNECTED
 * 		3. (*fd_ptr).num_authentication_attempts: to zero (since it doesn't matter anymore)
 *	and sends client a SERVER _LOGIN_PASS_MSG
 * 
 *	Otherwise, updates fd_ptr->num_authentication_attempts (adds 1,
 *	happens inside helper function get_user_details()),
 *	and sends client a SERVER_LOGIN_FAIL_MSG.
 * 
 * 	NOTE:	if num_authentication_attempts reaches ALLOWED_TRIALS,
 * 			CLOSES (fd_ptr->client_sockfd) SOCKET AND INITIATES IT!
 **/
 static void get_authentication_msg(active_fd* fd_ptr,
		user_info*** ptr_to_all_users_info, char*const *ptr_dir_path)
{
	char* curr_user_dir_path = NULL;
	bool is_authenticated = get_user_details(fd_ptr, ptr_to_all_users_info);
	
	if(!is_authenticated){
		send_server_login_failed_msg(fd_ptr->client_sockfd);
		if ((*fd_ptr).num_authentication_attempts == ALLOWED_TRIALS) {
			printf("Socket number: %d failed to authenticate too many times, closing connection.\n",
					(*fd_ptr).client_sockfd);
			close((*fd_ptr).client_sockfd);
			init_active_fd(fd_ptr);
		}
	} 
	else {
	//user validated, (*fd_ptr).client_info already been updated in get_user_details()
		(*fd_ptr).client_status = CLIENT_IS_CONNECTED;
		(*fd_ptr).num_authentication_attempts = 0;
		
		if((curr_user_dir_path = concat_strings(*ptr_dir_path,
				(*fd_ptr).client_info->username, false)) == NULL)
		{//Not supposed to get here:
			printf("Failed creating path to user directory, couldn't generate SERVER_LOGIN_PASS_MSG\n");
			return;
		}
		
		//Sends SERVER_LOGIN_PASS_MSG:
		if (!send_status_msg((*fd_ptr).client_sockfd, curr_user_dir_path,
				(*fd_ptr).client_info->username))
		{//Not supposed to get here:
			printf("Failed sending SERVER_LOGIN_PASS_MSG. Continuing to next client.\n");
		}
		free(curr_user_dir_path);
	}
 }

/**
 *	Gets:
 *		fd_ptr - a pointer to an active_fd that is ready to be received from
 * 		ptr_to_all_users_info - all users information
 *		ptr_dir_path - path to the directory where all users' directories are
 *
 *	Receives the msg from the active fd and handles it accordingly.
 *	[If any error accures, prints it to the screen]
 **/
static void handle_msg_from_active_fd(active_fd* fd_ptr,
		user_info*** ptr_to_all_users_info, char*const *ptr_dir_path)
{
	char* curr_user_dir_path = NULL;
	
	if (fd_ptr == NULL || ptr_to_all_users_info==NULL ||
			ptr_dir_path == NULL)
	{
		printf("Error: function handle_msg_from_active_fd() got NULL argument.\n");
		return;
	}
	
	switch (fd_ptr->client_status){
		
		case (NO_CLIENT_YET):
		case (CLIENT_IS_OFFLINE):
		//Never suppposed to get here:
			printf("Error: in function handle_msg_from_active_fd(), client status is invalid. Closing connection.\n");
			close(fd_ptr->client_sockfd);
			init_active_fd(fd_ptr);
			return;
		
		case (WELCOME_MSG_SENT): 
		//Means this msg supposed to be the authentication msg from client:
			get_authentication_msg(fd_ptr, ptr_to_all_users_info, ptr_dir_path);
			return;
		
		default: 
		//CLIENT_IS_CONNECTED
			if((curr_user_dir_path = concat_strings(*ptr_dir_path, (*fd_ptr).client_info->username, false)) == NULL){
				printf("Failed creating path to user directory\n");//Not supposed to get here.
				return;//Continue to next client
			}
			
			if(!get_msg_and_answer_it(fd_ptr, ptr_to_all_users_info, ptr_dir_path, curr_user_dir_path)){
				printf("Getting or answering client's message failed, continue to next client\n");
			}
			free(curr_user_dir_path);
	}

}



/**
 * Server's basic function: opens socket for connection, takes care of 1 client each time.
 **/
void start_service(user_info*** ptr_to_all_users_info, char*const *ptr_dir_path){

	int server_listen_sockfd, highest_sockfd;
	struct sockaddr_in server_addr;
	fd_set read_fds;
	int action = -1;
	
	init_array_active_fds();

	if((server_listen_sockfd = init_server_sock(&server_addr)) == -1){ //Failed creating server's socket
		return;
	}
	
	while(true){
		// Here just for tests: stops server from running if file named "exit.txt" 
		// was found in all-users-directory:
		if(stop_running(*ptr_dir_path)){
			printf("exit.txt was found! ending program\n");
			return;
		}
		
		highest_sockfd = init_fd_set(&read_fds, server_listen_sockfd);
		
		action = select(highest_sockfd+1, &read_fds, NULL, NULL, NULL);
		
		switch (action) {
			case (-1):
				printf("Error: select() failed. Error info is: %s.\n",strerror(errno));
				return;
			case (0): //Never supposed to get here
				printf("Function select() timedout.\n");
				return;
			default:
				if (FD_ISSET(server_listen_sockfd, &read_fds)){
					//A new client is attemting to connect:
					handle_new_connection_attempt(server_listen_sockfd);	
				}
				
				for (size_t i = 0; i < MAX_USERS; ++i) {
					if ((active_fds[i].client_sockfd != NO_SOCKFD) &&
						(FD_ISSET(active_fds[i].client_sockfd, &read_fds))) 
					{
						//Take care of an already active socket, that sent something:
						handle_msg_from_active_fd(&active_fds[i], ptr_to_all_users_info, ptr_dir_path);
					}
				}
		}

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
