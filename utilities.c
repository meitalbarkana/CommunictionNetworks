#include "utilities.h"
/**
 * prints bytes of const unsigned char* as ASCII
 **/
void printUnsignedCharArr(const unsigned char* arr, int len){
	for(int i=0;i<len;i++){
		printf("%c",*(arr+i));
	}
}
/**
 * converts iSizeInBytes first bytes in iNum to unsigned char* *iBuffer
 **/
void intToString(unsigned int iNum, unsigned int iSizeInBytes, unsigned char* iBuffer) {
	for (unsigned int i = 0; i < iSizeInBytes; i++) {
		iBuffer[iSizeInBytes - i - 1] = (iNum >> 8 * i) & 0xFF;
	}
}
/**
 * converts iSizeInBytes first bytes in unsigned char* iBuffer * to unsigned int
 **/
unsigned int stringToInt(unsigned char* iBuffer, unsigned int iSizeInBytes) {
	int res = 0;
	for (unsigned int i = 0; i < iSizeInBytes; i++) {
		res += (int)(iBuffer[iSizeInBytes - i - 1]) << 8 * i;
	}
	return res;
}

//from slides
int sendall(int s, unsigned char *buf, int *len) {

	int total = 0; // how many bytes we've sent
	int bytesleft = *len; // how many we have left to send
	int n;

	while (total < *len) {
		n = send(s, buf + total, bytesleft, 0);
		if (n == -1) { break; }
		total += n;
		bytesleft -= n;
	}

	*len = total; // return number actually sent here
	return n == -1 ? -1 : 0; //-1 on failure, 0 on success
}
int recvall(int s, unsigned char *buf, int *len) {

	int total = 0; // how many bytes we've recv
	int bytesleft = *len; // how many we have left to recv 
	int n;

	while (total < *len) {
		n = recv(s, buf + total, bytesleft, 0);
		if (n == -1) { break; }
		total += n;
		bytesleft -= n;
	}

	*len = total; // return number actually recv here
	return n == -1 ? -1 : 0; //-1 on failure, 0 on success
}
/**
 * reads iSize bytes and parse them to an int;
 **/
int getIntFromMsg(int iFd,int iSize, int* retVal) {
	unsigned char* sizeArr =(unsigned char*)malloc(iSize);
	if (recvall(iFd, sizeArr, &iSize) == -1) {
		free(sizeArr);
		return -1;
	}
	*retVal = stringToInt(sizeArr, iSize);
	free(sizeArr);
	return 0;
	
}
/**
 * get message from socket and parse it for a struct msg
 **/
int getMSG(int iFd, struct msg * msg) {
	getIntFromMsg(iFd, SIZE_OF_LEN, &msg->len);
	getIntFromMsg(iFd, SIZE_OF_TYPE, &msg->type);
	msg->msg = (unsigned char*)malloc(msg->len);
	if (recvall(iFd, msg->msg, &msg->len) == -1) {
		printf("Error in receiving message");
		free(msg->msg);
		return -1;
	}
	return 0;
}

/**
 * Returns true if path is a directory
 **/
bool doesPathExists(const char* path){
	struct stat dirData;
	if (stat(path, &dirData) == 0 && S_ISDIR(dirData.st_mode)){
		return true;
	}
	return false;
} 

/**
 * Returns true if path is a file (not a directory)
 **/
bool isValidFilePath(const char* path){
	struct stat fileData;
	if (stat(path, &fileData) == 0 && S_ISREG(fileData.st_mode)){
		return true;
	}
	return false;
} 

/**
 * Returns true if str is numeric
 **/
bool isStringNumeric(const char* str){
	for (size_t i = 0; i < strlen(str); ++i){
		if(!isdigit(str[i])){
			return false;
		}
	}
	return true;
}
/**
 * 	Gets pointer for writing the file, filePath, and pointer to long to save the length of the string
 * 	Returns true/false if action was performed successfully. 
 **/
bool fileToString(unsigned char** msg, const char* filepath,long* fsize) {
	FILE *f = fopen(filepath, "rb");

	if (f == NULL) {
		printf("Can't open file\n");
		return false;
	}

	if (fseek(f, 0, SEEK_END) != 0) {
		printf("fseek failed\n");
		return false;
	}
	 *fsize = ftell(f);
	if (*fsize == -1L) {
		printf("ftell failed\n");
		return false;
	}
	if (fseek(f, 0, SEEK_SET) != 0) {
		printf("fseek failed\n");
		return false;
	}

	*msg = (unsigned char *)malloc(*fsize + 1);
	if (*msg == NULL) {
		printf("malloc failed\n");
		return false;
	}
	if (fread(*msg, *fsize, 1, f) < 1) {
		printf("fread failed\n");
		return false;
	}
	fclose(f);
	unsigned char* end = *msg + *fsize;
	*end = 0;
	return true;
}
/**
 * 	writes msg to file in filepath
 * 	Note: msg must be null-terminated
 **/
bool StringTofile(unsigned char* msg, const char* filepath) {
	FILE *f = fopen(filepath, "wb");
	if (f == NULL) {
		printf("Can't open file\n");
		return false;
	}
	if (fprintf(f,"%s",msg) != strlen((char*)msg)) { //If not all characters were written. 
													//(Casting is safe since strlen() searches for '\0', which is =='\0' whether signed/unsigned)	
		printf("Failed writing to file / wrote partial message to file\n");
		return false;
	}
	fclose(f);
	return true;
}

/**
 * 	Gets 2 strings, and boolean that if true adds '\n' to the end of concatenated string.
 * 	Returns a concatenated string.
 * 	Note: user of this function has to free allocation!
 **/
char* concat_strings(const char* str1, const char* str2, bool add_newline){
	char* concated_str = (add_newline) ? calloc((strlen(str1)+strlen(str2)+2),sizeof(char)) : calloc((strlen(str1)+strlen(str2)+1),sizeof(char)); 
	if((concated_str) == NULL){
		return NULL;
	}
	strncpy(concated_str, str1, strlen(str1));
	strncat(concated_str, str2, strlen(str2));
	if (add_newline) {
		strncat(concated_str, "\n", 1);
	}
	return concated_str;
}

/**
 * 	Gets a path to a directory, and a maximum number of files to check
 * 	Returns:
 * 			-1 if an error occured/it's not a directory
 * 			otherwise, the number of regular files in the directory
 **/
int number_of_files_in_directory(const char* dir_path, int max_val){
	int counter = 0;
	int i = 0;
	DIR *dp;
	struct dirent *ep;
	
	dp = opendir (dir_path);
	if (dp == NULL)
    {
		printf("Couldn't open the directory\n");
		return -1;
    }
    
	while ((ep = (struct dirent*)readdir(dp)) && (i < max_val)){
		if (ep->d_type == DT_REG){ //Counts only regular files to the list
			counter++;
		}
		++i;
	}
	closedir(dp);
	return counter;
}
