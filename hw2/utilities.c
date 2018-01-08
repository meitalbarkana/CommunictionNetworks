#include "utilities.h"
void initApprovedFriendly(){
intToString((unsigned int) 0, SIZE_OF_LEN, approveFriendly);
intToString(CLIENT_FRIENDLY_MSG_WAS_HANDLED, SIZE_OF_TYPE, approveFriendly + SIZE_OF_LEN);
}
void printDebugString(const char* str){
	if(DEBUG_MODE){
		printf("%s\n",str);
	}
}
void printDebugInt(int n){
	if(DEBUG_MODE){
		printf("%d\n",n);
	}
}
/**
 * prints bytes of const unsigned char* as ASCII,
 * (with a new line at the end)
 **/
bool printUnsignedCharArr(const unsigned char* arr, int len,bool prefix, bool onlyDebug, bool printNewLine){
	if (onlyDebug && !DEBUG_MODE){
	return true;
	}
	if(prefix){
		len+=SIZE_OF_PREFIX;
		printf("Msg length is: %u\n",stringToInt(arr,SIZE_OF_LEN));
		printf("Msg type is: %hu\n",stringToInt(arr+SIZE_OF_LEN, SIZE_OF_TYPE));
	}
	for(int i=prefix*SIZE_OF_PREFIX;i<len;i++){
		printf("%c",*(arr+i));
	}
	if(printNewLine){
		printf("\n");
	}
	return true;
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
unsigned int stringToInt(const unsigned char* iBuffer, unsigned int iSizeInBytes) {
	int res = 0;
	for (unsigned int i = 0; i < iSizeInBytes; i++) {
		res += (int)(iBuffer[iSizeInBytes - i - 1]) << 8 * i;
	}
	return res;
}

//from slides
int sendall(int s, unsigned char *buf, int *len) {
	//printDebugString("send msg via socket: ");
	//printDebugInt(s);
	//printDebugString("Msg: ");
	//printUnsignedCharArr(buf,*len,true,true);
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
	//printDebugString("revice msg via: ");
	//printDebugInt(s);
	//printDebugString("Msg: ");
	//printUnsignedCharArr(buf,*len,true,true);
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
	return getMSGOrPrintFriendly(iFd,msg,false);
}
void printFriendly(int iFd){
	struct msg m = { NULL, -1, -1 };
	getMSGOrPrintFriendly(iFd,&m,true);
	free(m.msg);
	return ;

}
	int getMSGOrPrintFriendly(int iFd, struct msg * msg,bool justFriendly) {
	printDebugString("in getMSG, socket fd is:");
	printDebugInt(iFd);
	getIntFromMsg(iFd, SIZE_OF_LEN, &msg->len);
	getIntFromMsg(iFd, SIZE_OF_TYPE, &msg->type);
	if ((msg->msg = calloc((msg->len)+1, sizeof(unsigned char*))) == NULL){ //was: if ((msg->msg = (unsigned char*)malloc(msg->len)) == NULL){
		printf("Error in allocating space for receiving message\n");
		return -1;
	}
	if (recvall(iFd, msg->msg, &msg->len) == -1) {
		printf("Error in receiving message\n");
		free(msg->msg);
		return -1;
	}
	printDebugString("in getMSG - exiting with success, socket fd is:");
	printDebugInt(iFd);

	if(msg->type==SERVER_ACTUAL_FRIENDLY_MSG){
		printUnsignedCharArr(msg->msg,msg->len,false,false,true);
		int len = SIZE_OF_PREFIX;
		sendall(iFd,approveFriendly,&len);
		free(msg->msg);
		return (justFriendly || getMSG(iFd, msg));
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
	if ((str1 == NULL) || (str2 == NULL)){
		return NULL;
	}
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
 * 			otherwise, the number of files in the directory
 **/
int number_of_files_in_directory(const char* dir_path, int max_val){
	int counter = 0;
	DIR *dp;
	struct dirent *ep;
	
	dp = opendir (dir_path);
	if (dp == NULL)
    {
		printf("Couldn't open the directory\n");
		return -1;
    }
    
	while ((ep = (struct dirent*)readdir(dp)) && (counter < max_val)){
		if (ep->d_type == DT_REG){ //Counts only regular files to the list
			counter++;
		}
	}
	closedir(dp);
	return counter;
}

/**
 *	@max_length - line's maxium size, including '\n'&'\0' (not including prefix)
 * 	@prefix -	the input should start with prefix str,
 * 				line will discard it.
 * 	Updates line to contain an input line from stdin, including its '\n'&'\0'
 * 	Note: user should free line's allocated space. 
 * 	Returns:
 * 		on success: number of characters written to "line", '\0' not included!
 * 		on failure: -1 if an error happend / stdin doesn't contain '\n'
 * 		
 **/
int get_line_from_stdin(char* line, int max_length, const char* prefix) {
	
	int chars_written_so_far = 0;
	char c;

	for (size_t i = 0; (i < strlen(prefix)) && ((c = getchar()) != EOF) ; ++i) {
		if (c != prefix[i]) {
			while(c!='\n'){
				c = getchar();
			}
			return -1;
		}
	}

	max_length = max_length - 2; //Room for '\n', '\0'

	while((c = getchar()) != EOF) {
		if(c == '\n') {
			line[chars_written_so_far] = '\n';
			++chars_written_so_far;
			line[chars_written_so_far] = '\0';
			break;
		}
		if(chars_written_so_far < max_length) {
			line[chars_written_so_far] = c;
			++chars_written_so_far;
		} else { //chars_written_so_far = max_length
		while((c = getchar()) != '\n'){} // to read the entire row in a single call to this function
			return -1;
		}
	}

	if(c == EOF && chars_written_so_far == 0){
		return EOF;
	}

	return chars_written_so_far;
}

