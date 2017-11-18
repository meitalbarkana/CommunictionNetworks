#include "utilities.h"

/*void intToString(unsigned int iNum, unsigned int iSizeInBytes, unsigned char* iBuffer) {
	for (unsigned int i = 0; i < iSizeInBytes; i++) {
		iBuffer[iSizeInBytes - i - 1] = (iNum >> 8 * i) & 0xFF;
	}
}
unsigned int stringToInt(unsigned char* iBuffer, unsigned int iSizeInBytes) {
	int res = 0;
	for (unsigned int i = 0; i < iSizeInBytes; i++) {
		res += (int)(iBuffer[iSizeInBytes - i - 1]) << 8 * i;
	}
	return res;
}*/

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

	*len = total; /* return number actually sent here */
	return n == -1 ? -1 : 0; /*-1 on failure, 0 on success */
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

	*len = total; /* return number actually recv here */
	return n == -1 ? -1 : 0; /*-1 on failure, 0 on success */
}
int getIntFromMsg(int iFd,int Isize, int* retVal) {
	unsigned char* sizeArr =(unsigned char*)malloc(Isize);
	if (recvall(iFd, sizeArr, &Isize) == -1) {
		free(sizeArr);
		return -1;
	}
	*retVal = stringToInt(sizeArr, Isize);
	free(sizeArr);
	return 0;
	
}

int getMSG(int iFd, struct msg * msg) {
	getIntFromMsg(iFd, SIZE_OF_LEN, &msg->len);
	getIntFromMsg(iFd, SIZE_OF_TYPE, &msg->type);
	msg->msg = (char*)malloc(msg->len);
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

bool fileToString(unsigned char** msg, const char* filepath,long* fsize) {
	FILE *f = fopen(filepath, "rb");

	if (f == NULL) {
		printf("can't open file");
		return false;
	}

	if (fseek(f, 0, SEEK_END) != 0) {
		printf("fseek failed");
		return false;
	}
	 *fsize = ftell(f);
	if (*fsize == -1L) {
		printf("ftell failed");
		return false;
	}
	if (fseek(f, 0, SEEK_SET) != 0) {
		printf("fseek failed");
		return false;
	}

	*msg = (char *)malloc(*fsize + 1);
	if (*msg == NULL) {
		printf("malloc failed");
		return false;
	}
	if (fread(*msg, *fsize, 1, f) < 1) {
		printf("fread failed");
		return false;
	}
	fclose(f);
	unsigned char* end = *msg + *fsize;
	*end = 0;
	return true;
}

bool StringTofile(unsigned char* msg, const char* filepath) {
	FILE *f = fopen(filepath, "wb");
	if (f == NULL) {
		printf("can't open file");
		return false;
	}
	if (fprintf(f,"%s",msg) < 0) {
		printf("can't write to file");
		return false;
	}
	fclose(f);
	return true;
}

/**
 * 	Gets 2 strings,
 * 	Returns a concatenated string.
 * 	Note: user of this function has to free allocation!
 **/
char* concat_strings(const char* str1, const char* str2){
	char* concated_str = calloc((strlen(str1)+strlen(str2)+1),sizeof(char)); 
	if((concated_str) == NULL){
		return NULL;
	}
	strncpy(concated_str, str1, strlen(str1));
	strncat(concated_str, str2, strlen(str2));
	return concated_str;
}
