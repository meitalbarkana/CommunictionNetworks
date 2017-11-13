#pragma once
#include "utilities.h"

void intToString(unsigned int iNum, unsigned int iSizeInBytes, unsigned char* iBuffer) {
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
}

//from slides
int sendall(int s, char *buf, int *len) {

	int total = 0; /* how many bytes we've sent */
	int bytesleft = *len; /* how many we have left to send */
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
int recvall(int s, char *buf, int *len) {

	int total = 0; /* how many bytes we've recv */
	int bytesleft = *len; /* how many we have left to recv */
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
	char* sizeArr =(char*)malloc(Isize);
	if (recvall(iFd, &sizeArr, &Isize) == -1) {
		free(sizeArr);
		return -1;
	}
	*retVal = stringToInt(sizeArr, Isize);
	free(sizeArr);
	return 0;
	
}

int getMSG(int iFd, struct msg * msg) {
	getIntFromMsg(iFd, SIZE_OF_LEN, &msg->len);
	int type;
	getIntFromMsg(iFd, SIZE_OF_TYPE, &msg->type);
	msg->msg = (char*)malloc(&msg->len);
	if (recvall(iFd, &msg, &msg->len) == -1) {
		free(msg->msg);
		return -1;
	}
}

/**
 * Returns true if path is a directory
 **/
static bool doesPathExists(const char* path){
	struct stat dirData;
	if (stat(path, &dirData) == 0 && S_ISDIR(dirData.st_mode)){
		return true;
	}
	return false;
} 

/**
 * Returns true if path is a file (not a directory)
 **/
static bool isValidFilePath(const char* path){
	struct stat fileData;
	if (stat(path, &fileData) == 0 && S_ISREG(fileData.st_mode)){
		return true;
	}
	return false;
} 

/**
 * Returns true if str is numeric
 **/
static bool isStringNumeric(const char* str){
	for (size_t i = 0; i < strlen(str); ++i){
		if(!isdigit(str[i])){
			return false;
		}
	}
	return true;
}

