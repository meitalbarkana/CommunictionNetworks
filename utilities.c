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
int getSizeOfMsg(int iFd, int* oSize) {
	char sizeArr[SIZE_OF_LEN];
	int len;
	if (recvall(iFd, &sizeArr, &len) == -1) {
		return -1;
	}
	*oSize = stringToInt(sizeArr, SIZE_OF_LEN);
	return 0;
	
}
