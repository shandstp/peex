#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

int BUFFSZ = 128;

void readBytes(unsigned char *buff, int byteRdCnt, FILE* fs) {
	int i = 0;
	for(; i < byteRdCnt; i++) {
		buff[i] = fgetc(fs);
	}
	for(; i < BUFFSZ; i++) {
		buff[i] = 0x00;
	}
}

unsigned long long bytes2Int(unsigned char *buff, int byteCnt) {
	unsigned long long result = 0;
	for(int i = 0; i < byteCnt; i++) {
		result = (unsigned long long) (result | ((unsigned long long) buff[i] << (8 * i)));
	}
	return result;
}

char* bytes2String(unsigned char *buff, int byteCnt) {
	char *result = malloc(sizeof(char) * (byteCnt + 1));
	for(int i = 0; i < byteCnt; i++) {
		result[i] = (char) buff[i];
	}
	result[byteCnt] = 0;
	return result;
}

int main(int argc, char** argv) {
	FILE* fs = fopen("kindle.exe", "rb");
	unsigned char *buff = malloc((sizeof(unsigned char) * BUFFSZ));

	//Set file stream pointer to address containing the address where the PE signature will be stored if the given file is a PE image file.
	fseek(fs, 0x3c, SEEK_SET);
	//Get address of PE signature
	readBytes(buff, 2, fs);
	int pe_sig_loc = *buff;
	fseek(fs, pe_sig_loc, SEEK_SET);
	readBytes(buff, 4, fs);
	unsigned long long pe_sig = bytes2Int(buff, 4);
	
	if(pe_sig == 0x00004550) {
		printf("This is a Microsoft PE image file\n");
	} else {
		printf("This is not a Microsoft PE image file. PE Signature value: %llx\n", pe_sig);
	}

	printf("Signature: %s\n", bytes2String(buff, 4));

	readBytes(buff, 2, fs);
	unsigned long long machType = bytes2Int(buff, 2);
	if(machType == 0x014c) {
		printf("Machine Type: Intel 386 or later processors and compatible processors\n");
	}

	free(buff);
	return 0;
}
