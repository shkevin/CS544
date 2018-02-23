#include <arpa/inet.h>
#include <unistd.h> // for close
#include "attack.h"

int sock;
struct sockaddr_in server;
const static unsigned char aes_key[] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
	0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};

int main(int argc, char *argv[])
{
	char message[1024] , serverReply[2048];
	RSA *publicKey = NULL;

	//Verify input arguments
	commands commands = parseCMD(argc, argv);
	unsigned char* msg = commands.msg;

	/* Init vector */
	unsigned char iv[AES_BLOCK_SIZE];
	memset(iv, 0x00, AES_BLOCK_SIZE);
	
	/* Buffers for Encryption and Decryption */
	unsigned char enc_out[strlen((const char*)msg)];
	unsigned char dec_out[strlen((const char*)msg)];
	// cipherText C;
	// int *bruteForceArray = initializeArray();
	// C.cipherPrime = "thisIsPlainSilly";
	AES_KEY enc_key, dec_key;

	//Read the public key
	// if (!PEM_read_RSA_PUBKEY(commands.file, &publicKey, NULL, NULL))
	// {
	// 	fprintf(stderr, "Error loading RSA Public Key File.\n");
 //        ERR_print_errors_fp(stderr);
 //        exit(1);
	// }
	unsigned char *aes_input=msg;
	// unsigned char *aes_input= aes_key;

	printf("%lu\n", sizeof(publicKey)*sizeof(RSA));
	// if (AES_set_encrypt_key(publicKey, sizeof(aes_key)*8, &enc_key) != 0)
	// {
	// 	puts("Couldn't encrypt key");
	// }

	printf("sending: %s\n", commands.msg);

	//Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1)
    {
        perror("Could not create socket");
        exit(1);
    }
    puts("Socket created");

    server.sin_addr.s_addr = inet_addr(commands.ip);
    server.sin_family = AF_INET;
    server.sin_port = htons(commands.port);

    //Connect to remote server
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0)
    {
        perror("connect failed. Error");
        exit(1);
    }
    puts("Connected\n");

    //Keep communicating with the server
    // while(1)
    // {
    // 	break;
    	//Send a message to the server

    	/* AES-128 bit CBC Encryption */
		AES_set_encrypt_key(aes_key, sizeof(aes_key)*8, &enc_key);
		AES_cbc_encrypt(aes_input, enc_out, strlen((const char*)msg), &enc_key, iv, AES_ENCRYPT);

    	if(send(sock, aes_input, strlen((const char*)aes_input) , 0) < 0)
        {
            //process first move here
            puts("Send failed");
            return 1;
        }

    	//Receive a reply from the server
        if(recv(sock, serverReply, strlen(serverReply), 0) < 0)
        {
            puts("Receive failed");
            // break;
            return 1;
        }

        puts(serverReply);

		/* AES-128 bit CBC Decryption */
		memset(iv, 0x00, AES_BLOCK_SIZE); // don't forget to set iv vector again, else you can't decrypt data properly
		AES_set_decrypt_key(aes_key, sizeof(aes_key)*8, &dec_key); // Size of key is in bits
		AES_cbc_encrypt(enc_out, dec_out, strlen((const char*)msg), &dec_key, iv, AES_DECRYPT);

		/* Printing and Verifying */
		print_data("\n Original ",aes_input, strlen((const char*)msg));
		
		print_data("\n Encrypted",enc_out, sizeof(enc_out));
		
		print_data("\n Decrypted",dec_out, sizeof(dec_out));

    //     break;
    // }

	// C.ciper = strcat(); cipherPrime || C
	//cleartext = ciperPrime ^ valid padding
	fclose(commands.file);
	close(sock);
	return 0;
}

/* ************************************************
* PARAMETERS: 
* FUNCTION: 
* RETURNS: 
************************************************* */
int* initializeArray()
{
	for (int i = 0; i < 256; i++) { bruteForceArray[i] = i; }
	return bruteForceArray;
}

/* ************************************************
* PARAMETERS: argument counter, arguments passed
* FUNCTION: parses the input given by the user,
			and stores them into a struct.
* RETURNS: Commands given to program
************************************************* */
commands parseCMD(int argc, char *argv[])
{
	commands commands = {.port = 10041, 
			.ip = "", .file = NULL, .error = false};
	int option;

	if ((argc < 2)) commands.error = true;
	else commands.ip = argv[1];

	while ((option = getopt(argc, argv, "k:p:m:")) != -1)
	{
		switch (option)
		{
			case 'k':
				commands.file = readKey(optarg);
				break;
			case 'p':
				commands.port = atoi(optarg);
				break;
			case 'm':
				commands.msg = (unsigned char*)optarg;
				break;
			default:
				commands.error = true;
				break;
		}
	}

	if (commands.error)
	{
		fprintf(stderr, "Incorrect commands usage\n");
		exit(1);
	}

	return commands;
}

/* ************************************************
* PARAMETERS: 
* FUNCTION: 
* RETURNS: 
************************************************* */
FILE* readKey(char *file)
{
	FILE* fp = fopen(file, "rb");
	if (fp == NULL)
	{
		perror("Couldn't open specified file");
		exit(1);
	}
	return fp;
}

//http://www.firmcodes.com/how-do-aes-128-bit-cbc-mode-encryption-c-programming-code-openssl/
void print_data(const char *tittle, const void* data, int len)
{
	printf("%s : ",tittle);
	const unsigned char * p = (const unsigned char*)data;
	int i = 0;
	for (; i<len; ++i)
	{
		// printf("%02X ", *p++);
		printf("%c", *p++);
	}
	printf("\n");
}