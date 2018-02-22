#include <arpa/inet.h>
#include <unistd.h> // for close
#include "attack.h"

int sock;
struct sockaddr_in server;

int main(int argc, char *argv[])
{
	char message[1024] , serverReply[2048];
	char *userMsg;
	// cipherText C;
	// int *bruteForceArray = initializeArray();
	// C.cipherPrime = "thisIsPlainSilly";

	//Verify input arguments
	commands commands = parseCMD(argc, argv);
	if (commands.error)
	{
		fprintf(stderr, "Incorrect commands usage\n");
		exit(1);
	}

	userMsg = commands.msg;

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
    	if(send(sock, userMsg, strlen(message) , 0) < 0)
        {
            //process first move here
            puts("Send failed");
            return 1;
        }

    	//Receive a reply from the server
        if(recv(sock, serverReply, 14, 0) < 0)
        {
            puts("Receive failed");
            // break;
        }

    //     break;
    // }

	// C.ciper = strcat(); cipherPrime || C
	//cleartext = ciperPrime ^ valid padding
	close(sock);
	return 0;
}

int* initializeArray()
{
	for (int i = 0; i < 256; i++) { bruteForceArray[i] = i; }
	return bruteForceArray;
}

commands parseCMD(int argc, char *argv[])
{
	commands commands = {.port = 10041, .msg = "", .ip = "", .error = false};
	int option;

	if ((argc < 2)) commands.error = true;
	else commands.ip = argv[1];

	while ((option = getopt(argc, argv, "p:m:")) != -1)
	{
		switch (option)
		{
			case 'p':
				commands.port = atoi(optarg);
				break;
			case 'm':
				commands.msg = optarg;
				break;
			default:
				printf("Incorrect usage of attack\n");
				commands.error = true;
				break;
		}
	}
	return commands;
}