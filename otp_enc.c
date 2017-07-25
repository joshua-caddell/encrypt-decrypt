/* this code was adapted from examples found on
 * http://www.linuxhowtos.org/C_C++/socket.htm
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <fcntl.h>

void error(const char *msg)
{
	fprintf(stderr,"%s\n", msg);
	exit(1);
}
void validate(char text[]);
int sendall(int s, char *buf, int *len);

int main(int argc, char *argv[])
{
    	int sockfd, portno, n;
    	struct sockaddr_in serv_addr;
    	struct hostent *server;
	char *host = "localhost";
    	char buffer[256];
	char key[71000], message[70000], encrypted[70000], keyfile[32], messagefile[32];
    
	//check for correct command line usage	
	if (argc < 4) 
		error("usage error: not enough arguments");
   	
	//copy file names from command line arguments
	strcpy(keyfile, argv[2]);
	strcpy(messagefile, argv[1]);

	FILE *fp;

	memset(key, 0, sizeof(key));

	//open file containing key and read it
	fp = fopen(keyfile, "r");
	fgets(key, sizeof(key), fp);	
	fclose(fp);//close file

	//strip trailing new line character
	if(key[strlen(key) - 1] == '\n')
		key[strlen(key) - 1] = '\0';

	memset(message, 0, sizeof(message));
	
	//read plain text file and strip new 
	//line character
	fp = fopen(messagefile, "r");
	fgets(message, sizeof(message), fp);	
	fclose(fp);
	if(message[strlen(message) - 1] == '\n')
		message[strlen(message) - 1] = '\0';

	if (strlen(key) < strlen(message))
		error("ERROR: encryption key too short");

	//check for ivalid characters
	validate(key);
	validate(message);	
	
	//get port number from command line args
	portno = atoi(argv[3]);
	//create a scoket
    	sockfd = socket(AF_INET, SOCK_STREAM, 0);
    	if (sockfd < 0) 
    	    	error("ERROR opening socket");
    
	server = gethostbyname(host);
    	if (server == NULL) 
        	error("ERROR, no such host\n");
    	
	bzero((char *) &serv_addr, sizeof(serv_addr));
    	serv_addr.sin_family = AF_INET;
	
	//copy server address into struct
    	bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr,server->h_length);
    	serv_addr.sin_port = htons(portno);//concert port to big endian order
    	if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0) 
	{
		fprintf(stderr, "ERROR connecting to port %d", portno);
		exit(2);
	}
	//exchange verification from server to
	//prevent connection to otp_dec_d
	bzero(buffer,256);
       	strcpy(buffer, "encrypt");
	int length = strlen(buffer);
	if(sendall(sockfd, buffer, &length) < 0)
		error("error sending data");

	bzero(buffer, 256);
	n = read(sockfd, buffer, 255);
	if(n < 0)
		error("ERROR reading from socket");
	if(strcmp(buffer, "encrypt") != 0)
		error("can not connect to decryption server");

	//send key to server
	length = strlen(key);
	if (sendall(sockfd, key, &length) < 0)
		error("error sending data");
	
	//receive response from server
	bzero(buffer, 256);
	while((n = recv(sockfd, buffer, 255 , 0)) > 0)
	{
		if(n < 256)
			break;		
	}
	//send the plain text to the server
	length = strlen(message);
	sendall(sockfd, message, &length);
	
	//recevie the encrypted text back from server
	memset(message, 0, sizeof(message));
	char buf[1025];
	memset(buf, 0, sizeof(buf));
    	while((n = recv(sockfd, buf, 1024, 0)) > 0)
	{	
		//concatenate portion received with
		//the whole
		strcat(message, buf);
		bzero(buf, sizeof(buf));
		if(n < 1024)//end of string reached
			break;		
	}

	printf("%s\n",message);
 
	close(sockfd);
    
	return 0;
}

//function check the key and plaintext for invalid
//characters
void validate(char text[])
{
	int i;	
	
	//iterate through string
	for(i = 0; i < strlen(text); i++)
	{
		//65 - 90 is ascii range for capital letters
		if(text[i] < 65 || text[i] > 90)
		{
			if(text[i] != 32)//32 is space character
			{
				error("ERROR: Invalid characters in file");
				
			}
		}
	}
}

/*Source of this function is http://beej.us/guide/bgnet/output/html/singlepage/bgnet.html#sendman 
 * this function keeps track of bytes sent to handle partial sends through the socket
 * */
int sendall(int s, char *buf, int *len)
{
	int total = 0;        // how many bytes we've sent
	int bytesleft = *len; // how many we have left to send
	int n;

	//iterate until all the bytes are sent
	while(total < *len) {
		n = send(s, buf+total, bytesleft, 0);
		if (n == -1) { break; }
		total += n;
		bytesleft -= n;
	}

	*len = total; // return number actually sent here

	return n==-1?-1:0; // return -1 on failure, 0 on success
}


