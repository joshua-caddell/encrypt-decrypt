/* this code was adapted from examples found on:
 * http://www.linuxhowtos.org/C_C++/socket.htm */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>

void error(const char *msg)//function to make error handling simpler
{
    	fprintf(stderr, "%s\n", msg);
    	exit(1);
}

int sendall(int s, char *buf, int *len);
void encrypt(char keyText[], char message[], char encrypted[]);
int main(int argc, char *argv[])
{
     	int sockfd, newsockfd, portno;
     	socklen_t clilen;
     	char buffer[256];
     	struct sockaddr_in serv_addr, cli_addr;
     	int n;
	char key[71000], message[70000], encrypted[70000];
	
	//check command line usage
	if (argc < 2) 
         	error("USAGE ERROR, no port provided");
     
	//create a new socket
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
     	if (sockfd < 0) 
        	error("ERROR opening socket");
     
	//zero out struct and set properties
	bzero((char *) &serv_addr, sizeof(serv_addr));
     	portno = atoi(argv[1]);
     	serv_addr.sin_family = AF_INET;
     	serv_addr.sin_addr.s_addr = INADDR_ANY;//will work for localhost
     	serv_addr.sin_port = htons(portno); //convert port number to big endian byte order
    
	// bind socket to the address set up above
	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) 
              error("ERROR on binding");
     
	listen(sockfd,5);//start listening on the socket for connections
	
	while(1)//loop on accept to take incoming connections
	{
		//accept new connections
		clilen = sizeof(cli_addr);
     		newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
     		if (newsockfd < 0) 
          		error("ERROR on accept");
	
		//exchnage verification with client
		char verify[256];
		bzero(verify, 256);
		n = recv(newsockfd, verify, 255, 0);
		if(n < 0)
			error("recv error");	
		//send validation word to client to prevent
		//otp_dec from connecting here
		bzero(buffer, 256);
		strcpy(buffer, "encrypt");	
		n = write(newsockfd, buffer, strlen(buffer));
		if(n < 0)
			error("ERROR writing to socket");	

		int status;
		int pid = fork();//fork off a new process
		if(pid < 0)
			error("fork error");
		else if(pid == 0)//child
		{
			close(sockfd);//we no longer need the "listening" socket
			
			//if verification from client is not
			//"encrypt" then close connection
			if( strcmp(buffer, verify) != 0)
			{
				close(newsockfd);
				error("ERROR: otp_dec can not connect to this server");
			}

			char buf[1025];

			int total = 0;
			bzero(key,sizeof(key));
			bzero(buf, sizeof(buf));
			//receive the encryption key from client 1024 byte increments
			while ((n = recv(newsockfd, buf, 1024, 0)) > 0)
			{	
				total += n;
				strcat(key, buf); //add new section to the whole
				bzero(buf, sizeof(buf));
				if (n < 1024)//the end of the string has been reached
			 		break;
			}
			
			//printf("key total: %d\nlength of key: %d\n", total, strlen(key));	
			
			//send confirmation to client that bytes were received
			//i did this mainly because i had trouble getting
			//consecutive sends from the client to work. it works
			//better if client and server call and respond
			bzero(buffer, 256);
	     		sprintf(buffer, "read %d bytes of key\n", total);
			total = strlen(buffer);
			sendall(newsockfd, buffer, &total); 
		
			//receive the message
			total = 0;
			bzero(buf, sizeof(buf));
			bzero(message, sizeof(message));
			while ((n = recv(newsockfd, buf, 1024, 0)) > 0)
			{
				total += n;
				strcat(message, buf);
				bzero(buf, sizeof(buf));	
				if (n < 1024)
				 	break;
			}
   	
			//printf("message total: %d\nlength of message before function: %d\n", total, strlen(message));	
			
			encrypt(key, message, encrypted);//encrypt the message
			
			//send the encryption back to the client
			total = strlen(encrypted);
			//printf("encrytped length: %d\n", total);
			sendall(newsockfd, encrypted, &total);

			//printf("encrypted total: %d\n", total);	
			
			close(newsockfd);
			exit(0);
		}
		else//parent
		{
			close(newsockfd);//closed connection being used in child
			
			//waitpid returns 0 when no children have changed state
			while(pid > 0)
				pid = waitpid(0, &status, WNOHANG);
		}

	}
	//the program shouldn't ever reach here
	close(sockfd);
     
	return 0; 
}

//function to encrypt a plain text file using the provided
//encryption key. result is stored in encrypted
void encrypt(char keyText[], char message[], char encrypted[])
{
	int i, msg, key, enc;
			
	memset(encrypted, 0, sizeof(encrypted));
	
	//printf("message length in function: %d\n", strlen(message));
	//iterate through each letter in message and encrypt
	//each one
	for(i = 0; i < strlen(message); i++)
	{
		//convert letter to integer (ASCII)
		msg = message[i];
		key = keyText[i];
		//printf("%d\n", key);
		//whitespace character is changed
		//to 91 to make encryption easier
		if(msg == 32)
			msg = 91;
		if(key == 32)
			key = 91;
		
		//subtract 65 to give a number
		//between 0 and 26 inclusive
		msg -= 65;
		key -= 65;
		enc = msg + key; 
		//printf("%d\n", enc);
		enc = enc % 27;
		//add 65 so it has the 
		//right ascii value
		enc += 65;
		if(enc == 91)
		       enc = 32;//space character
		//build encrypted string
		encrypted[i] = enc;				
	}
}

/*Source of this function is http://beej.us/guide/bgnet/output/html/singlepage/bgnet.html#sendman
 *sends data in buf through socket s and keeps track of what was sent to deal 
with partial sends.  */
int sendall(int s, char *buf, int *len)
{
	int total = 0;        // how many bytes we've sent
	int bytesleft = *len; // how many we have left to send
	int n;

	while(total < *len) {//loop until all of the data is sent
		n = send(s, buf+total, bytesleft, 0);
		if (n == -1) { break; }
		total += n;
		bytesleft -= n;
	}

	*len = total; // return number actually sent here

	return n==-1?-1:0; // return -1 on failure, 0 on success
}



