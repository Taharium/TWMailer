#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <iostream>
#include <stdexcept>
#include <cctype>

///////////////////////////////////////////////////////////////////////////////
int sendEmail(char buffer[], int size);
int listemail(char buffer[], int size);
int readOrDel(char buffer[], int size);

#define BUF 1024

///////////////////////////////////////////////////////////////////////////////

int main(int argc, char *argv[])
{
    for (int i = 0; i < argc; i++)
    {
        std::cerr << argv[i];
    }
    int create_socket;
    char buffer[BUF];
    struct sockaddr_in address;
    int size;
    int isQuit;

    ////////////////////////////////////////////////////////////////////////////
    // CREATE A SOCKET
    // https://man7.org/linux/man-pages/man2/socket.2.html
    // https://man7.org/linux/man-pages/man7/ip.7.html
    // https://man7.org/linux/man-pages/man7/tcp.7.html
    // IPv4, TCP (connection oriented), IP (same as server)
    if ((create_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("Socket error");
        return EXIT_FAILURE;
    }

    ////////////////////////////////////////////////////////////////////////////
    // INIT ADDRESS
    // Attention: network byte order => big endian
    memset(&address, 0, sizeof(address)); // init storage with 0
    address.sin_family = AF_INET;         // IPv4
    // https://man7.org/linux/man-pages/man3/htons.3.html
   

    // checks if agrc is 3 for port
     in_port_t port;
    try
    {
        if (argc < 2 || argc > 3)
            throw std::invalid_argument("There are either not enough arguemnts or too many.\nPlease enter IP-Adress(optional) and the port\n");

        if(argc == 2)
        {
            // https://man7.org/linux/man-pages/man3/inet_aton.3.html
            inet_aton("127.0.0.1", &address.sin_addr);
            port = (in_port_t)std::stol(argv[1]);
        }
        else
        {
            port = (in_port_t)std::stol(argv[2]);
            inet_aton(argv[1], &address.sin_addr);
        }

        if ((port > 1024)) // port can only be between those two numbers
            address.sin_port = htons(port);
    }
    catch (const std::invalid_argument &e)
    {
        std::cerr << e.what() << '\n';
    }

    ////////////////////////////////////////////////////////////////////////////
    // CREATE A CONNECTION
    // https://man7.org/linux/man-pages/man2/connect.2.html
    if (connect(create_socket, (struct sockaddr *)&address, sizeof(address)) == -1)
    {
        // https://man7.org/linux/man-pages/man3/perror.3.html
        perror("Connect error - no server available");
        return EXIT_FAILURE;
    }

    // ignore return value of printf
    printf("Connection with server (%s) established\n", inet_ntoa(address.sin_addr));

    ////////////////////////////////////////////////////////////////////////////
    // RECEIVE DATA
    // https://man7.org/linux/man-pages/man2/recv.2.html
    size = recv(create_socket, buffer, BUF - 1, 0);
    if (size == -1)
    {
        perror("recv error");
    }
    else if (size == 0)
    {
        printf("Server closed remote socket\n"); // ignore error
    }
    else
    {
        buffer[size] = '\0';
        printf("%s", buffer); // ignore error
    }

    do
    {
        printf(">> ");

        
        if (fgets(buffer, BUF - 1, stdin) != NULL)
        {
            int size = strlen(buffer);
            // remove new-line signs from string at the end
            if (buffer[size - 2] == '\r')
            {
                size -= 1;
                buffer[size] = 0;
            }
            isQuit = strncmp(buffer, "quit\n", sizeof(buffer)) == 0;
            
            for (char &c : buffer) {
                c = std::toupper(c);
            }
            
            std::string command(buffer);
            
            if(command == "SEND\n")
                size = sendEmail(buffer, size);
            else if(command == "LIST\n")
                size = listemail(buffer, size);
            else if(command == "DEL\n" || command == "READ\n")
                size = readOrDel(buffer, size);
            



            //////////////////////////////////////////////////////////////////////
            // SEND DATA
            // https://man7.org/linux/man-pages/man2/send.2.html
            // send will fail if connection is closed, but does not set
            // the error of send, but still the count of bytes sent
            if ((send(create_socket, buffer, size + 1, 0)) == -1)
            {
                // in case the server is gone offline we will still not enter
                // this part of code: see docs: https://linux.die.net/man/3/send
                // >> Successful completion of a call to send() does not guarantee
                // >> delivery of the message. A return value of -1 indicates only
                // >> locally-detected errors.
                // ... but
                // to check the connection before send is sense-less because
                // after checking the communication can fail (so we would need
                // to have 1 atomic operation to check...)
                perror("send error");
                break;
            }

            //////////////////////////////////////////////////////////////////////
            // RECEIVE FEEDBACK
            // consider: reconnect handling might be appropriate in somes cases
            //           How can we determine that the command sent was received
            //           or not?
            //           - Resend, might change state too often.
            //           - Else a command might have been lost.
            //
            // solution 1: adding meta-data (unique command id) and check on the
            //             server if already processed.
            // solution 2: add an infrastructure component for messaging (broker)
            //
            if(isQuit != 0)
            {
                break;
            }
            memset(buffer, 0, sizeof(buffer));
            size = recv(create_socket, buffer, BUF - 1, 0);
            //std::cout << size << '\n';
            if (size == -1)
            {
                perror("recv error");
                break;
            }
            else if (size == 0)
            {
                printf("Server closed remote socket\n"); // ignore error
                break;
            }
            else
            {
                buffer[size] = '\0';
                printf("<< %s\n", buffer); // ignore error
                if (strcmp("OK", buffer) != 0)
                {
                    fprintf(stderr, "<< Server error occured, abort\n");
                    break;
                }
            }
        }
    } while (!isQuit);

    ////////////////////////////////////////////////////////////////////////////
    // CLOSES THE DESCRIPTOR
    if (create_socket != -1)
    {
        if (shutdown(create_socket, SHUT_RDWR) == -1)
        {
            // invalid in case the server is gone already
            perror("shutdown create_socket");
        }
        if (close(create_socket) == -1)
        {
            perror("close create_socket");
        }
        create_socket = -1;
    }

    return EXIT_SUCCESS;
}

int sendEmail(char buffer[], int size)
{
    size = strlen(buffer); //TODO: newline
    std::cout << buffer[1] << size << '\n';
    for(int i = 0; i<2; i++)
    {
        if (fgets(buffer + size, BUF - size - 1, stdin) != NULL)
        {
            std::cout << buffer;
        }
        size = strlen(buffer);
    }
    if (fgets(buffer + size, 80, stdin) != NULL)
    {
        std::cout << buffer;
    }
    size = strlen(buffer);
    
    if (fgets(buffer + size, BUF - size -1, stdin) != NULL)
    {
        std::cout << buffer;
    }

    if(strlen(buffer) > BUF)
    {
        buffer[BUF - 1] = '\0';
    }
    size = strlen(buffer);
    std::cout << size << '\n';

    return size;
}

int listemail(char buffer[], int size)
{
    if (fgets(buffer + size, BUF - size - 1, stdin) != NULL)
    {
        std::cout << buffer;
    }    
    size = strlen(buffer);

    return size;
}

int readOrDel(char buffer[], int size)
{
    for(int i = 0; i<2; i++)
    {
        if (fgets(buffer + size, BUF - size - 1, stdin) != NULL)
        {
            std::cout << buffer;
        }
        size = strlen(buffer);
    }

    return size;
}