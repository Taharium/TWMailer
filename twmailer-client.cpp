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
#include <vector>

///////////////////////////////////////////////////////////////////////////////
int sendEmail(std::string& newBuffer, int size, int& create_socket);
int listemail(std::string& newBuffer, int size, int& create_socket);
int readOrDel(std::string& newBuffer, int size, int& create_socket);
int sendingHeader(int& create_socket, int& size);

#define BUF 1024

///////////////////////////////////////////////////////////////////////////////

int main(int argc, char *argv[])
{
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
    int len = 0;
    int byte = recv(create_socket, &len, sizeof(len), 0);
    if (byte == -1)
    {
        perror("recv error");
    }
    else if (LC_IDENTIFICATION == 0)
    {
        printf("Server closed remote socket\n"); // ignore error
    }
    else
    {
        buffer[len] = '\0';
        //printf("%d", len); // ignore error
    }

    size = recv(create_socket, buffer, len, 0);
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
    memset(buffer, 0, sizeof(buffer));
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
            
            for (char &c : buffer) 
            {
                c = std::toupper(c);
            }
            
            std::string command(buffer);
            std::string newBuffer(buffer);
            if(command == "SEND\n")
                size = sendEmail(newBuffer, size, create_socket);
            else if(command == "LIST\n")
                size = listemail(newBuffer, size, create_socket);
            else if(command == "DEL\n" || command == "READ\n")
                size = readOrDel(newBuffer, size, create_socket);
            else if(command == "QUIT\n")
            {
                isQuit = true;
                int len = newBuffer.size();
                sendingHeader(create_socket, len);
            }
            else
            {
                int len = newBuffer.size();
                sendingHeader(create_socket, len);
            }
            //////////////////////////////////////////////////////////////////////
            // SEND DATA
            // https://man7.org/linux/man-pages/man2/send.2.html
            // send will fail if connection is closed, but does not set
            // the error of send, but still the count of bytes sent
            if ((send(create_socket, newBuffer.c_str(), newBuffer.size(), 0)) == -1)
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
            int len = 0, byte = 0;
            byte = recv(create_socket, &len, sizeof(len), MSG_WAITFORONE);
            if (byte == -1)
            {
                perror("recv error");
                break;
            }
            else if (byte == 0)
            {
                printf("Server closed remote socket\n"); // ignore error
                break;
            }

            len = ntohs(len);
            char newBuf[len];

            size = recv(create_socket, newBuf, len, 0);

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
                newBuf[size] = '\0';
                printf("<< %s\n", newBuf); // ignore error
                if (strcmp("ERR", newBuf) == 0)
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

int sendEmail(std::string& newBuffer, int size, int& create_socket)
{
    /* size = newBuffer.size(); //TODO: newline
    std::cout << buffer[1] << size << '\n';
    for(int i = 0; i<2; i++)
    {
        if (fgets(buffer + size, BUF - size - 1, stdin) == NULL)
        {
            //retuns 1 (size of buffer tht will be read in server) if there is an error
            return 1;
        }
        size = strlen(buffer);
    }

    if (fgets(buffer + size, 80, stdin) == NULL)
    {
        return 1;
    } */
    
    /*
    size = strlen(buffer); 
    
        // Read a line of input using fgets
        if (fgets(buffer + size, BUF - size -1, stdin) == NULL)
        {
            // Discard remaining characters in the input stream
            int extraLen = 0;
            int c;
            std::vector<char> buffer2;
            buffer2.reserve(BUF);
            while ((c = getchar()) != '\n' && c != EOF)
            {
                extraLen++;
                buffer2.emplace_back(c);
            }

            buffer[BUF-1] = '\0';
            break;
        } */
    int counter = 0;
    while (true) 
    {
        switch (counter)
        {
        case 0:
            std::cout << "sender: ";
            break;
        case 1:
            std::cout << "receiver: ";
            break;
        case 2:{
            std::cout << "subject: ";
            std::string line;
            std::getline(std::cin, line);
            if(line.size() > 80)
                line = line.substr(0, 80);
            newBuffer.append(line + '\n');
            break;
        }
        case 3:
            std::cout << "message: ";
            break;
        
        default:
            break;
        }
        if (counter == 2)
        {
            counter++;
            continue;
        }
        
        std::string line;
        std::getline(std::cin, line);
        newBuffer.append(line + '\n');
        counter++;

        // Check for termination sequence "\n.\n"
        size = newBuffer.size();
        if (size >= 3 && newBuffer[size - 3] == '\n' && newBuffer[size - 2] == '.' && newBuffer[size - 1] == '\n')
        {
            break;
        }
    }
    size = newBuffer.size();
    return sendingHeader(create_socket, size);


    /* char message[] = "Ist dies eine sehr lange Nachricht, die in Teilen gesendet werden soll?";
    int message_length = strlen(message);
    int bytes_sent = 0;
    int total_bytes_sent = 0;

    while (total_bytes_sent < message_length) {
        int remaining_bytes = message_length - total_bytes_sent;
        int bytes_to_send = (remaining_bytes > BUF) ? BUF : remaining_bytes;

        // Kopieren Sie einen Teil der Nachricht in den Puffer.
        char buffer[BUF];
        strncpy(buffer, message + total_bytes_sent, bytes_to_send);

        // Senden Sie den Puffer über die Verbindung.
        int bytes_just_sent = send(, buffer, bytes_to_send, 0);
        if (bytes_just_sent == -1) {
            perror("send");
            break; // Fehlerbehandlung
        }

        total_bytes_sent += bytes_just_sent;
    } */

}

int listemail(std::string& newBuffer, int size, int& create_socket)
{
    std::cout << "username: ";
    std::string line;
    std::getline(std::cin, line);
    newBuffer.append(line + '\n');
    size = newBuffer.size();
    return sendingHeader(create_socket, size);

}

int readOrDel(std::string& newBuffer, int size, int& create_socket)
{
    for(int i = 0; i < 2; i++)
    {
        if(i == 0)
            std::cout << "username: ";
        else
            std::cout << "messagenumber: ";
        std::string line;
        std::getline(std::cin, line);
        newBuffer.append(line + '\n');
    }
    size = newBuffer.size();
    return sendingHeader(create_socket, size);
    
}

int sendingHeader(int& create_socket, int& size)
{
    int len = htons(size);
    if(send(create_socket, &len, sizeof(len), 0) == -1)
    {
        perror("send failed");
        return 1;
    }

    return size;
}