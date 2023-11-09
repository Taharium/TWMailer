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
#include <ldap.h>
#include <termios.h>

///////////////////////////////////////////////////////////////////////////////
const char* getpass();
int getch();
void sendEmail(std::string& newBuffer, std::string& username);
void listemail(std::string& newBuffer, std::string& username);
void readOrDel(std::string& newBuffer, std::string& username, bool usedList);
int sendingHeader(int& create_socket, int& size);
void loginToLDAP(std::string& username, std::string& newBuffer);
int sendAll(int& create_socket, std::string& newBuffer, int& size);
int receiveHandler(int &byte);
//int handleLogin(int& create_socket, std::string& username, std::string& newBuffer);



#define BUF 1024

///////////////////////////////////////////////////////////////////////////////

int main(int argc, char *argv[])
{
    std::string username;
    int create_socket;
    char buffer[BUF];
    struct sockaddr_in address;
    int size;
    int isQuit;
    bool loggedIn = false;
    bool usedList = false;
/*     int counter = 1;
    bool isBanned = false; */

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
        else if(argc == 3)
        {
            port = (in_port_t)std::stol(argv[2]);
            //std::cout << argv[1] << ' ' << port << '\n';
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
    int byte = recv(create_socket, &len, sizeof(len), 0); // header for initial message
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

    size = recv(create_socket, buffer, len, 0); // actuaöl initial message
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
        
        if (fgets(buffer, BUF - 1, stdin) != NULL) // read comand
        {
            int size = strlen(buffer);
            // remove new-line signs from string at the end
            if (buffer[size - 2] == '\r')
            {
                size -= 1;
                buffer[size] = 0;
            }
            
            for (char &c : buffer) 
            {
                c = std::toupper(c);
            }

            isQuit = strncmp(buffer, "QUIT\n", sizeof(buffer)) == 0;
            
            std::string newBuffer(buffer); // the command            
            
            if(loggedIn)
            {
                if(newBuffer == "SEND\n")
                    sendEmail(newBuffer, username);
                else if(newBuffer == "LIST\n")
                {
                    usedList = true;
                    listemail(newBuffer, username);
                }
                else if(newBuffer == "DEL\n" || newBuffer == "READ\n")
                {
                    readOrDel(newBuffer, username, usedList);
                }
            }
/* 
            if(counter == 3)
            {
                newBuffer.append("FAIL\n" + username + '\n' + std::to_string(counter) + '\n');   
                counter = 0;
                //TODO: how to get a flag that the timer is done on the next login --> if a person is blaclisted counter should not increase
            } */

            if(newBuffer == "LOGIN\n" && !loggedIn)
            {
                loginToLDAP(username, newBuffer);
                /* if(loginToLDAP(username))
                {
                    newBuffer.append(username + '\n' + std::to_string(counter) + '\n');
                }
                else
                {
                    if(counter != 3)
                        counter++;
                } */
                /* loginToLDAP(username);
                newBuffer.append(username + '\n' + std::to_string(counter) + '\n');
                send(create_socket, newBuffer.c_str(), newBuffer.size(), 0);
                int len = 0;
                int byte = recv(create_socket, &len, sizeof(len), 0);
                if(receiveHandler(byte) == -1)
                    break;
                len = ntohs(len);
                counter = len; */
                /* if(handleLogin(create_socket, newBuffer, username) == 0)
                {
                    loggedIn = true;
                } */
                /* if(loginToLDAP(username))// change --> validate everytime on login
                {
                    loggedIn = true;
                    size = newBuffer.size();
                    sendingHeader(create_socket, size);
                    send(create_socket, buffer, strlen(buffer), 0);
                    continue;
                } 
                */
            }

            //////////////////////////////////////////////////////////////////////
            // SEND DATA
            // https://man7.org/linux/man-pages/man2/send.2.html
            // send will fail if connection is closed, but does not set
            // the error of send, but still the count of bytes sent
            size = newBuffer.size();
            sendingHeader(create_socket, size); // header with length of message
            sendAll(create_socket, newBuffer, size); // actual message            

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
            byte = recv(create_socket, &len, sizeof(len), MSG_WAITFORONE); // receive header with length of message

            if(receiveHandler(byte) == -1)
                break;

            len = ntohs(len); //important
            char newBuf[len];

            size = recv(create_socket, newBuf, len, 0); // actal message
            if(receiveHandler(size) == -1)
                break;
            
            else
            {
                newBuf[size] = '\0';
                if(strncmp(newBuf, "OK", 2) == 0)
                {
                    loggedIn = true;
                }
                
                printf("<< %s\n", newBuf); // ignore error
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

void sendEmail(std::string& newBuffer, std::string& username)
{
    int counter = 1;
    newBuffer.append(username + '\n');
    std::cout << username << '\n';
    while (true)
    {
        switch (counter)
        {
        case 1:{
            std::cout << "receiver: ";
            std::string line;
            std::getline(std::cin, line);
            if(line.size() > 8)
            {
                std::cout << "receiver too long, max 8 characters\n";
                counter--;
                break;
            }
            newBuffer.append(line + '\n');
            break;
        }
        case 2:{
            std::cout << "subject: ";
            std::string line;
            std::getline(std::cin, line);
            if(line.size() > 80)
                line = line.substr(0, 80); //if higher than 80 --> trunc
            newBuffer.append(line + '\n');
            break;
        }
        case 3:
            std::cout << "message: ";
            break;
        }
        if (counter == 2 && counter == 0)
        {
            counter++;
            continue;
        }
        
        std::string line;
        std::getline(std::cin, line);
        newBuffer.append(line + '\n');
        counter++;

        // Check for termination sequence "\n.\n"
        int size = newBuffer.size();
        if (size >= 3 && newBuffer[size - 3] == '\n' && newBuffer[size - 2] == '.' && newBuffer[size - 1] == '\n')
        {
            //erases "\n.\n"
            newBuffer.erase(size - 3, 3);
            break;
        }
    }

}

void listemail(std::string& newBuffer, std::string& username)
{
    newBuffer.append(username + '\n');
}

void readOrDel(std::string& newBuffer, std::string& username, bool usedList)
{
    newBuffer.append(username + '\n');
    std::cout << "messagenumber: ";
    std::string line;
    std::getline(std::cin, line);
    newBuffer.append(line + '\n');
    newBuffer.append(std::to_string(usedList) + '\n');
}

int sendingHeader(int& create_socket, int& size)
{
    int len = htons(size);
    if(send(create_socket, &len, sizeof(len), 0) == -1)
    {
        perror("send failed");
        return 1;
    }
    return 0;
}

void loginToLDAP(std::string &username, std::string &newBuffer)
{
    // read username (bash: export ldapuser=<yourUsername>)
    char ldapBindUser[256];
    char rawLdapUser[128];
    std::cout << "\nUsername: ";
    std::getline(std::cin, username);
    std::cout << '\n' <<username.c_str() <<'\n';
    if (username.size() <= 8)
        strcpy(rawLdapUser, username.c_str());
    else
        return;
    sprintf(ldapBindUser, "uid=%s,ou=people,dc=technikum-wien,dc=at", rawLdapUser);
    printf("user set to: %s\n", ldapBindUser);

    // read password (bash: export ldappw=<yourPW>)
    char ldapBindPassword[256];
    strcpy(ldapBindPassword, getpass());
    std::string pw(ldapBindPassword);
    std::string user(ldapBindUser);
    newBuffer.append(user + '\n' + pw + '\n');
}

const char *getpass()
{
    int show_asterisk = 0;

    const char BACKSPACE = 127;
    const char RETURN = 10;

    unsigned char ch = 0;
    std::string password;

    printf("Password: ");

    while ((ch = getch()) != RETURN)
    {
        if (ch == BACKSPACE)
        {
            if (password.length() != 0)
            {
                if (show_asterisk)
                {
                    printf("\b \b"); // backslash: \b
                }
                password.resize(password.length() - 1);
            }
        }
        else
        {
            password += ch;
            if (show_asterisk)
            {
                printf("*");
            }
        }
    }
    printf("\n");
    return password.c_str();
}

int getch()
{
    int ch;
    // https://man7.org/linux/man-pages/man3/termios.3.html
    struct termios t_old, t_new;

    // https://man7.org/linux/man-pages/man3/termios.3.html
    // tcgetattr() gets the parameters associated with the object referred
    //   by fd and stores them in the termios structure referenced by
    //   termios_p
    tcgetattr(STDIN_FILENO, &t_old);
    
    // copy old to new to have a base for setting c_lflags
    t_new = t_old;

    // https://man7.org/linux/man-pages/man3/termios.3.html
    //
    // ICANON Enable canonical mode (described below).
    //   * Input is made available line by line (max 4096 chars).
    //   * In noncanonical mode input is available immediately.
    //
    // ECHO   Echo input characters.
    t_new.c_lflag &= ~(ICANON | ECHO);
    
    // sets the attributes
    // TCSANOW: the change occurs immediately.
    tcsetattr(STDIN_FILENO, TCSANOW, &t_new);

    ch = getchar();

    // reset stored attributes
    tcsetattr(STDIN_FILENO, TCSANOW, &t_old);

    return ch;
}

int sendAll(int& create_socket, std::string& newBuffer, int& size)
{
    int total = 0;
    int bytesLeft = size;
    int sendBytes = 0;
    while( total < size )
    {
        sendBytes = send(create_socket, newBuffer.c_str() + total, bytesLeft, 0);
        if (sendBytes == -1)
        {
            perror("send error");
            return -1;
        }
        total += sendBytes;
        bytesLeft -= sendBytes;
    }

    size = total;
    return 0;
}

/* int handleLogin(int& create_socket, std::string& username, std::string& newBuffer)
{
    int a = (int)loginToLDAP(username); 
    newBuffer.append(username + '\n');
    int size = newBuffer.size();
    sendingHeader(create_socket, size);
    send(create_socket, newBuffer.c_str(), newBuffer.size(), 0);

    int len = 0;
    int byte = recv (create_socket, &len, sizeof(len), 0);
    if(receiveHandler(byte) == -1)
        return -1;
    len = ntohs(len);
    char buffer[len];
    byte = recv(create_socket, buffer, len, 0);
    if(receiveHandler(byte) == -1)
        return -1;
    if(strncmp(buffer, "OK", 2))
        return 
} */

int receiveHandler(int &byte)
{
    if (byte == -1)
    {
        perror("recv error");
        return -1;
    }
    else if (byte == 0)
    {
        printf("Server closed remote socket\n"); // ignore error
        return -1;
    }
    return 0;
}
