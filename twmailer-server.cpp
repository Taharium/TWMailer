#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <filesystem>
#include <vector>
#include <cstring>
#include <algorithm>
#include <set>
#include <map>
#include <tuple>
#include <ctime>
#include <ldap.h>
#include <termios.h>
/* #include <stdexcept>

// Custom exception class derived from std::exception
class MyException : public std::exception {
public:
    // Constructor that accepts a custom error message
    MyException(const char* message) : errorMessage(message) {}

    // Override the what() function to provide error message
    const char* what() const noexcept override {
        return errorMessage.c_str();
    }

private:
    std::string errorMessage;
}; */

namespace fs = std::filesystem;

///////////////////////////////////////////////////////////////////////////////
#define BUF 1024

///////////////////////////////////////////////////////////////////////////////

int abortRequested = 0;
int create_socket = -1;
int new_socket = -1;

///////////////////////////////////////////////////////////////////////////////

void createDir(std::vector<std::string>& parts, const std::string& receiverDir);
void writeIntoFile(std::vector<std::string>& parts, const std::string& receiverDir);
void updateIndex(const std::string& filePath, int index);
void deleteFile(const std::string& pathToFileToDelete);
int sendingHeader(int* current_socket, int& size);
std::string readFile(const std::string& pathToFileToRead);
std::string listFiles(const std::string& receive);
void *clientCommunication(void *data, std::string spoolDirectory, struct sockaddr_in& cliad);
void signalHandler(int sig);
void writeBanToFile(std::map<std::tuple<std::string, std::string>, std::time_t>& banMap);
bool loginToLDAP(std::vector<std::string>& credentials);

///////////////////////////////////////////////////////////////////////////////

int main(int argc, char *argv[])
{
    socklen_t addrlen;
    struct sockaddr_in address, cliaddress;
    int reuseValue = 1;

    ////////////////////////////////////////////////////////////////////////////
    // SIGNAL HANDLER
    // SIGINT (Interrup: ctrl+c)
    // https://man7.org/linux/man-pages/man2/signal.2.html
    if (signal(SIGINT, signalHandler) == SIG_ERR)
    {
        perror("signal can not be registered");
        return EXIT_FAILURE;
    }

    ////////////////////////////////////////////////////////////////////////////
    // CREATE A SOCKET
    // https://man7.org/linux/man-pages/man2/socket.2.html
    // https://man7.org/linux/man-pages/man7/ip.7.html
    // https://man7.org/linux/man-pages/man7/tcp.7.html
    // IPv4, TCP (connection oriented), IP (same as client)
    if ((create_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("Socket error"); // errno set by socket()
        return EXIT_FAILURE;
    }

    ////////////////////////////////////////////////////////////////////////////
    // SET SOCKET OPTIONS
    // https://man7.org/linux/man-pages/man2/setsockopt.2.html
    // https://man7.org/linux/man-pages/man7/socket.7.html
    // socket, level, optname, optvalue, optlen
    if (setsockopt(create_socket, SOL_SOCKET, SO_REUSEADDR, &reuseValue, sizeof(reuseValue)) == -1)
    {
        perror("set socket options - reuseAddr");
        return EXIT_FAILURE;
    }

    if (setsockopt(create_socket, SOL_SOCKET, SO_REUSEPORT, &reuseValue, sizeof(reuseValue)) == -1)
    {
        perror("set socket options - reusePort");
        return EXIT_FAILURE;
    }

    ////////////////////////////////////////////////////////////////////////////
    // INIT ADDRESS
    // Attention: network byte order => big endian
    if(argc != 3)
    {
        printf("There are either not enough arguemnts or too many.\nPlease enter port and mail-spool-directoryname\n");
        return EXIT_FAILURE;
    }

    in_port_t port = (in_port_t)std::stol(argv[1]);
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    ////////////////////////////////////////////////////////////////////////////
    // ASSIGN AN ADDRESS WITH PORT TO SOCKET
    if (bind(create_socket, (struct sockaddr *)&address, sizeof(address)) == -1)
    {
        perror("bind error");
        return EXIT_FAILURE;
    }

    ////////////////////////////////////////////////////////////////////////////
    // ALLOW CONNECTION ESTABLISHING
    // Socket, Backlog (= count of waiting connections allowed)
    if (listen(create_socket, 5) == -1)
    {
        perror("listen error");
        return EXIT_FAILURE;
    }

    while (!abortRequested)
    {
        /////////////////////////////////////////////////////////////////////////
        // ignore errors here... because only information message
        // https://linux.die.net/man/3/printf
        printf("Waiting for connections...\n");

        /////////////////////////////////////////////////////////////////////////
        // ACCEPTS CONNECTION SETUP
        // blocking, might have an accept-error on ctrl+c
        addrlen = sizeof(struct sockaddr_in);
        if ((new_socket = accept(create_socket, (struct sockaddr *)&cliaddress, &addrlen)) == -1)
        {
            if (abortRequested)
            {
                perror("accept error after aborted");
            }
            else
            {
                perror("accept error");
            }
            break;
        }

        /////////////////////////////////////////////////////////////////////////
        // START CLIENT
        // ignore printf error handling
        printf("Client connected from %s:%d...\n", inet_ntoa(cliaddress.sin_addr), ntohs(cliaddress.sin_port));
        clientCommunication(&new_socket, argv[2], cliaddress); // returnValue can be ignored
        new_socket = -1;
    }

    // frees the descriptor
    if (create_socket != -1)
    {
        if (shutdown(create_socket, SHUT_RDWR) == -1)
        {
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

void *clientCommunication(void *data, std::string spoolDirectory, struct sockaddr_in& cliad)
{
    std::map<std::tuple<std::string, std::string>, std::time_t> banMap;
    std::string buffer;
    int size;
    int *current_socket = (int *)data;
    int counterBanned = 0;

    ////////////////////////////////////////////////////////////////////////////
    // SEND welcome message
    buffer = "Welcome to myserver!\r\nPlease enter your commands...\r\n";
    size = buffer.size();
    //header for length of message in buffer
    if (send(*current_socket, &size, sizeof(size), 0) == -1)
    {
        perror("send failed");
        return NULL;
    }
    //std::strcpy(buffer, "Welcome to myserver!\r\nPlease enter your commands...\r\n");
    if (send(*current_socket, buffer.c_str(), buffer.size(), 0) == -1)
    {
        perror("send failed");
        return NULL;
    }
    do
    {
        /////////////////////////////////////////////////////////////////////////
        // RECEIVE
        int len = 0;
        int byte;
        byte = recv(*current_socket, &len, sizeof(len), MSG_WAITFORONE); //receive header
        if (byte == -1) // check if header has an error
        {
            if (abortRequested)
            {
                perror("recv error after aborted");
            }
            else
            {
                perror("recv error");
            }
            break;
        }
        if (byte == 0)
        {
            printf("Client closed remote socket\n"); // ignore error
            break;
        }
        len = ntohs(len);
        char newBuffer[len];

        size = recv(*current_socket, newBuffer, len, 0); // real data using the length in header

        if (size == -1)
        {
            if (abortRequested)
            {
                perror("recv error after aborted");
            }
            else
            {
                perror("recv error");
            }
            break;
        }
        if (size == 0)
        {
            printf("Client closed remote socket\n"); // ignore error
            break;
        }

        // remove ugly debug message, because of the sent newline of client
        if (newBuffer[size - 2] == '\r' && newBuffer[size - 1] == '\n')
        {
            size -= 2;
        }
        else if (newBuffer[size - 1] == '\n')
        {
            --size;
        }

        std::string message = "OK";
        newBuffer[size] = '\0';
        // Read strings separated by '\n' from the input stream

        std::vector<std::string> parts;
        parts.reserve(3);

        std::istringstream stream(newBuffer); // Create an input string stream from the buffer
        std::string line;

        //bool readList = false;
        int counter = 0;
        
        while (std::getline(stream, line, '\n'))
        {
            // Process the extracted string (in this example, just print it)
            parts.emplace_back(line);
            counter++;
        }
        if(parts.size() < 2)
            message = "ERR";
        else if(strncmp(newBuffer, "LOGIN", 4) == 0)
        {
            bool isLoggedin = false;
            bool banned = false;
            char clientIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(cliad.sin_addr), clientIP, INET_ADDRSTRLEN);
            std::string ipstring(clientIP);
            auto keyTuple = std::make_tuple(ipstring, parts[1]);
            if(banMap.find(keyTuple) != banMap.end())
            {
                std::time_t currentTime = std::time(0);
                std::time_t bannedTime = banMap[keyTuple];
                if(currentTime > bannedTime)
                {
                    banMap.erase(keyTuple);
                    //TODO search in file and delete
                }
                else
                {
                    message = "ERR - BANNED"; // build own exception for this
                    banned = true;
                }
            }
            
            if(loginToLDAP(parts) && !banned)
            {
                counterBanned = 0;
                isLoggedin = true;          
            }
            else if(!banned)
            {
                counterBanned++;
                message = "ERR - Wrong credentials";
                isLoggedin = false;
            }

            if(!isLoggedin && counterBanned == 3 && !banned)
            {
                char clientIP[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(cliad.sin_addr), clientIP, INET_ADDRSTRLEN);
                std::string ipstring(clientIP);
                std::cout << ipstring << std::endl;
                auto keyTuple = std::make_tuple(ipstring, parts[1]);
                std::time_t bannedTime = std::time(0) + 60;
                //std::string timeString = std::ctime(&bannedTime);
                banMap[keyTuple] = bannedTime;
                writeBanToFile(banMap);
                message = "ERR - Blacklisted";
                counterBanned = 0;
            }
        }
        else if(strncmp(newBuffer, "FAIL", 4) == 0)
        {
            
        }
        else if(strncmp(newBuffer, "SEND", 4) == 0) // send
        {
            if(counter >= 5)
            {
                std::string receiverDir = spoolDirectory + "/" + parts[2];
                if(!fs::exists(spoolDirectory)) //if spool does not exists --> creat
                    fs::create_directories(spoolDirectory);
                
                if(!fs::exists(receiverDir)) //if username-Dir does not exit --> creat
                {
                    createDir(parts, receiverDir);
                }
                else
                {
                    writeIntoFile(parts, receiverDir); // write into file
                }
            }
            else
            {
                message = "ERR";
            }
        }
        else if(strncmp(newBuffer, "LIST", 4) == 0) //list
        {
            if(counter == 2)
            {
                std::string directoryPath = spoolDirectory + "/" + parts[1]; //directorypath using username
                if (fs::is_directory(directoryPath)) 
                {
                    message = listFiles(directoryPath);
                    //readList = true;
                } 
                else 
                {
                    message = "0 messages";
                }
            }
            else 
            {
                message = "ERR";
            }
        }
        else if(strncmp(newBuffer, "DEL", 3) == 0) //delete
        {
            if(std::stoi(parts[3]) > 0)
            {
                message = "ERR - List at least once";
                counter = 0;
            }

            if(counter == 4)
            {
                std::string pathToFileToDelete = spoolDirectory + "/" + parts[1] + "/" + parts[2] + ".txt"; //path of file to delete using username and messagenumber
                if (fs::exists(pathToFileToDelete)) 
                {
                    deleteFile(pathToFileToDelete);
                } 
                else
                {
                    message = "ERR";
                }
            }
            else
            {
                message = "ERR";
            }
        }
        else if(strncmp(newBuffer, "READ", 4) == 0)
        {
            if(std::stoi(parts[3]) > 0)
            {
                message = "ERR - List at least once";
                counter = 0;
            }

            if(counter == 4 )
            {
                std::string pathToFileToRead = spoolDirectory + "/" + parts[1] + "/" + parts[2] + ".txt"; //path of file to read using username and messagenumber
                if (fs::exists(pathToFileToRead)) 
                {
                    message = readFile(pathToFileToRead);
                } 
                else
                {
                    message = "ERR";
                }
            }
            else
            {
                message = "ERR";
            }
        }
        else if(strncmp(newBuffer, "QUIT", 4) == 0) //quit
        {
            break;
        }
        else // if there is a typo in command return err
        {
            message = "ERR";
        }

        printf("Message received: %s\n", newBuffer); // ignore error

        int size = message.size();

        sendingHeader(current_socket, size); // header with length of message
        
        if (send(*current_socket, message.c_str(), message.size(), 0) == -1) //actual string
        {
            perror("send answer failed");
            return NULL;
        }
    } while (!abortRequested);
    // closes/frees the descriptor if not already
    if (*current_socket != -1)
    {
        if (shutdown(*current_socket, SHUT_RDWR) == -1)
        {
            perror("shutdown new_socket");
        }
        if (close(*current_socket) == -1)
        {
            perror("close new_socket");
        }
        *current_socket = -1;
    }

    return NULL;
}

void signalHandler(int sig)
{
    if (sig == SIGINT)
    {
        printf("abort Requested... "); // ignore error
        abortRequested = 1;
        /////////////////////////////////////////////////////////////////////////
        // With shutdown() one can initiate normal TCP close sequence ignoring
        // the reference count.
        // https://beej.us/guide/bgnet/html/#close-and-shutdownget-outta-my-face
        // https://linux.die.net/man/3/shutdown
        if (new_socket != -1)
        {
            if (shutdown(new_socket, SHUT_RDWR) == -1)
            {
                perror("shutdown new_socket");
            }
            if (close(new_socket) == -1)
            {
                perror("close new_socket");
            }
            new_socket = -1;
        }

        if (create_socket != -1)
        {
            if (shutdown(create_socket, SHUT_RDWR) == -1)
            {
                perror("shutdown create_socket");
            }
            if (close(create_socket) == -1)
            {
                perror("close create_socket");
            }
            create_socket = -1;
        }
    }
    else
    {
        exit(sig);
    }
}

void createDir(std::vector<std::string>& parts, const std::string& receiverDir)
{
        // Check if the directory already exists, if not, create it
    try 
    {
        fs::create_directories(receiverDir); //create spool dir
        std::string filePath = receiverDir + "/index.txt";
        updateIndex(filePath, 0); // if no indexfile create
        writeIntoFile(parts, receiverDir);
    } 
    catch (const std::exception& e) 
    {
        std::cerr << "Failed to create directory: " << e.what() << std::endl;
    }
}

void writeIntoFile(std::vector<std::string>& parts, const std::string& receiverDir)
{
    std::string filePathIndex = receiverDir + "/index.txt";
    std::ifstream inputFile(filePathIndex);
    int index = 0;
    if (inputFile.is_open())  //open index and take the number 
    {
        std::string line;
        std::getline(inputFile, line);
        index = std::stoi(line);
        // Close the file after reading
        inputFile.close();
    }

    index++;

    std::string msgFile = std::to_string(index) + ".txt";
    std::string filePath = receiverDir + "/" + msgFile;
    std::ofstream outputFile(filePath);
    if (outputFile.is_open()) 
    {
        // Write content to the file
        for(size_t i = 1; i < parts.size(); i++)
        {
            if(i == parts.size()-1)
                outputFile << parts[i];
            else
                outputFile << parts[i] << '\n';
        }
            
        outputFile.close();
    }
    updateIndex(filePathIndex, index); //update index after creating a file
}

void updateIndex(const std::string& filePath, int index)
{
    std::ofstream outputFile(filePath);
    if (outputFile.is_open())
    {
        // Write index to the file
        outputFile << index << '\n';
        outputFile.close();
    }
}

std::string listFiles(const std::string& directoryPath) 
{
    std::string message = "";
    int filenameFound = 0;
    std::set<std::string> sortfile;
    for (const auto& entry : fs::directory_iterator(directoryPath)) 
    {
        if (fs::is_regular_file(entry) && entry.path().filename().string() != "index.txt") 
        {
            filenameFound++;
            std::ifstream inputFile(entry.path()); //open file to read
            int lineCount = 0;
            if (inputFile.is_open()) 
            {
                std::string line;
                while (std::getline(inputFile, line)) 
                {
                    ++lineCount;

                    if (lineCount == 3) //take only subject
                    {
                        //subject and filenumber for list
                        sortfile.insert(line + ' ' + entry.path().filename().stem().string() + '\n');
                        //message.append(line + ' ' + entry.path().filename().stem().string() + '\n');
                        break;
                    }
                }
            }
            // Close the file after reading
            inputFile.close();
        }
    }
    message.append(std::to_string(filenameFound) + " messages\n");
    for (auto &&i : sortfile)
    {
        message.append(i);
    }
    
    /* std::string prefix = std::to_string(filenameFound) + " messages\n";
    message.insert(0, prefix); */
    if(message.back() == '\n') //delete last \n
        message.pop_back();
    return message;
}


void deleteFile(const std::string& pathToFileToDelete)
{
    try 
    {
        // delete the file
        fs::remove(pathToFileToDelete);
    } 
    catch (const std::exception& e) 
    {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

std::string readFile(const std::string& pathToFileToRead)
{
    std::string message = "OK\n";
    std::ifstream inputFile(pathToFileToRead); // open file to read
    if (inputFile.is_open()) 
    {   
        std::string line;
        // read line by line
        while (std::getline(inputFile, line)) 
        {
            message.append(line + '\n');
        }

        // close file and delete last \n
        inputFile.close();
        if(message.back() == '\n')
            message.pop_back();
    }
    else
    {
        message = "ERR";
    }

    return message;
}

int sendingHeader(int* current_socket, int& size) //sending header with length of message
{
    int len = htons(size);
    if(send(*current_socket, &len, sizeof(len), 0) == -1)
    {
        perror("send failed");
        return 1;
    }

    return size;
}

void writeBanToFile(std::map<std::tuple<std::string, std::string>, std::time_t>& banMap)
{
    std::string banDir = "banDir";
    if(!fs::exists(banDir)) //if spool does not exists --> creat
        fs::create_directories(banDir);
    
    std::ofstream outputFile(banDir + "/ban.txt", std::ios::app);
    if (outputFile.is_open())
    {
        for(auto& i : banMap)
        {
            auto& [ip, user] = i.first;
            auto& time = i.second;
            outputFile << ip << user << ' ' << time << '\n';
        }
        outputFile.close();
    }
}

bool loginToLDAP(std::vector<std::string>& credentials)
{
    std::string& username = credentials[1];
    std::string& password = credentials[2];

    ////////////////////////////////////////////////////////////////////////////
    // LDAP config
    // anonymous bind with user and pw empty
    const char *ldapUri = "ldap://ldap.technikum-wien.at:389";
    const int ldapVersion = LDAP_VERSION3;

    // general
    int rc = 0; // return code

    ////////////////////////////////////////////////////////////////////////////
    // setup LDAP connection
    // https://linux.die.net/man/3/ldap_initialize
    LDAP *ldapHandle;
    rc = ldap_initialize(&ldapHandle, ldapUri);
    if (rc != LDAP_SUCCESS)
    {
        fprintf(stderr, "ldap_init failed\n");
        return false;
    }
    printf("connected to LDAP server %s\n", ldapUri);

    ////////////////////////////////////////////////////////////////////////////
    // set verison options
    // https://linux.die.net/man/3/ldap_set_option
    rc = ldap_set_option(
        ldapHandle,
        LDAP_OPT_PROTOCOL_VERSION, // OPTION
        &ldapVersion);             // IN-Value
    if (rc != LDAP_OPT_SUCCESS)
    {
        // https://www.openldap.org/software/man.cgi?query=ldap_err2string&sektion=3&apropos=0&manpath=OpenLDAP+2.4-Release
        fprintf(stderr, "ldap_set_option(PROTOCOL_VERSION): %s\n", ldap_err2string(rc));
        ldap_unbind_ext_s(ldapHandle, NULL, NULL);
        return false;
    }

    ////////////////////////////////////////////////////////////////////////////
    // start connection secure (initialize TLS)
    // https://linux.die.net/man/3/ldap_start_tls_s
    // int ldap_start_tls_s(LDAP *ld,
    //                      LDAPControl **serverctrls,
    //                      LDAPControl **clientctrls);
    // https://linux.die.net/man/3/ldap
    // https://docs.oracle.com/cd/E19957-01/817-6707/controls.html
    //    The LDAPv3, as documented in RFC 2251 - Lightweight Directory Access
    //    Protocol (v3) (http://www.faqs.org/rfcs/rfc2251.html), allows clients
    //    and servers to use controls as a mechanism for extending an LDAP
    //    operation. A control is a way to specify additional information as
    //    part of a request and a response. For example, a client can send a
    //    control to a server as part of a search request to indicate that the
    //    server should sort the search results before sending the results back
    //    to the client.
    rc = ldap_start_tls_s(
        ldapHandle,
        NULL,
        NULL);
    if (rc != LDAP_SUCCESS)
    {
        fprintf(stderr, "ldap_start_tls_s(): %s\n", ldap_err2string(rc));
        ldap_unbind_ext_s(ldapHandle, NULL, NULL);
        return false;
    }

    ////////////////////////////////////////////////////////////////////////////
    // bind credentials
    // https://linux.die.net/man/3/lber-types
    // SASL (Simple Authentication and Security Layer)
    // https://linux.die.net/man/3/ldap_sasl_bind_s
    // int ldap_sasl_bind_s(
    //       LDAP *ld,
    //       const char *dn,
    //       const char *mechanism,
    //       struct berval *cred,
    //       LDAPControl *sctrls[],
    //       LDAPControl *cctrls[],
    //       struct berval **servercredp);

    BerValue bindCredentials;
    bindCredentials.bv_val = (char *)password.c_str();
    bindCredentials.bv_len = password.size();
    BerValue *servercredp; // server's credentials
    rc = ldap_sasl_bind_s(
        ldapHandle,
        username.c_str(),
        LDAP_SASL_SIMPLE,
        &bindCredentials,
        NULL,
        NULL,
        &servercredp);
    if (rc != LDAP_SUCCESS)
    {
        fprintf(stderr, "LDAP bind error: %s\n", ldap_err2string(rc));
        ldap_unbind_ext_s(ldapHandle, NULL, NULL);
        return false;
    }
    ldap_unbind_ext_s(ldapHandle, NULL, NULL);
    return true;
}