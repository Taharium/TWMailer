#include "headers/clientheaders.h"

///////////////////////////////////////////////////////////////////////////////
const char* getpass();
int getch();
void sendEmail(std::string& newBuffer, std::string& username);
void listemail(std::string& newBuffer, std::string& username);
void readOrDel(std::string& newBuffer, std::string& username, bool usedList);
bool loginToLDAP(std::string& username, int& create_socket, bool& isBanned);
int sendAllHeader(int& create_socket, int& size);
int sendAll(int& create_socket, std::string& newBuffer, int& size);
int receiveHandler(int byte);
int recvAll(int create_socket, char* message, int size);
int recvAllHeader(int create_socket, int &size);

#define BUF 1024

///////////////////////////////////////////////////////////////////////////////

int main(int argc, char *argv[])
{
    std::string username;
    int create_socket;
    struct sockaddr_in address;
    int size;
    int isQuit;
    bool loggedIn = false;
    bool usedList = false;
    bool isBanned = false;


    // CREATE A SOCKET
    if ((create_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("Socket error");
        return EXIT_FAILURE;
    }

    // INIT ADDRESS
    // Attention: network byte order => big endian
    memset(&address, 0, sizeof(address)); // init storage with 0
    address.sin_family = AF_INET;         // IPv4

    
    in_port_t port;
    try
    {
        if (argc < 2 || argc > 3) // checks if agrc is 3 for port
            throw std::invalid_argument("There are either not enough arguemnts or too many.\nPlease enter IP-Adress(optional) and the port\n");

        if(argc == 2)
        {
            inet_aton("127.0.0.1", &address.sin_addr); // localhost as default IP, ipstring converted to binary
            port = (in_port_t)std::stol(argv[1]); // port as argument 
        }
        else if(argc == 3)
        {
            inet_aton(argv[1], &address.sin_addr); // IP as argument, ipstring converted to binary
            port = (in_port_t)std::stol(argv[2]); // port as argument
        }

        if ((port > 1024)) // port can only be between those two numbers
            address.sin_port = htons(port); 
    }
    catch (const std::invalid_argument &e)
    {
        std::cerr << e.what() << '\n';
    }

    // CREATE A CONNECTION
    if (connect(create_socket, (struct sockaddr *)&address, sizeof(address)) == -1)
    {
        perror("Connect error - no server available");
        return EXIT_FAILURE;
    }

    // ignore return value of printf
    printf("Connection with server (%s) established\n", inet_ntoa(address.sin_addr));

    int len = 0;

    if(recvAllHeader(create_socket, len) == -1) // header with length of message
        return EXIT_FAILURE;

    //len = ntohs(len); //important
    char buffer[len]; // buffer for message, size of message

    if((size = recvAll(create_socket, buffer, len)) == -1) // actual message
        return EXIT_FAILURE;
    else 
    {
        buffer[size] = '\0'; // add end of string
        printf("%s", buffer);
    }

    memset(buffer, 0, sizeof(buffer)); // clear buffer
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
            
            for (char &c : buffer)  // convert to uppercase
                c = std::toupper(c);

            isQuit = strncmp(buffer, "QUIT\n", sizeof(buffer)) == 0; // check if quit
            
            std::string newBuffer(buffer); // convert char* to string           
            
            if(loggedIn) // check if logged in
            {
                if(newBuffer == "SEND\n")
                    sendEmail(newBuffer, username);
                else if(newBuffer == "LIST\n")
                {
                    usedList = true;
                    listemail(newBuffer, username);
                }
                else if(newBuffer == "DEL\n" || newBuffer == "READ\n")
                    readOrDel(newBuffer, username, usedList);
            }

            if(newBuffer == "LOGIN\n" && !loggedIn) // check if login was entered
            {
                bool login = loginToLDAP(username, create_socket, isBanned); // login to ldap
                newBuffer.append(username + '\n' + std::to_string(login) + '\n' + std::to_string(isBanned) + '\n'); 
            }

            size = newBuffer.size() + 1;
            if(sendAllHeader(create_socket, size) == -1) // header with length of message
                break;
                
            if(sendAll(create_socket, newBuffer, size) == -1) // actual message  
                break;          

            if(isQuit != 0) // check if quit
                break;
            
            int len = 0;

            if(recvAllHeader(create_socket, len) == -1) // header with length of message
                break;

            //len = ntohs(len); //important
            char newBuf[len]; // buffer for message, size of message

            if((size = recvAll(create_socket, newBuf, len)) == -1) // actual message received
                break;
            else
            {
                newBuf[size] = '\0'; // add end of string
                if(strncmp(newBuf, "OK", 2) == 0) // check if ok
                {
                    loggedIn = true; // set logged in to true
                }
                printf("<< %s\n", newBuf); // ignore error
            }
        }
    } while (!isQuit);

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

void sendEmail(std::string& newBuffer, std::string& username) // send email
{
    int counter = 1;
    newBuffer.append(username + '\n');
    std::cout << username << '\n';
    while (true)
    {
        switch (counter)
        {
        case 1:{
            std::cout << "receiver: "; // receiver
            std::string line;
            std::getline(std::cin, line); // read line
            if(line.size() > 8) // check if line is too long
            {
                std::cout << "receiver too long, max 8 characters\n";
                counter--; // to repeat the input
                break;
            }
            newBuffer.append(line + '\n'); // append to buffer
            break;
        }
        case 2:{
            std::cout << "subject: "; // subject
            std::string line;
            std::getline(std::cin, line); // read line
            if(line.size() > 80) // check if line is too long
            {
                std::cout << "subject too long, max 80 characters\n";
                counter--; // to repeat the input
                break;
            }
            newBuffer.append(line + '\n'); // append to buffer
            break;
        }
        case 3:
            std::cout << "message: "; // message
            break;
        }
        if (counter < 3) // if counter is smaller than 3, increase counter and continue
        {
            counter++;
            continue;
        }
        
        std::string line;
        std::getline(std::cin, line); // read line
        newBuffer.append(line + '\n');
        counter++; // increase counter

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
    newBuffer.append(username + '\n'); // append username
}

void readOrDel(std::string& newBuffer, std::string& username, bool usedList)
{
    newBuffer.append(username + '\n');
    std::cout << "messagenumber: "; // message number
    std::string line;
    std::getline(std::cin, line); // read line
    newBuffer.append(line + '\n' + std::to_string(usedList) + '\n'); // append line and usedList (true or false)
}

bool loginToLDAP(std::string &username, int &create_socket, bool& isBanned)
{
    // read username (bash: export ldapuser=<yourUsername>)
    ////////////////////////////////////////////////////////////////////////////
    // LDAP config
    // anonymous bind with user and pw empty
    const char *ldapUri = "ldap://ldap.technikum-wien.at:389";
    const int ldapVersion = LDAP_VERSION3;

    char ldapBindUser[256];
    char rawLdapUser[128];
    std::cout << "Username: ";
    std::getline(std::cin, username); // read line from cin to username

    if (username.size() <= 8)
        strcpy(rawLdapUser, username.c_str());
    else
        return false;
    sprintf(ldapBindUser, "uid=%s,ou=people,dc=technikum-wien,dc=at", rawLdapUser);
    printf("user set to: %s\n", ldapBindUser);

    // read password (bash: export ldappw=<yourPW>)
    char ldapBindPassword[256];
    strcpy(ldapBindPassword, getpass());

    std::string buf;
    buf.append("CHECK\n"); // append check to buffer
    int size = buf.size() + 1;
    if(sendAllHeader(create_socket, size) == -1) // send header with length of message
        return false;
    if(sendAll(create_socket, buf, size) == -1) // actual message
        return false;

    if(recvAllHeader(create_socket, size) == -1) // recv header with length of message
        return false;
    
    //size = ntohs(size); //important
    char buffer[size]; // buffer for message, size of message

    if(recvAll(create_socket, buffer, size) == -1) // actual message
        return false;
    else 
    {
        buffer[size] = '\0'; // add end of string
    }

    if(strncmp(buffer, "ERR", 6) == 0) // check if error
    {
        isBanned = true; // set isBanned to true
        return false; 
    }

    isBanned = false; // set isBanned to false if not banned
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
    bindCredentials.bv_val = (char *)ldapBindPassword;
    bindCredentials.bv_len = strlen(ldapBindPassword);
    BerValue *servercredp; // server's credentials
    rc = ldap_sasl_bind_s(
        ldapHandle,
        ldapBindUser,
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

int sendAllHeader(int& create_socket, int& size)
{
    char buffer[sizeof(size)]; // buffer for message, size of message
    int len = htons(size); // convert to network byte order
    memcpy(buffer, &len, sizeof(len)); // copy to buffer
    int total = 0; // total bytes sent
    int sizeofLen = sizeof(len); // size of length of message
    while (total <sizeofLen )
    {
        int sendBytes = send(create_socket, &buffer[total], sizeof(len) - total, 0); // send header
        if (sendBytes == -1)
        {
            perror("send error");
            return -1;
        }
        total += sendBytes; // increase total bytes sent
    }
    
    return 0;
}

int sendAll(int& create_socket, std::string& newBuffer, int& size)
{
    int total = 0; // total bytes sent
    int bytesLeft = size; // bytes left to send
    int sendBytes = 0; // bytes sent
    while( total < size )
    {
        sendBytes = send(create_socket, newBuffer.c_str() + total, bytesLeft, 0); // send message
        if (sendBytes == -1)
        {
            perror("send error");
            return -1;
        }
        total += sendBytes; // increase total bytes sent
        bytesLeft -= sendBytes; // decrease bytes left to send
    }

    size = total; // set size to total bytes sent
    return 0;
}

int receiveHandler(int byte)
{
    if (byte == -1) // check if error
    {
        perror("recv error");
        return -1;
    }
    else if (byte == 0) // check if server closed remote socket
    {
        printf("Server closed remote socket\n"); // ignore error
        return -1;
    }
    return 0;
}

int recvAllHeader(int create_socket, int &size)
{
    int sizeofHeader = sizeof(size); // size of header
    char buffer[sizeofHeader]; // buffer for message, size of message
    memset(buffer, 0, sizeof(buffer)); // clear buffer
    int total = 0; // total bytes received
    int bytesLeft = sizeofHeader; // bytes left to receive
    int recvBytes = 0; // bytes received
    while (total < sizeofHeader) 
    {
        recvBytes = recv(create_socket, &buffer[total], bytesLeft, 0); // receive header
        if (receiveHandler(recvBytes) == -1)
        {
            return -1;
        }

        total += recvBytes; // increase total bytes received
        bytesLeft -= recvBytes; // decrease bytes left to receive
    }
    buffer[total] = '\0'; // add end of string
    memcpy(&size, buffer, sizeofHeader); // copy to size
    return 0;
}

int recvAll(int create_socket, char* message, int size)
{
    int total = 0; // total bytes received
    int bytesLeft = size; // bytes left to receive
    int recvBytes = 0; // bytes received

    while (total < size)
    {
        recvBytes = recv(create_socket, &message[total], bytesLeft, 0); // receive message
        if (receiveHandler(recvBytes) == -1)
        {
            return -1;
        }

        total += recvBytes; // increase total bytes received
        bytesLeft -= recvBytes; // decrease bytes left to receive
    }

    size = total; // set size to total bytes received
    return size;
}