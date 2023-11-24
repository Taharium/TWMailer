#include "headers/clientheaders.h"

///////////////////////////////////////////////////////////////////////////////
const char* getpass();
int getch();
void sendEmail(std::string& newBuffer, std::string& username);
void listemail(std::string& newBuffer, std::string& username);
void readOrDel(std::string& newBuffer, std::string& username, bool usedList);
int sendingHeader(int& create_socket, int& size);
bool loginToLDAP(std::string& username, int& create_socket, bool& isBanned);
int sendAll(int& create_socket, std::string& newBuffer, int& size);
int receiveHandler(int &byte);

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
            inet_aton("127.0.0.1", &address.sin_addr);
            port = (in_port_t)std::stol(argv[1]);
        }
        else if(argc == 3)
        {
            inet_aton(argv[1], &address.sin_addr);
            port = (in_port_t)std::stol(argv[2]);
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
    int byte = recv(create_socket, &len, sizeof(len), 0); // header for initial message
    
    if(receiveHandler(byte) == -1)
        return EXIT_FAILURE;

    len = ntohs(len); //important
    char buffer[len];
    
    size = recv(create_socket, buffer, len, 0); // actual initial message
    if(receiveHandler(size) == -1)
        return EXIT_FAILURE;
    else 
    {
        buffer[size] = '\0';
        printf("%s", buffer);
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
                c = std::toupper(c);

            isQuit = strncmp(buffer, "QUIT\n", sizeof(buffer)) == 0;
            
            std::string newBuffer(buffer); // convert char* to string           
            
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
                    readOrDel(newBuffer, username, usedList);
            }

            if(newBuffer == "LOGIN\n" && !loggedIn)
            {
                bool login = loginToLDAP(username, create_socket, isBanned);
                newBuffer.append(username + '\n' + std::to_string(login) + '\n' + std::to_string(isBanned) + '\n');
            }
                

            size = newBuffer.size();
            if(sendingHeader(create_socket, size) == -1) // header with length of message
                break;
                
            if(sendAll(create_socket, newBuffer, size) == -1) // actual message  
                break;          

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
                break;
            
            int len = 0, byte = 0;
            byte = recv(create_socket, &len, sizeof(len), MSG_WAITFORONE); // receive header with length of message

            if(receiveHandler(byte) == -1)
                break;

            len = ntohs(len); //important
            char newBuf[len];

            size = recv(create_socket, newBuf, len, 0); // actual message
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
        if (counter < 3)
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
    newBuffer.append(line + '\n' + std::to_string(usedList) + '\n');
}

int sendingHeader(int& create_socket, int& size)
{
    int len = htons(size);
    if(send(create_socket, &len, sizeof(len), 0) == -1)
    {
        perror("send failed");
        return -1;
    }
    return 0;
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
    std::cout << "\nUsername: ";
    std::getline(std::cin, username);
    //std::cout << '\n' <<username.c_str() <<'\n';
    if (username.size() <= 8)
        strcpy(rawLdapUser, username.c_str());
    else
        return false;
    sprintf(ldapBindUser, "uid=%s,ou=people,dc=technikum-wien,dc=at", rawLdapUser);
    printf("user set to: %s\n", ldapBindUser);

    // read password (bash: export ldappw=<yourPW>)
    char ldapBindPassword[256];
    strcpy(ldapBindPassword, getpass());
/*     std::string pw(ldapBindPassword);
    std::string ldapString(ldapBindUser);
    newBuffer.append(ldapString + '\n' + pw + '\n' + username + '\n'); */
    std::string buf;
    buf.append("CHECK\n" + username + '\n');
    int size = buf.size();
    sendingHeader(create_socket, size);
    sendAll(create_socket, buf, size);

    int byte = recv(create_socket, &size, sizeof(size), 0); // header for initial message
    if(receiveHandler(byte) == -1)
        return EXIT_FAILURE;
    
    size = ntohs(size); //important
    char buffer[size];

    byte = recv(create_socket, buffer, size, 0); // actual initial message
    if(receiveHandler(byte) == -1)
        return EXIT_FAILURE;
    else 
    {
        buffer[size] = '\0';
    }

    if(strncmp(buffer, "BANNED", 6) == 0)
    {
        isBanned = true;
        return false;
    }

    isBanned = false;
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
