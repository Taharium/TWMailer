#include "headers/serverheaders.h"

std::mutex m;

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
int sendAllHeader(int& current_socket, int& size);
std::string readFile(const std::string& pathToFileToRead);
std::string listFiles(const std::string& receive);
void *clientCommunication(int current_socket, std::string spoolDirectory, std::string ipstring);
void signalHandler(int sig);
//void StartCommunicationThread(std::string spoolDir);
void writeBanToFile(std::time_t& bannedTime, std::string& ipstring);
int receiveHandler(int byte);
void writeIntoBanMap( std::map<std::string, std::time_t>& banMap);
bool handleLogin(std::string& ipString, std::map<std::string, std::time_t>& banMap, int& counterBanned, std::vector<std::string>& parts);
bool searchIfBanned(std::string& ipstring, std::map<std::string, std::time_t>& banMap);
void blacklisting(std::string& ipstring, std::map<std::string, std::time_t>& banMap);
int sendAll(int current_socket, std::string& message, int& size);
void eraseFromFile(std::time_t& bannedTime);
int recvAll(int current_socket, char* message, int size);
int recvAllHeader(int& current_socket, int& size);

///////////////////////////////////////////////////////////////////////////////

int main(int argc, char *argv[])
{
    int reuseValue = 1;
    struct sockaddr_in address; 

    ////////////////////////////////////////////////////////////////////////////
    // SIGNAL HANDLER
    // SIGINT (Interrup: ctrl+c)
    if (signal(SIGINT, signalHandler) == SIG_ERR)
    {
        perror("signal can not be registered");
        return EXIT_FAILURE;
    }

    // CREATE A SOCKET
    if ((create_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("Socket error"); // errno set by socket()
        return EXIT_FAILURE;
    }

    ////////////////////////////////////////////////////////////////////////////
    // SET SOCKET OPTIONS
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
    
    std::vector<std::thread> threads;

    while (!abortRequested)
    {
        socklen_t addrlen;
        struct sockaddr_in cliaddress;
        // ignore errors here... because only information message
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
        char clientIP[INET_ADDRSTRLEN];
        // convert IP to string safer version than inet_ntoa
        inet_ntop(AF_INET, &(cliaddress.sin_addr), clientIP, INET_ADDRSTRLEN); 
        std::string clientIPString(clientIP); //convert char* to string --> ipstring
        printf("Client connected from %s:%d...\n", clientIP, ntohs(cliaddress.sin_port)); 
        std::string spoolDir = argv[2]; //spool directory

        //start thread for client communication --> more clients can communicate at the same time
        threads.emplace_back(std::thread(clientCommunication, new_socket, spoolDir, clientIPString)); 
        new_socket = -1;
    }

    // lock the mutex to get the id of the current thread and join it
    m.lock();
    auto id = std::this_thread::get_id();
    m.unlock();
        
    for (auto& thread : threads)
    {
        if(thread.get_id() == id)
            thread.join();
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

    printf("Server shutdown\n"); // ignore error

    return EXIT_SUCCESS;
}

void *clientCommunication(int current_socket, std::string spoolDirectory, std::string ipstring)
{
    //banMap for blacklisting with ip and time
    std::map<std::string, std::time_t> banMap;
    //read ban.txt and write into banMap
    writeIntoBanMap(banMap);
    
    int size;
    int counterBanned = 0;

    ////////////////////////////////////////////////////////////////////////////
    // SEND welcome message
    std::string buffer = "Welcome to myserver!\r\nPlease enter your commands...\r\n";
    size = buffer.size() + 1;
    //the header with the length of the actual string that is being send to the client
    if(sendAllHeader(current_socket, size) == -1)
        return NULL;

    // the actual string that is being send to the client
    if(sendAll(current_socket, buffer, size) == -1)
        return NULL;
    do
    {
        /////////////////////////////////////////////////////////////////////////
        // RECEIVE
        int len = 0;

        // receive header with length of actual string
        if((size = recvAllHeader(current_socket, len)) == -1)
            break;

        len = ntohs(len); //convert from network byte order to host byte order
        // allocate buffer for actual string with length of header
        char newBuffer[len];
        
        // receive actual string and check if there is an error
        if((size = recvAll(current_socket, newBuffer, len)) == -1)
            break;

        // remove ugly debug message, because of the sent newline of client
        if (newBuffer[size - 2] == '\r' && newBuffer[size - 1] == '\n')
        {
            size -= 2;
        }
        else if (newBuffer[size - 1] == '\n')
        {
            --size;
        }
        // message to send back to client OK or ERR
        std::string message = "OK";
        // add null terminator to string
        newBuffer[size] = '\0';

        // Read strings separated by '\n' from the input stream
        std::vector<std::string> parts;
        parts.reserve(3);
        std::istringstream stream(newBuffer); // Create an input string stream from the buffer
        std::string line;
        int counter = 0;
        while (std::getline(stream, line, '\n'))
        {
            // append the extracted string
            parts.emplace_back(line);
            counter++;
        }

        if(strncmp(newBuffer, "CHECK", 5) == 0) // checks if ip is banned
        {
            m.lock();
            if(searchIfBanned(ipstring, banMap)) // searches in banMap if ip is banned, if yes --> true --> send ERR
                message = "ERR";
            m.unlock();
        }
        else if(strncmp(newBuffer, "LOGIN", 5) == 0) // if check is ok --> login
        {
            if(std::stoi(parts[3]) == 1)    // parts[3] is a bool that says if the user is banned or not
            {
                message = "ERR";
            }
            else if(counter == 4)   //TODO check if messge is ok
            {
                // handles login, if login fails lase is returned
                if(!handleLogin(ipstring, banMap, counterBanned, parts)) 
                    message = "ERR";
            }
            else
            {
                message = "ERR";
            }
        }
        else if(strncmp(newBuffer, "SEND", 4) == 0) // send
        {
            if(counter >= 5)
            {
                // directorypath using receivername (parts[2] is recievername)
                std::string receiverDir = spoolDirectory + "/" + parts[2]; 
                if(!fs::exists(spoolDirectory)) //if spool does not exists --> create
                {
                    m.lock();
                    fs::create_directories(spoolDirectory);
                    m.unlock();
                }
                    
                
                if(!fs::exists(receiverDir)) //if username-Dir does not exit --> create
                {
                    createDir(parts, receiverDir); // create directory and write into file (only happens once)
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
                if (fs::is_directory(directoryPath))    //check if directory exists
                {
                    message = listFiles(directoryPath); //list files in directory
                    //readList = true;
                } 
                else    //if directory does not exists --> 0 messages
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
            if(std::stoi(parts[3]) == 0) // TODO: change to message = "ERR" and check in the next if on message
            {
                counter = 0;
            }

            if(counter == 4)
            {
                //path of file to delete using username (parts[1]) and messagenumber(parts[2])
                std::string pathToFileToDelete = spoolDirectory + "/" + parts[1] + "/" + parts[2] + ".txt"; 
                if (fs::exists(pathToFileToDelete)) 
                {
                    deleteFile(pathToFileToDelete); //delete file
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
            if(std::stoi(parts[3]) == 0)    // parts[3] is a bool that says if the user used list before read or delete
            {
                counter = 0;
            }

            if(counter == 4)
            {
                //path of file to read using username and messagenumber
                std::string pathToFileToRead = spoolDirectory + "/" + parts[1] + "/" + parts[2] + ".txt"; 
                if (fs::exists(pathToFileToRead)) 
                {
                    message = readFile(pathToFileToRead);   //read file
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
        else  // if there is a typo in command return err
        {
            message = "ERR";
        }

        if(strncmp(newBuffer, "QUIT", 4) == 0) //quit
        {
            break;
        }

        if (newBuffer[0] != '\0') {
            printf("Message received: %s\n", newBuffer);
        } else {
            printf("Received an empty message.\n");
        } // ignore error

        int size = message.size() + 1;

        if(sendAllHeader(current_socket, size) == -1) // header with length of message
            break;
        
        if(sendAll(current_socket, message, size) == -1) //actual string
            break;

    } while (!abortRequested);
    // closes/frees the descriptor if not already
    if (current_socket != -1)
    {
        if (shutdown(current_socket, SHUT_RDWR) == -1)
        {
            perror("shutdown new_socket");
        }
        if (close(current_socket) == -1)
        {
            perror("close new_socket");
        }
        current_socket = -1;
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
        m.lock();
        fs::create_directories(receiverDir); //create spool dir
        m.unlock();
        std::string filePath = receiverDir + "/index.txt";  //create index file
        m.lock();
        updateIndex(filePath, 0);   //update index with 0 or if it does not exists create it with 0
        m.unlock();             
        writeIntoFile(parts, receiverDir); //write into file
    } 
    catch (const std::exception& e) 
    {
        std::cerr << "Failed to create directory: " << e.what() << std::endl;
    }
}

void writeIntoFile(std::vector<std::string>& parts, const std::string& receiverDir)
{
    m.lock();
    std::string filePathIndex = receiverDir + "/index.txt"; //path of index file
    std::ifstream inputFile(filePathIndex); //open index file to read
    int index = 0;
    if (inputFile.is_open())  //open index and take the number 
    {
        std::string line;
        std::getline(inputFile, line);
        index = std::stoi(line); //convert string to int
        // Close the file after reading
        inputFile.close();
    }
    index++; //increment index
    m.unlock();

    m.lock();
    std::string msgFile = std::to_string(index) + ".txt"; //create filename with index number and .txt
    std::string filePath = receiverDir + "/" + msgFile; //path of file
    std::ofstream outputFile(filePath); //open file to write
    if (outputFile.is_open()) 
    {
        // Write content to the file
        for(size_t i = 1; i < parts.size(); i++) //write into file
        {
            if(i == parts.size()-1) //if last line --> no \n
                outputFile << parts[i];
            else
                outputFile << parts[i] << '\n'; 
        }
        outputFile.close();
    }
    updateIndex(filePathIndex, index); //update index after creating a file
    m.unlock();
}

void updateIndex(const std::string& filePath, int index)
{
    std::ofstream outputFile(filePath); //open index to write or create
    if (outputFile.is_open())
    {
        // Write index to the file
        outputFile << index << '\n'; //write index into file
        outputFile.close();
    }
}

std::string listFiles(const std::string& directoryPath) //TODO list files in order
{
    std::string message = "";
    int filenameFound = 0;
    std::set<std::string> sortfile;
    for (const auto& entry : fs::directory_iterator(directoryPath))  //iterate through directory 
    {
        if (fs::is_regular_file(entry) && entry.path().filename().string() != "index.txt")  //check if it is a file and not index.txt
        {
            m.lock();
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
                        sortfile.insert('<' + entry.path().filename().stem().string() + ' ' + line + ">\n");
                        break;
                    }
                }
            }
            // Close the file after reading
            inputFile.close();
            m.unlock();
        }
    }
    message.append(std::to_string(filenameFound) + " messages\n"); //append number of messages
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
        m.lock();
        fs::remove(pathToFileToDelete); 
        m.unlock();
    } 
    catch (const std::exception& e)  //if file does not exists
    {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

std::string readFile(const std::string& pathToFileToRead)
{
    std::string message = "OK\n";
    m.lock();
    std::ifstream inputFile(pathToFileToRead); // open file to read
    if (inputFile.is_open()) 
    {   
        std::string line;
        // read line by line
        while (std::getline(inputFile, line)) 
        {
            message.append(line + '\n');    //append line in the file to message
        }

        // close file and delete last \n
        inputFile.close();
        
        if(message.back() == '\n')  //delete last \n
            message.pop_back();
    }
    else
    {
        message = "ERR";
    }
    m.unlock();

    return message;
}

int sendAllHeader(int& current_socket, int& size)
{
    char buffer[sizeof(size)]; //header buffer with size of int (4)
    int len = ntohs(size); //convert from host byte order to network byte order
    memcpy(buffer, &len, sizeof(len)); //copy len into buffer
    int total = 0; //how many bytes we've sent
    int sizeofLen = sizeof(len);  
    while (total < sizeofLen )
    {
        //send header with length of actual string to client, in a loop to send all bytes 
        int sendBytes = send(current_socket, &buffer[total], sizeof(len) - total, 0); 
        if (sendBytes == -1)
        {
            perror("send error");
            return -1;
        }
        total += sendBytes; //increase total by sendBytes
    }
    return 0;
}

void writeBanToFile(std::time_t& bannedTime, std::string& ipstring) 
{
    std::string banDir = "banDir";
    if(!fs::exists(banDir)) //if bandir does not exists --> create
    {
        m.lock();
        fs::create_directories(banDir);
        m.unlock();
    }
    
    std::ofstream outputFile(banDir + "/ban.txt", std::ios::app);   //open ban.txt to write in apppend mode
    m.lock();
    if (outputFile.is_open())
    {
        outputFile << '\n' << bannedTime << ' ' << ipstring ;
        outputFile.close();
    }
    m.unlock();
}

bool searchIfBanned(std::string& ipstring, std::map<std::string, std::time_t>& banMap)
{
    std::time_t currentTime = std::time(0);
    if(banMap.find(ipstring) != banMap.end())   //if ip is in banMap
    {
        std::time_t bannedTime = banMap[ipstring]; //get banned time
        if(currentTime > bannedTime)   //if current time is bigger than banned time --> erase from banMap and ban.txt, beacuse time is over
        {
            banMap.erase(ipstring);
            eraseFromFile(bannedTime);
        }
        else   //if current time is smaller than banned time --> still banned
        {
            return true;
        }
    }
    return false;
}

void blacklisting(std::string& ipstring, std::map<std::string, std::time_t>& banMap)
{
    std::time_t bannedTime = std::time(0) + 60; //banned time is current time + 60 seconds
    banMap[ipstring] = bannedTime;
    writeBanToFile(bannedTime, ipstring);

}

int receiveHandler(int byte) //check if there is an error
{
    if (byte == -1) // check if header has an error
    {
        if (abortRequested) // check if abort is requested
            perror("recv error after aborted");
        else
            perror("recv error");
        return -1;
    }
    if (byte == 0) // check if client closed remote socket
    {
        printf("Client closed remote socket\n"); // ignore error
        return -1;
    }
    return 0;
}

void writeIntoBanMap(std::map<std::string, std::time_t>& banMap)
{
    std::string banDir = "banDir"; 
    m.lock();
    if(!fs::exists(banDir)) //if banDir does not exists --> create
    {
        fs::create_directories(banDir);
        return;
    } 
    m.unlock();

    m.lock();
    std::ifstream inputFile(banDir + "/ban.txt");
    if (inputFile.is_open())  //open index and take the number 
    {
        std::string line;
        std::getline(inputFile, line);
        while (std::getline(inputFile, line))
        {
            std::istringstream stream(line); // Create an input string stream from the buffer
            std::string ip, time;
            stream >> time >> ip; //read time and ip from ban.txt and write into banMap
            std::time_t timeT = std::stol(time); //convert string to int
            banMap[ip] = timeT;
        }
        // Close the file after reading
        inputFile.close();
    }
    m.unlock();
}

bool handleLogin(std::string& ipString, std::map<std::string, std::time_t>& banMap, int& counterBanned, std::vector<std::string>& parts)
{
    bool isLoggedin = false; 
    
    if(std::stoi(parts[2]) == 1)    // parts[2] is a bool that says if the user successfully logged in or not
        isLoggedin = true;      
    else
    {
        m.lock();
        counterBanned++;   //counter for blacklisting
        m.unlock();
    }
    
    if(counterBanned == 3) //if counter is 3 --> blacklisting
    {
        blacklisting(ipString, banMap);  //blacklisting
        counterBanned = 0;
    }
    return isLoggedin;
}

int sendAll(int current_socket, std::string& message, int& size)
{
    int total = 0;      // how many bytes we've sent
    int bytesLeft = size;  // how many we have left to send
    int sendBytes = 0; // how many we've sent in last send() call
    while( total < size )
    {
        sendBytes = send(current_socket, message.c_str() + total, bytesLeft, 0); //send message to client in a loop to send all bytes
        if (sendBytes == -1)
        {
            return -1;
        }
        total += sendBytes; //increase total by sendBytes
        bytesLeft -= sendBytes; //decrease bytesLeft by sendBytes
    }

    size = total; // asign number actually sent here
    return 0;
}

void eraseFromFile(std::time_t& bannedTime)
{
    std::ifstream inFile("banDir/ban.txt");

    if (!inFile)    //if file does not exists
    {
        std::cerr << "Error opening file: ban.txt" << std::endl;
        return;
    }

    std::map<std::string, std::time_t> banMap;
    std::string line;

    std::getline(inFile, line); //skip first line
    while (std::getline(inFile, line)) 
    {
        std::istringstream stream(line);
        std::string ip, time; 
        stream >> time >> ip; //read time and ip from ban.txt and write into banMap
        banMap[ip] = std::stol(time); //convert string to int
    }

    inFile.close();

    for (auto it = banMap.begin(); it != banMap.end();) //iterate through banMap
    {
        auto& time = it->second;
        
        if (time == bannedTime)
        {
            it = banMap.erase(it);  // erase returns the iterator to the next element
        }
        else
        {
            ++it;  // move to the next element
        }
    }

    std::ofstream outputFile("banDir/ban.txt");
    if (outputFile.is_open())
    {
        for(auto& i : banMap) //write banMap into ban.txt
        {
            auto& ip = i.first; 
            auto& time = i.second;
            outputFile << '\n' << time << ' ' << ip ;
        }
        outputFile.close();
    }
}

int recvAll(int current_socket, char* message, int size)
{
    int total = 0; // how many bytes we've received
    int bytesLeft = size; // how many we have left to receive
    int recvBytes = 0; // how many we've received in last recv() call
    while (total < size)
    {
        recvBytes = recv(current_socket, &message[total], bytesLeft, 0);  //receive message from client in a loop to receive all bytes
        if (receiveHandler(recvBytes) == -1)
        {
            return -1;
        }

        total += recvBytes; //increase total by recvBytes
        bytesLeft -= recvBytes; //decrease bytesLeft by recvBytes
    }

    size = total; // asign number actually received here
    return size;
}

int recvAllHeader(int& current_socket, int& size)
{
    int sizeofHeader = sizeof(size); //size of header
    char buffer[sizeofHeader]; //header buffer with size of int (4)
    memset(buffer, 0, sizeof(buffer)); //set buffer to 0
    int total = 0; // how many bytes we've received
    int bytesLeft = sizeofHeader; // how many we have left to receive
    int recvBytes = 0; // how many we've received in last recv() call
    while (total < sizeofHeader)
    {
        recvBytes = recv(current_socket, &buffer[total], bytesLeft, 0); //receive header from client in a loop to receive all bytes
        if (receiveHandler(recvBytes) == -1)
        {
            return -1;
        }

        total += recvBytes; //increase total by recvBytes
        bytesLeft -= recvBytes; //decrease bytesLeft by recvBytes
    }
    buffer[total] = '\0'; //add null terminator to buffer
    memcpy(&size, buffer, sizeofHeader); //copy buffer into size
    return 0;
}
