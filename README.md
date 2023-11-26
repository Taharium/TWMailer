# TWMailer

please use make first before using the program

to run the program use the following command

## Server

```
./bin/twmailer-server <server port> <spool-directory>
```

if you don't have spool directory, enter a name and it will create a directory with that name

## Client

```
./bin/twmailer-client <ip address> <server port>
```
ip address is e.g. 127.0.0.1

## Commands

these command can be used at first
```
login
quit
```


once you login you can use the following commands

```
send
list
read
del
quit
```

### login

```
username:
password:
```

### send

```
receiver:
subject:
message:
```

### list

is a command that will list all the emails in the spool directory

### read

```
messagenumber:
```

### del

```
messagenumber:
```
