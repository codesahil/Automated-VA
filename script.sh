#/bin/bash
echo "------------------------Running NMAP Automation Script---------------------------------"
if [ ! -f $1 ]
then
    echo "Error: Must supply file"
    exit
fi
if [ ! -d "result" ]; then
  mkdir result
  mkdir result/tcp
  mkdir result/tcp/aggresive
  mkdir result/udp
fi
while read -r line
do
    host=`echo $line | cut -d" " -f1`
    echo "--------------------------"
    echo "[*] Full Port TCP Scan [*]"
    echo "---------------------------------------------------------"
    echo "[**]If the scan runs very slow edit the script and add -T4 switch[**]"
    echo "---------------------------------------------------------"
    nmap -sSV -p 1-65535 $host -oA result/tcp/$host
    #nmap --top-ports 100 $host -oA result/tcp/$host #for fast testing purpose
    #Agressive Scan
    PORTS=$(grep open "result/tcp/$host.nmap" 2>/dev/null | cut -d'/' -f1 | perl -pe 's|\n|,|g' | sed 's/,$//g')
    if [ -n "${PORTS}" ]; then
    	echo "---------------------------------------------------------"
    	echo "[**] Running Agressive Scan on Open Ports [**]"
    	echo "---------------------------------------------------------"
        nmap -A -Pn -sT -p ${PORTS} $host -oA result/tcp/aggresive/$host
        grep 'tcp.*open' result/tcp/aggresive/$host.nmap
	fi
	#SMB
	PORTS=$(grep 'open.*netbios' "result/tcp/$host.nmap" 2>/dev/null | cut -d'/' -f1 | perl -pe 's|\n|,|g' | sed 's/,$//g')
  
	if [ -n "${PORTS}" ]; then
		echo "---------------------------------------------------------"
		echo "[***]Running SMB Scripts[***]"
		echo "---------------------------------------------------------"
        mkdir -p result/tcp/smb
  
        enum4linux -a $host > result/tcp/smb/enum_host.txt
  
        echo "######################## OS Discovery" > result/tcp/smb/smb_info_$host.txt
        nmap -Pn -p ${PORTS} --script=smb-os-discovery $host >> $result/tcp/smb/smb_info_$host.txt
        echo "######################## Security Mode" >> result/tcp/smb//smb_info_$host.txt
        nmap -Pn -p ${PORTS} --script=smb-security-mode $host >> result/tcp/smb/smb_info_$host.txt
        echo "######################## System Info" >> result/tcp/smb/smb_info_$host.txt
        nmap -Pn -p ${PORTS} --script=smb-system-info $host >> result/tcp/smb/smb_info_$host.txt
        echo "######################## Domains" >> result/tcp/smb/smb_info_$host.txt
        nmap -Pn -p ${PORTS} --script=smb-enum-domains $host >> result/tcp/smb/smb_info_$host.txt
        echo "######################## Shares" >> result/tcp/smb/smb_info_$host.txt
        nmap -Pn -p ${PORTS} --script=smb-enum-shares $host >> result/tcp/smb/smb_info_$host.txt
        echo "######################## Users" >> result/tcp/smb/smb_info_$host.txt
        nmap -Pn -p ${PORTS} --script=smb-enum-users $host >> result/tcp/smb/smb_info_$host.txt
        echo "######################## Groups" >> result/tcp/smb/smb_info_$host.txt
        nmap -Pn -p ${PORTS} --script=smb-enum-groups $host >> result/tcp/smb/smb_info_$host.txt
        echo "######################## SMB ls" >> result/tcp/smb/smb_info_$host.txt
        nmap -Pn -p ${PORTS} --script=smb-ls $host >> result/tcp/smb/smb_info_$host.txt
        echo "######################## SMB Enum " >> result/tcp/smb/smb_info_$host.txt
        nmap -Pn -p ${PORTS} --script=smb-mbenum $host >> result/tcp/smb/smb_info_$host.txt
        echo "######################## SMB Vulns " >> result/tcp/smb/smb_info_$host.txt
        nmap -Pn -p ${PORTS} --script=smb-vuln* $host >> result/tcp/smb/smb_info_$host.txt
        echo "######################## Samba Vulns " >> result/tcp/smb/smb_info_$host.txt
        nmap -Pn -p ${PORTS} --script=samba-vuln* $host >> result/tcp/smb/smb_info_$host.txt
	fi
	#HTTP
	PORTS=$(grep 'open.*http' "result/tcp/$host.nmap" 2>/dev/null | cut -d'/' -f1 | perl -pe 's|\n|,|g' | sed 's/,$//g')
  
	if [ "${PORTS}" ]; then
		echo "---------------------------------------------------------"
		echo "[***]Running HTTP Scripts[***]"
		echo "---------------------------------------------------------"
        mkdir -p result/tcp/http
        echo "######################## Cookie Flags" > result/tcp/http/http_info_$host.txt
        nmap -Pn -p ${PORTS} --script=http-cookie-flags $host >> result/tcp/http/http_info_$host.txt
        echo "######################## CORS" >> result/tcp/http/http_info_$host.txt
        nmap -Pn -p ${PORTS} --script=http-cors $host >> result/tcp/http/http_info_$host.txt
        echo "######################## Cross Domain Policy" >> result/tcp/http/http_info_$host.txt
        nmap -Pn -p ${PORTS} --script=http-cross-domain-policy $host>> result/tcp/http/http_info_$host.txt
        echo "######################## Methods" >> result/tcp/http/http_info_$host.txt
        nmap -Pn -p ${PORTS} --script=http-methods $host >> result/tcp/http/http_info_$host.txt
        echo "######################## Headers" >> result/tcp/http/http_info_$host.txt
        nmap -Pn -p ${PORTS} --script=http-headers $host >> result/tcp/http/http_info_$host.txt
        echo "######################## Vulns" >> result/tcp/http/http_info_$host.txt
        nmap -Pn -p ${PORTS} --script=http-vuln* $host >> result/tcp/http/http_info_$host.txt
        echo "######################## WAF Detect" >> result/tcp/http/http_info_$host.txt
        nmap -Pn -p ${PORTS} --script=http-waf-detect $host >> result/tcp/http/http_info_$host.txt
        echo "######################## WAF Fingerprint" >> result/tcp/http/http_info_$host.txt
        nmap -Pn -p ${PORTS} --script=http-waf-fingerprint $host >> result/tcp/http/http_info_$host.txt
	fi
	#FTP
	PORTS=$(grep 'open.*ftp' "result/tcp/$host.nmap" 2>/dev/null | cut -d'/' -f1 | perl -pe 's|\n|,|g' | sed 's/,$//g')
  
	if [ "${PORTS}" ]; then
        mkdir -p result/tcp/ftp
        echo "---------------------------------------------------------"
        echo "[***]Running FTP Scripts[***]"
        echo "---------------------------------------------------------"
        nmap -Pn -p ${PORTS} --script=ftp-vuln* $host > result/tcp/ftp/vulns_ftp_$host.txt
        nmap -Pn -p ${PORTS} --script=ftp-*-backdoor $host > result/tcp/ftp/vulns_ftp_backdoor_$host.txt
        nmap -Pn -p ${PORTS} --script=ftp-anon $host > result/tcp/ftp/ftp_anon_$host.txt
	fi

  	#SMTP
	PORTS=$(grep 'open.*smtp' "result/tcp/$host.nmap" 2>/dev/null | cut -d'/' -f1 | perl -pe 's|\n|,|g' | sed 's/,$//g')
  
	if [ "${PORTS}" ]; then
        mkdir -p result/tcp/smtp
        echo "---------------------------------------------------------"
        echo "[***]Running SMTP Scripts[***]"
        echo "---------------------------------------------------------"
        nmap -Pn -p ${PORTS} --script=smtp-vuln* $host > result/tcp/smtp/vuln_smtp_$host.txt
        nmap -Pn -p ${PORTS} --script=smtp-open-relay $host > result/tcp/smtp/smtp_open_relay_$host.txt
        nmap -Pn -p ${PORTS} --script=smtp-enum-users $host >  result/tcp/smtp/smtp_enum_users_$host.txt
	fi

	#SSL
	PORTS=$(grep 'open.*ssl' "result/tcp/$host.nmap" 2>/dev/null | cut -d'/' -f1 | perl -pe 's|\n|,|g' | sed 's/,$//g')

	if [ "${PORTS}" ]; then
        mkdir -p result/tcp/ssl
        echo "---------------------------------------------------------"
        echo "[***]Running SMTP Scripts[***]"
        echo "---------------------------------------------------------"
        nmap -Pn -p ${PORTS} --script=ssl-enum-ciphers $host > result/tcp/ssl/ssl_ciphers_$host.txt
        nmap -Pn -p ${PORTS} --script=ssl-heartbleed $host > result/tcp/ssl/ssl_heartbleed_$host.txt
        nmap -Pn -p ${PORTS} --script=ssl-ccs-injection $host >  result/tcp/ssl/ssl_css_injection_$host.txt
        if [ ! -d "testssl.sh" ]; then
        	git clone https://github.com/drwetter/testssl.sh
        	bash /testssl.sh/testssl.sh -U $host >> testssl_output
    	fi
    	bash /testssl.sh/testssl.sh -U $host >> testssl_output
	fi

	# MySQL
	PORTS=$(grep 'open.*mysql' "result/tcp/$host.nmap" 2>/dev/null | cut -d'/' -f1 | perl -pe 's|\n|,|g' | sed 's/,$//g')
  
	if [ "${PORTS}" ]; then
        mkdir -p result/tcp/mysql
        echo "---------------------------------------------------------"
        echo "[***]Running MYSQL Scripts[***]"
        echo "---------------------------------------------------------"
        nmap -Pn -p ${PORTS} --script=mysql-* $host > result/tcp/mysql/mysql_$host.txt
	fi
  
	# SSH
	PORTS=$(grep 'open.*ssh' "result/tcp/$host.nmap" 2>/dev/null | cut -d'/' -f1 | perl -pe 's|\n|,|g' | sed 's/,$//g')
  
	if [ "${PORTS}" ]; then
        mkdir -p result/tcp/ssh
        echo "---------------------------------------------------------"
        echo "[***]Running SSH Scripts[***]"
        echo "---------------------------------------------------------"
        nmap -Pn -p ${PORTS} --script=ssh* $host > result/tcp/ssh/ssh_$host.txt
	fi
  	echo "---------------------------------------------------------"
    echo "[*] Full Port UDP Scan [*]"
    echo "---------------------------------------------------------"
    echo "[**] If the scan runs very slow edit the script and add -T4 switch [**]"
    echo "---------------------------------------------------------"
    nmap -sUV -p 49,53,67,68,69,88,113,118,123,135,137,138,139,143,156,161,162,194,213,220,264,389,444,500,514,520,530,563,1194,1293,1434,1512,1645,1646,1812,3306,3389,5060,5061,5432 $host -oA result/udp/$host
    
done < $1
