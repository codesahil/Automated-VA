#/bin/bash
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
    echo "[*] Full Port TCP Scan."
    echo "[**]If the scan runs very slow edit the script and add -T4 switch"
    #nmap -sSV -p 1-65535 $host -oA result/tcp/$host
    PORTS=$(grep open "result/tcp/$host.nmap" 2>/dev/null | cut -d'/' -f1 | perl -pe 's|\n|,|g' | sed 's/,$//g')
    if [ -n "${PORTS}" ]; then
        nmap -A -Pn -sT -p ${PORTS} $host -oA result/tcp/aggresive/$host
        grep 'tcp.*open' result/tcp/aggresive/$host.nmap
	fi

	PORTS=$(grep 'open.*netbios' "result/tcp/agressive/$host.nmap" 2>/dev/null | cut -d'/' -f1 | perl -pe 's|\n|,|g' | sed 's/,$//g')
  
	if [ -n "${PORTS}" ]; then
        mkdir -p result/tcp/smb
  
        enum4linux -a $host > result/tcp/smb/enum_host.txt
  
        echo "######################## OS Discovery" > result/tcp/smb/smb_info_$host.txt
        nmap -Pn -p ${PORTS} --script=smb-os-discovery $host >> $result/tcp/smb/smb_info_${HOST}.txt
        echo "######################## Security Mode" >> result/tcp/smb//smb_info_${HOST}.txt
        nmap -Pn -p ${PORTS} --script=smb-security-mode $host >> result/tcp/smb/smb_info_$host.txt
        echo "######################## System Info" >> result/tcp/smb/smb_info_${HOST}.txt
        nmap -Pn -p ${PORTS} --script=smb-system-info $host >> result/tcp/smb/smb_info_$host.txt
        echo "######################## Domains" >> result/tcp/smb/smb_info_${HOST}.txt
        nmap -Pn -p ${PORTS} --script=smb-enum-domains $host >> result/tcp/smb/smb_info_$host.txt
        echo "######################## Shares" >> result/tcp/smb/smb_info_${HOST}.txt
        nmap -Pn -p ${PORTS} --script=smb-enum-shares $host >> result/tcp/smb/smb_info_$host.txt
        echo "######################## Users" >> result/tcp/smb/smb_info_${HOST}.txt
        nmap -Pn -p ${PORTS} --script=smb-enum-users $host >> result/tcp/smb/smb_info_$host.txt
        echo "######################## Groups" >> result/tcp/smb/smb_info_${HOST}.txt
        nmap -Pn -p ${PORTS} --script=smb-enum-groups $host >> result/tcp/smb/smb_info_$host.txt
        echo "######################## SMB ls" >> result/tcp/smb/smb_info_${HOST}.txt
        nmap -Pn -p ${PORTS} --script=smb-ls $host >> result/tcp/smb/smb_info_$host.txt
        echo "######################## SMB Enum " >> result/tcp/smb/smb_info_${HOST}.txt
        nmap -Pn -p ${PORTS} --script=smb-mbenum $host >> result/tcp/smb/smb_info_$host.txt
        echo "######################## SMB Vulns " >> result/tcp/smb/smb_info_${HOST}.txt
        nmap -Pn -p ${PORTS} --script=smb-vuln* $host >> result/tcp/smb/smb_info_$host.txt
        echo "######################## Samba Vulns " >> result/tcp/smb/smb_info_${HOST}.txt
        nmap -Pn -p ${PORTS} --script=samba-vuln* $host >> result/tcp/smb/smb_info_$host.txt
	fi

    nmap --top-ports 100 $host -oA result/tcp/$host #for fast testing purpose
    echo "[*] Full Port UDP Scan"
    echo "[**]If the scan runs very slow edit the script and add -T4 switch"
    #nmap -sUV -p 49,53,67,68,69,88,113,118,123,135,137,138,139,143,156,161,162,194,213,220,264,389,444,500,514,520,530,563,1194,1293,1434,1512,1645,1646,1812,3306,3389,5060,5061,5432 $host -oA result/udp/$host
    #nmap --top-ports 100 $host -oA result/tcp/$host #for fast testing purpose
done < $1
