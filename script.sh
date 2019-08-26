#/bin/bash
if [ ! -f $1 ]
then
    echo "Error: Must supply file"
    exit
fi
if [ ! -d "result" ]; then
  mkdir result
  mkdir result/tcp
  mkdir result/udp
fi
while read -r line
do
    host=`echo $line | cut -d" " -f1`
    echo "--------------------------"
    echo "[*] Full Port TCP Scan."
    echo "[**]If the scan runs very slow edit the script and add -T4 switch"
    nmap -sSV -p 1-65535 $host -oA result/tcp/$host
    #nmap --top-ports 100 $host -oA result/tcp/$host #for fast testing purpose
    echo "[*] Full Port UDP Scan"
    echo "[**]If the scan runs very slow edit the script and add -T4 switch"
    nmap -sUV -p 49,53,67,68,69,88,113,118,123,135,137,138,139,143,156,161,162,194,213,220,264,389,444,500,514,520,530,563,1194,1293,1434,1512,1645,1646,1812,3306,3389,5060,5061,5432 $host -oA result/udp/$host
    #nmap --top-ports 100 $host -oA result/tcp/$host #for fast testing purpose
done < $1
