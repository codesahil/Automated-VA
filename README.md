## Automated-VA
All the required tools and dependency installs automtiacally.
Its has some tools preconfigured to run with the scripts,

1.It automatically runs nse scripts specific to services for finding Vulnerabilities.
2.Run EyeWitness for taking screenshots od rdp and vnc.
3.Runs testssl for VA of SSL Related Issues.
4.Its stores the whole result in tabular html format for better analysis.


This script can take any file as argument where you can provide a list of ip.Every IP in different lines.
So lets say the file containing list of IP is stored as list.
Now execute 
#./automate.sh list

Note: Recommend using a kali machine for this script to run smoothly.

