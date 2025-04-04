# systemsTest1
youtube video=    https://youtu.be/39kPsX2pBBE

This tool is a multi-threaded TCP port scanner written in Go. It allows users to scan a specified range of ports on one or multiple target hosts, identifying open ports and retrieving service banners if available. The scanner supports command-line flags for customization, including specifying target hosts, port ranges, concurrency level, timeout duration, and JSON-formatted output.

how to run:

Targeted scan"scan port with a certain range"/"also multyple traget scan"
    go run main.go -target=scanme.nmap.org,example.com -start-port=20 -end-port=81 -workers=100 -timeout=3 -json   

Single Target scan
    go run main.go -target=scanme.nmap.org

Default scan
    go run main.go 

Sample output

Scanning port 1/61 for target scanme.nmap.org
Scanning port 2/61 for target scanme.nmap.org
...
Scan Summary:
Targets: scanme.nmap.org
Total ports scanned: 61
Open ports: 2
Scan completed in: 1.532s
Target scanme.nmap.org: Port 22 open
Target scanme.nmap.org: Port 80 open, but no response received.

