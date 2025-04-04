# systemsTest1

This tool is a multi-threaded TCP port scanner written in Go. It allows users to scan a specified range of ports on one or multiple target hosts, identifying open ports and retrieving service banners if available. The scanner supports command-line flags for customization, including specifying target hosts, port ranges, concurrency level, timeout duration, and JSON-formatted output.

how to run:

Targeted scan"scan port with a certain range"/"also multyple traget scan"
    go run main.go -target=scanme.nmap.org,example.com -start-port=20 -end-port=81 -workers=100 -timeout=3 -json   

Single Target scan
    go run main.go -target=scanme.nmap.org

Default scan
    go run main.go 