# VhostFinder
This tool will identify virtual hosts by performing a similarity comparison. It will generate a baseline request to attempt to map a non-existent virtual host. From there it will iterate over the supplied domains and compare them for any differences. Any significant differences will result in a virtual host being detected.

# Install

```
go install -v github.com/wdahlenburg/VhostFinder@latest
```

# Usage

```
Usage:
  VhostFinder [flags]

Flags:
REQUIRED:
   -ip string[]        IP Address to Fuzz
   -ips string[]       File list of IPs
   -wordlist string[]  File of FQDNs or subdomain prefixes to fuzz for

OTHER OPTIONS:
   -d, -domain string[]  Optional domain(s) to append to a subdomain wordlist (Ex: example1.com)
   -H, -header string[]  Custom header(s) for each request
   -p, -path string[]    Custom path(s) to send during fuzzing (default ["/"])
   -paths string[]       File list of custom paths
   -port int             Port to use (default 443)
   -proxy string         Proxy (Ex: http://127.0.0.1:8080)
   -t, -threads int      Number of threads to use (default 10)
   -timeout int          Timeout per HTTP request (default 8)
   -tls                  Use TLS (default true)
   -v, -verbose          Verbose mode
   -verify               Verify vhost is different than public url
```

### Examples:
```bash
  VhostFinder -ip 10.8.0.1 -wordlist domains.txt
  [!] Finding vhosts!
  [!] Obtaining baseline on: https://10.8.0.1:443/
  [+] [10.8.0.1] [/] [200] [1337] host.example.com

  VhostFinder -ip 10.8.0.1 -wordlist subdomains.txt -domain host1.example.com -v
  [!] Finding vhosts!
  [!] Obtaining baseline on: https://10.8.0.1:443/
  [+] [10.8.0.1] [/] [200] [31337] admin.host1.example.com
  [-] [10.8.0.1] [/] [404] [128] test.host1.example.com

  VhostFinder -ip 10.8.0.1 -wordlist subdomains.txt -domain host1.example.com -domain anotherdomain.net -domain host2.example.com -v
  [!] Finding vhosts!
  [!] Obtaining baseline on: https://10.8.0.1:443/
  [+] [10.8.0.1] [/] [200] [31337] admin.host1.example.com
  [-] [10.8.0.1] [/] [404] [128] test.host1.example.com
  [-] [10.8.0.1] [/] [404] [128] admin.anotherdomain.net
  [+] [10.8.0.1] [/] [503] [1072] test.anotherdomain.net
  [+] [10.8.0.1] [/] [200] [3749] admin.host2.example.com
  [-] [10.8.0.1] [/] [404] [128] test.host2.example.com

  VhostFinder -ips ips.txt -wordlist domains.txt -paths paths.txt -v -H "X-Forwarded-For: 127.0.0.1" -H "User-Agent: curl/7.81.0"
  [!] Finding vhosts!
  [!] Obtaining baseline on: https://10.8.0.1:443/
  [!] Obtaining baseline on: https://10.8.0.1:443/admin/
  [!] Obtaining baseline on: https://10.8.0.2:443/
  [!] Obtaining baseline on: https://10.8.0.2:443/admin/
  [-] [10.8.0.1] [/] [400] [140] admin.example.com
  [-] [10.8.0.2] [/] [400] [141] test.example.com
  [-] [10.8.0.1] [/admin/] [200] [965] admin.example.com
  [+] [10.8.0.2] [/admin/] [400] [140] test.example.com
```

Note the output columns indicate the following:

```
[success/fail] [ip] [path] [status code] [content length] domain
```

# What is Virtual Host Fuzzing?

Essentially the following request is sent repeatedly to a particular IP:

```
GET / HTTP/1.1
Host: FUZZ
Connection: close


```

The host header is fuzzed based on user input, while all requests are sent to the same IP. 
