
# CF-Failover  
Using the Cloudflare API to change DNS records to maximize uptime

## Usage/Examples  
`api-failover -c config.json`

### Configure
The configure file is a JSON array file with each domain group in the following pattern:
```json
  {
    "primary": ["ip1", "ip2", "ip3..."],
    "backup": ["backip1", "backip2..."],
    "method": "tcp", // "tcp", "ping" are the methods currently supported
    "record": "your.domain.com",
    "param": "80",  // not used for ping, port number for tcp
    "token": "cloudflare token",
    "zoneid": "cloudflare zone id",
    "interval": 10  // health check interval
  }
```
 
### Pinging on Linux  
In some cases, an error may be thrown when the program attempts to ping the specified hosts. The simplest way to alleviate this is to run the program as root or in Docker.  
For more information, check the Linux section in the  [pro-bing](https://github.com/prometheus-community/pro-bing#linux) README

### Precompiled releases   
Precompiled releases are build automatically by Github Actions and can be downloaded from the [releases](https://github.com/slashtechno/api-failover/releases) page  
After downloading for the appropriate platform, the program can be run directly  

### Compiling locally  
In order to compile locally, Go must be installed  
```bash
git clone https://github.com/snowie2000/cf-failover/
cd api-failover
go install
```

