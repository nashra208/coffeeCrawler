# color variables to rock this tool 
import sys 
import requests
import dns.query
import dns.zone
import dns.resolver

blue = '\033[96m' 
reset = '\033[0m' 
red = '\033[91m' 
white = '\033[97m'

def banner():
    
    art = r"""
    _________         _____  _____               _________                      .__                
\_   ___ \  _____/ ____\/ ____\____   ____   \_   ___ \____________ __  _  _|  |   ___________ 
/    \  \/ /  _ \   __\\   __\/ __ \_/ __ \  /    \  \/\_  __ \__  \\ \/ \/ /  | _/ __ \_  __ \
\     \___(  <_> )  |   |  | \  ___/\  ___/  \     \____|  | \// __ \\     /|  |_\  ___/|  | \/
 \______  /\____/|__|   |__|  \___  >\___  >  \______  /|__|  (____  /\/\_/ |____/\___  >__|   
        \/                        \/     \/          \/            \/                 \/      
    

    """
    print(blue + art + reset + "\n - By Nashra \n")
            
def usage(): 
    print(red+"Usage:") 
    print(red+" script.py --path <URL> <WORDLIST> Run subdomain/path enumeration") 
    print(red+" script.py --help Show this help"+reset)
    
    
def directory_fuzzing(url, word_list): 

    try: 
        with open(word_list, 'r') as directory: 
            for dir in directory: 
                dir = dir.strip() 
                dir_attack = url + dir 
                r = requests.get(dir_attack)
                if r.status_code == 200 or r.status_code == 302:
                    print(f'{dir_attack} --------> {blue}{r.status_code}{reset}')
                else :
                    print(f'{dir_attack} --------> {red}{r.status_code}{reset}')
                    # pass 
    except FileNotFoundError: 
            print(red + f'😭 {word_list} not found' + reset)
            
def zone_transfer(domain):
    print(f'Scanning for zone file transfer...')
    # get the authorative nameserver first
    authorative_nameserver = dns.resolver.resolve(domain, "NS")
    nameservers = [str(rdata.target).rstrip('.') for rdata in authorative_nameserver]
    for ns in nameservers:
        try:
            # resolve NS hostname to IP 
            ns_ip = dns.resolver.resolve(ns, 'A')[0].to_text()
            print(f'Trying zone transfer on {ns} with IP {ns_ip}')
            #using xfr protocol for query
            xfr = dns.query.xfr(ns, domain, timeout=5)
            # zone transfer
            zone = dns.zone.from_xfr(xfr)
            if zone:
                print(f"Zone transfer succeeded for {ns}: ")
                for name, node in zone.nodes.items():
                    print(name.to_text() + "." + domain)
                    print("name:", name)              # dns.name.Name object → label (e.g. www)
                    print("name.to_text():", name.to_text())  # converts to string → "www"
                    print("node:", node)              # dns.node.Node object → holds rdatasets (records)
                    print("node.rdatasets:", node.rdatasets)  # list of record sets (A, MX, etc.)
            else:
                print(f"No zone data from {ns}")
        except dns.resolver.NXDOMAIN:
            print(red+f' Could not resolve IP for {ns}'+reset) 
        except dns.exception.FormError:
            print(red+f"[-] Zone transfer not allowed on {ns}"+reset)
        except dns.exception.DNSException as e:
            print(f"xfr connection succeeded but no zone data: {e}")
        except Exception as e:
            print(red+f"[!] AXFR is not allowed for {ns} {e}"+reset)       
            
                
def terminal():
     # expects at least one argument (the command) to be present before calling
    command = sys.argv[1]
    match command:

        case "--path":
            if len(sys.argv) < 4:
                print(red + "Error: missing arguments for --path" + reset)
                print("Usage: script.py --sub <URL> <WORDLIST>")
                return
            url = sys.argv[2]
            word_list = sys.argv[3]
            # call directory_fuzzing from within the --path case
            directory_fuzzing(url, word_list)
        case "--zone":
            if len(sys.argv) < 2:
                print(red + "Error: missing arguments for --sub" + reset)
                print("Usage: script.py --sub <URL> <WORDLIST>")
                return
            domain = sys.argv[2]
            zone_transfer(domain)
        case "--help" | "-h":
            usage()
        case _:
            print(f"Unknown command: {command}")
            usage()
            
def main():
    try:
        banner() 
        if len(sys.argv) < 3: 
            usage() 
            return 
        terminal() 
    except KeyboardInterrupt:
        print('Ok bye bye')

if __name__ == "__main__": main()



