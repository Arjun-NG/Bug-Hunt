import os
import argparse
import subprocess

# Create output directory if it doesn't exist
output_dir = "output"
os.makedirs(output_dir, exist_ok=True)

# Define helper functions for each task
def run_command(command):
    """Helper function to execute a shell command."""
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    return process.stdout

def subdomain_enumeration(target_domain, output_file):
    """Run subdomain enumeration."""
    print(f"Running subdomain enumeration for {target_domain}...")
    subfinder_output = run_command(f"subfinder -d {target_domain} -all -recursive")
    assetfinder_output = run_command(f"assetfinder -subs-only {target_domain}")
    findomain_output = run_command(f"findomain -t {target_domain}")
    crtsh_output = run_command(f"crtsh -d {target_domain}")
    with open(output_file, "w") as f:
        f.write(subfinder_output)
        f.write(assetfinder_output)
        f.write(findomain_output)
        f.write(crtsh_output)

def alive_subdomains(input_file):
    """Filter live subdomains and categorize by status code."""
    print("Finding alive subdomains and categorizing by status code...")
    alive_output = os.path.join(output_dir, "subdomains_alive.txt")
    run_command(f"cat {input_file} | httpx -silent -ports 80,443,8080,8000,8888 -threads 200 > {alive_output}")
    run_command(f"cat {alive_output} | httpx -silent -mc 200 -o {output_dir}/subdomains_200.txt")
    run_command(f"cat {alive_output} | httpx -silent -mc 403 -o {output_dir}/subdomains_403.txt")
    run_command(f"cat {alive_output} | httpx -silent -mc 404 -o {output_dir}/subdomains_404.txt")

def crawl_urls(input_file):
    """Crawl URLs for live subdomains."""
    print("Crawling URLs...")
    allurls_output = os.path.join(output_dir, "allurls.txt")
    run_command(f"katana -u {input_file} -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -kf -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -o {allurls_output}")

def filter_vulnerabilities(input_file):
    """Filter URLs for various vulnerabilities."""
    print("Filtering URLs for different vulnerabilities...")
    xss_output = os.path.join(output_dir, "xss_output.txt")
    open_redirect_output = os.path.join(output_dir, "open_redirect_output.txt")
    lfi_output = os.path.join(output_dir, "lfi_output.txt")
    sqli_output = os.path.join(output_dir, "sqli_output.txt")
    run_command(f"cat {input_file} | gf xss | sort -u > {xss_output}")
    run_command(f"cat {input_file} | gf or | sort -u > {open_redirect_output}")
    run_command(f"cat {input_file} | gf lfi | sort -u > {lfi_output}")
    run_command(f"cat {input_file} | gf sqli | sort -u > {sqli_output}")

def extract_sensitive_info(input_file):
    """Extract sensitive information from URLs."""
    sensitive_info_output = os.path.join(output_dir, "sensitive_info.txt")
    print("Extracting sensitive information from URLs...")
    run_command(f"cat {input_file} | grep -E '\\.txt|\\.log|\\.cache|\\.secret|\\.db|\\.backup|\\.yml|\\.json|\\.gz|\\.rar|\\.zip|\\.config' > {sensitive_info_output}")

def scan_js_files(input_file):
    """Scan JavaScript files."""
    js_output = os.path.join(output_dir, "js.txt")
    print("Scanning for JavaScript files...")
    run_command(f"cat {input_file} | grep -E '\\.js$' > {js_output}")

def nuclei_scan(input_file, tags, output_file):
    """Run Nuclei scan with specified tags."""
    print(f"Running Nuclei scan on {input_file} with tags {tags}...")
    run_command(f"cat {input_file} | nuclei -tags {tags} -o {output_file}")

def subdomain_takeover(input_file):
    """Check for subdomain takeover."""
    takeover_output = os.path.join(output_dir, "takeover_results.txt")
    print("Checking for subdomain takeover...")
    run_command(f"subzy --targets {input_file} -v -o {takeover_output}")

def dir_brute_force(input_file):
    """Directory brute-forcing."""
    dirsearch_output = os.path.join(output_dir, "dirsearch_results.txt")
    print("Running directory brute-forcing...")
    with open(input_file, "r") as f:
        for line in f:
            line = line.strip()
            run_command(
                f"dirsearch -u {line} -e php,cgi,htm,html,shtm,shtml,js,txt,bak,zip,old,conf,log,pl,asp,aspx,jsp,sql,db,sqlite,mdb,tar,gz,7z,rar,json,xml,yml,yaml,ini,java,py,rb,php3,php4,php5 --random-agent --recursive -R 3 -t 20 --exclude-status=404 --follow-redirects --delay=0.1 >> {dirsearch_output}"
            )

def host_header_injection(input_file):
    """Run Host Header Injection tests."""
    print("Running Host Header Injection tests...")
    with open(input_file, "r") as f:
        for line in f:
            line = line.strip()
            run_command(f"headi -url {line}")

# Argument parsing
parser = argparse.ArgumentParser(description="Automated Security Enumeration Script")
parser.add_argument("-d", "--domain", help="Target domain")
parser.add_argument("-f", "--file", help="Input file containing list of domains")
args = parser.parse_args()

# Run tasks based on input
if args.domain:
    target_domain = args.domain
    subdomain_file = os.path.join(output_dir, "subdomain.txt")
    subdomain_enumeration(target_domain, subdomain_file)
elif args.file:
    input_file = args.file
    subdomain_file = os.path.join(output_dir, "subdomain.txt")
    with open(input_file, "r") as f:
        for domain in f:
            domain = domain.strip()
            subdomain_enumeration(domain, subdomain_file)
else:
    print("Usage: script.py -d <target_domain> or script.py -f <input_file>")
    exit(1)

# Run the rest of the tasks
alive_subdomains(subdomain_file)
crawl_urls(os.path.join(output_dir, "subdomains_alive.txt"))
filter_vulnerabilities(os.path.join(output_dir, "allurls.txt"))
extract_sensitive_info(os.path.join(output_dir, "allurls.txt"))
scan_js_files(os.path.join(output_dir, "allurls.txt"))
nuclei_scan(os.path.join(output_dir, "js.txt"), "lfi,cve", os.path.join(output_dir, "nuclei_js_scan.txt"))
nuclei_scan(os.path.join(output_dir, "subdomains_alive.txt"), "lfi,cve", os.path.join(output_dir, "nuclei_scan_results.txt"))
subdomain_takeover(os.path.join(output_dir, "subdomains_alive.txt"))
dir_brute_force(os.path.join(output_dir, "subdomains_alive.txt"))
host_header_injection(os.path.join(output_dir, "subdomains_alive.txt"))

print("All tasks complete. Results saved in the output directory.")

