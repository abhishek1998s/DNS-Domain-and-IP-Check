from modules.Domain import DomainLabel
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import os
import time

# ====================
DATA_PATH = 'D:/Anaconda Python/DNS_IP_Reputation-main/data/domain_list.txt'  # Path of the input domain list
RES_PATH = 'D:/Anaconda Python/DNS_IP_Reputation-main/res/domain_labels.txt'  # Path to save the domain labels

# ====================
class DomainLabel:
    def __init__(self):
        self.base_url = 'https://www.trustedsource.org/sources/index.pl'  # Use HTTPS
        self.headers = {'User-Agent': 'Mozilla/5.0'}
        self.session = requests.Session()
        retry = Retry(connect=3, backoff_factor=0.5)
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        self.domain_set = set()  # Initialize domain_set here

        # Load already labeled domains
        if os.path.exists(RES_PATH):
            with open(RES_PATH, 'r') as f_input:
                for line in f_input.readlines():
                    record = line.strip().split(',')
                    domain = record[0]
                    self.domain_set.add(domain)  # Populate domain_set

    def lookup(self, domain):
        try:
            # Set a timeout for the request
            r = self.session.get(self.base_url, headers=self.headers, params={'md5': domain}, timeout=10, verify=False)  # Disable SSL verification
            if r.status_code == 200:
                categorized = 'True'
                category = 'Unknown'
                risk = 'Unknown'
                # Parse the HTML content to extract the category and risk
                if 'malicious' in r.text:
                    category = 'Malicious'
                    risk = 'High'
                elif 'suspicious' in r.text:
                    category = 'Suspicious'
                    risk = 'Medium'
                else:
                    category = 'Benign'
                    risk = 'Low'
                return categorized, category, risk
            else:
                return 'False', None, None
        except requests.exceptions.Timeout:
            print(f"Timeout error for domain {domain}. Skipping...")
            return 'False', None, None
        except requests.exceptions.RequestException as e:
            print(f"Error while looking up domain {domain}: {e}")
            return 'False', None, None

    def save_result(self, domain, categorized, category, risk):
        with open(RES_PATH, 'a+') as f_output:
            if categorized == 'False':
                f_output.write('%s,%s\n' % (domain, categorized))
            else:
                f_output.write('%s,%s,%s,%s\n' % (domain, categorized, category, risk))

# =====================
domain_label = DomainLabel()
label_cnt = 0  # Counter of labelled domains

# Read the input domain list
with open(DATA_PATH, 'r') as f_input:
    for line in f_input.readlines():
        domain = line.strip()
        if domain in domain_label.domain_set:  # Check against the instance variable
            label_cnt += 1
            continue
        
        # Attempt to categorize the domain
        categorized, category, risk = domain_label.lookup(domain)
        print('-Record-#%d %s %s %s %s' % (label_cnt, domain, categorized, category, risk))
        
        # Save the result
        domain_label.save_result(domain, categorized, category, risk)
        
        label_cnt += 1
        time.sleep(1)  # Sleep for 1 sec to avoid hitting the API too quickly