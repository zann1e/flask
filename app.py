from flask import Flask, render_template, request, redirect, url_for
import whois
from ipwhois import IPWhois
import socket
import requests
from bs4 import BeautifulSoup
from pymongo import MongoClient
import dns.resolver

# Set up Flask app
app = Flask(__name__)

# MongoDB connection (replace <username>, <password>, and <cluster_url> with your actual MongoDB credentials)
mongo_client = MongoClient("mongodb+srv://zann:zQJEMLhJLFBLGZnB@cluster0.0fmqx9y.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
db = mongo_client['whois_db']  # Database
whois_collection = db['whois_data']  # Collection

def is_ip_address(domain_name):
    try:
        socket.inet_aton(domain_name)
        return True
    except socket.error:
        return False

def get_dns_records(domain_name):
    record_types = ['A', 'MX', 'CNAME', 'TXT', 'NS']
    dns_records = {}

    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain_name, record_type)
            records = [answer.to_text() for answer in answers]
            dns_records[record_type] = records
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.Timeout):
            dns_records[record_type] = ["No record found"]

    return dns_records

def get_website_data(domain_name):
    try:
        url = f"http://{domain_name}"
        response = requests.get(url, timeout=5)
        meta_info = {
            'title': "No title",
            'meta_description': "No meta description",
            'meta_keywords': "No meta keywords"
        }
        headers = response.headers

        # If the request is successful, parse meta info
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            meta_info['title'] = soup.title.string if soup.title else "No title"

            for meta in soup.find_all('meta'):
                if 'name' in meta.attrs:
                    if meta.attrs['name'].lower() == 'description':
                        meta_info['meta_description'] = meta.attrs['content']
                    elif meta.attrs['name'].lower() == 'keywords':
                        meta_info['meta_keywords'] = meta.attrs['content']

        return meta_info, headers
    except Exception as e:
        return {
            'title': "Error fetching title",
            'meta_description': str(e),
            'meta_keywords': "Error fetching meta keywords"
        }, {"Error": str(e)}


def fetch_and_save_domain_data(domain_name):
    domain_info_dict = {}
    ip_info_dict = {}
    ip_address = None
    meta_info = {}
    http_headers = {}
    dns_records = {}

    try:
        if not is_ip_address(domain_name):
            # Get WHOIS information
            domain_info = whois.whois(domain_name)
            domain_info_dict = {k: v for k, v in domain_info.items() if v}

            # Resolve domain to IP
            ip_address = socket.gethostbyname(domain_name)

            # Get meta info and HTTP headers in a single request
            meta_info, http_headers = get_website_data(domain_name)

            # Get DNS records
            dns_records = get_dns_records(domain_name)
        else:
            ip_address = domain_name

        # Perform IP WHOIS lookup using the resolved IP address
        ipwhois = IPWhois(ip_address)
        ip_info_dict = ipwhois.lookup_rdap()

        # Combine all data into a dictionary
        domain_data = {
            'domain_name': domain_name,
            'domain_info': domain_info_dict,
            'ip_address': ip_address,
            'ip_info': ip_info_dict,
            'meta_info': meta_info,
            'http_headers': http_headers,
            'dns_records': dns_records
        }

        # Store data in MongoDB
        whois_collection.update_one(
            {'domain_name': domain_name},  # Query to check if domain exists
            {'$set': domain_data},         # Update or insert new data
            upsert=True                    # Insert if not exists
        )

        return domain_data

    except Exception as e:
        return {'error': str(e)}



@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        domain_name = request.form['domain_name']
        return redirect(url_for('get_whois', domain_name=domain_name))
    return render_template('index.html')

@app.route('/whois/<domain_name>', methods=['GET'])
def get_whois(domain_name):
    # Check if data is already in MongoDB
    domain_data = whois_collection.find_one({'domain_name': domain_name})

    if domain_data:
        return render_template('whois.html', domain_name=domain_name,
                               domain_info=domain_data['domain_info'],
                               ip_address=domain_data['ip_address'],
                               ip_info=domain_data['ip_info'],
                               meta_info=domain_data['meta_info'],
                               http_headers=domain_data['http_headers'],
                               dns_records=domain_data['dns_records'])

    # If not in database, fetch and save it
    domain_data = fetch_and_save_domain_data(domain_name)

    if 'error' in domain_data:
        return render_template('whois.html', domain_name=domain_name, error=domain_data['error'])

    return render_template('whois.html', domain_name=domain_name,
                           domain_info=domain_data['domain_info'],
                           ip_address=domain_data['ip_address'],
                           ip_info=domain_data['ip_info'],
                           meta_info=domain_data['meta_info'],
                           http_headers=domain_data['http_headers'],
                           dns_records=domain_data['dns_records'])

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
