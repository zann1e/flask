import os
from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_caching import Cache
from pymongo import MongoClient
import whois
from ipwhois import IPWhois
import socket
import requests
from bs4 import BeautifulSoup
import dns.resolver
from datetime import datetime

# Flask and Cache Configuration
config = {
    "DEBUG": True,
    "CACHE_TYPE": "SimpleCache",
    "CACHE_DEFAULT_TIMEOUT": 300
}

app = Flask(__name__)
app.config.from_mapping(config)
cache = Cache(app)

# MongoDB Connection
mongo_client = MongoClient(os.getenv("MONGODB_URI", "mongodb://localhost:27017/"))
db = mongo_client['whois_db']
whois_collection = db['whois_data']


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
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers, dns.resolver.Timeout):
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
        headers = dict(response.headers)

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


@cache.memoize(timeout=300)
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
            domain_info_dict = {k: str(v) for k, v in domain_info.items() if v}

            # Resolve domain to IP
            ip_address = socket.gethostbyname(domain_name)

            # Get meta info and HTTP headers
            meta_info, http_headers = get_website_data(domain_name)

            # Get DNS records
            dns_records = get_dns_records(domain_name)
        else:
            ip_address = domain_name

        # Perform IP WHOIS lookup
        ipwhois = IPWhois(ip_address)
        ip_info_dict = ipwhois.lookup_rdap()

        # Combine all data
        domain_data = {
            'domain_name': domain_name,
            'domain_info': domain_info_dict,
            'ip_address': ip_address,
            'ip_info': ip_info_dict,
            'meta_info': meta_info,
            'http_headers': http_headers,
            'dns_records': dns_records,
            'timestamp': datetime.utcnow()
        }

        # Store data in MongoDB
        whois_collection.update_one(
            {'domain_name': domain_name},
            {'$set': domain_data},
            upsert=True
        )

        return domain_data

    except Exception as e:
        return {'error': str(e)}


@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')


@app.route('/get', methods=['POST'])
def get():
    domain_name = request.form['domain_name'].lower().strip()
    return redirect(url_for('get_whois', domain_name=domain_name))


@app.route('/whois/<domain_name>')
@cache.cached(timeout=50)
def get_whois(domain_name):
    domain_name = domain_name.lower()

    # Check if data is in MongoDB
    domain_data = whois_collection.find_one({'domain_name': domain_name})

    if not domain_data:
        # Fetch and save if not in database
        domain_data = fetch_and_save_domain_data(domain_name)

    if 'error' in domain_data:
        return render_template('whois.html',
                               domain_name=domain_name,
                               error=domain_data['error'])

    return render_template('whois.html',
                           domain_name=domain_name,
                           domain_info=domain_data.get('domain_info', {}),
                           ip_address=domain_data.get('ip_address', 'N/A'),
                           ip_info=domain_data.get('ip_info', {}),
                           meta_info=domain_data.get('meta_info', {}),
                           http_headers=domain_data.get('http_headers', {}),
                           dns_records=domain_data.get('dns_records', {}))


@app.route('/recent_domains')
def recent_domains():
    recent = list(whois_collection.find().sort('timestamp', -1).limit(10))
    return jsonify([domain['domain_name'] for domain in recent])


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)