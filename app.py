import os
from flask import Flask, render_template, request, redirect, url_for, jsonify
from pymongo import MongoClient
import whois
from ipwhois import IPWhois
import socket
import requests
from bs4 import BeautifulSoup
import dns.resolver
from datetime import datetime
from flask import Response
from xml.etree.ElementTree import Element, SubElement, tostring
from xml.dom import minidom
from dotenv import load_dotenv

app = Flask(__name__)


# MongoDB Connection
load_dotenv()
mongo_client = MongoClient(os.getenv("MONGODB_URI"))
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
        meta_info = {}
        headers = dict(response.headers)

        if response.status_code == 200:
            response.encoding = "utf-8"
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


@app.route('/', methods=['GET'])
def index():
    user_ip = request.headers.get('X-Forwarded-For', request.remote_addr)  # Get the client IP address
    return render_template('index.html', user_ip=user_ip)


@app.route('/get', methods=['POST'])
def get():
    domain_name = request.form['domain_name'].lower().strip()
    return redirect(url_for('get_whois', domain_name=domain_name))


@app.route('/domain/<domain_name>')
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
                           dns_records=domain_data.get('dns_records', {}),
                           screenshot_data=domain_data.get('screenshot', {}))

# Add this route to your existing Flask app
@app.route('/sitemap.xml', methods=['GET'])
def sitemap():
    try:
        # Fetch all domain names from MongoDB
        domains = whois_collection.find({}, {'domain_name': 1, 'timestamp': 1, '_id': 0})

        # Create the root XML element
        urlset = Element('urlset')
        urlset.set('xmlns', 'http://www.sitemaps.org/schemas/sitemap/0.9')

        # Get the current domain (e.g., http://example.com)
        base_url = request.host_url.rstrip('/')  # Removes trailing slash

        # Add each domain's WHOIS page to the sitemap
        for domain in domains:
            url = SubElement(urlset, 'url')
            loc = SubElement(url, 'loc')
            loc.text = f"{base_url}/domain/{domain['domain_name']}"
            lastmod = SubElement(url, 'lastmod')
            lastmod.text = domain['timestamp'].strftime('%Y-%m-%d')  # Use the stored timestamp

        # Convert the XML tree to a string
        xml_str = tostring(urlset, encoding='utf-8', method='xml')
        # Pretty-print the XML
        xml_pretty_str = minidom.parseString(xml_str).toprettyxml(indent="  ")

        # Return the XML response with the correct content type
        return Response(xml_pretty_str, mimetype='application/xml')

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/ads.txt', methods=['GET'])
def ads_txt():
    return Response('google.com, pub-2325580012296666, DIRECT, f08c47fec0942fa0', mimetype='text/plain')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)