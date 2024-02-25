import requests
import itertools as it
import gzip
import bisect
import shutil
import zipfile
from netaddr import spanning_cidr

from concurrent.futures import ThreadPoolExecutor
from csv import reader
from math import log2
from ipaddress import ip_address
from typing import Any, List
from os import path
from datetime import datetime

from rdap import IanaRDAPDatabase

MAX_DAYS = 0

def iprange_to_cidr(start, end) -> str:
    return str(spanning_cidr([start, end]))

def download_file(url) -> None:
    response = requests.get(url, stream=True)
    print(f'Downloading {url} - {response.status_code}')
    if "content-disposition" in response.headers:
        content_disposition = response.headers["content-disposition"]
        filename = content_disposition.split("filename=")[1]
    else:
        filename = url.split("/")[-1]

    with open(filename, mode="wb") as file:
        for chunk in response.iter_content(chunk_size=10 * 1024):
            file.write(chunk)
        print(f'Downloaded file {filename}')

def urls_dataset() -> List[str]:
    urls = [
        #ARIN 
        f'https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest',
        #RIPIE NCC
        f'https://ftp.ripe.net/ripe/stats/delegated-ripencc-extended-latest',
        #APNIC' 
        f'https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest',
        #AFRINI
        f'https://ftp.apnic.net/stats/afrinic/delegated-afrinic-extended-latest',
        #LACNIC
        f'https://ftp.apnic.net/stats/lacnic/delegated-lacnic-extended-latest',
        #ASN
        f'https://iptoasn.com/data/ip2asn-v4.tsv.gz',
        #City - Maxmind GeoLite2
        f'https://cdn.jsdelivr.net/npm/@ip-location-db/geolite2-city/geolite2-city-ipv4.csv.gz',
        #City - https://ipapi.is/geolocation.html
        f'https://ipapi.is/data/geolocationDatabaseIPv4.csv.zip'
    ]

    return urls

def size_to_cidr_mask(c):
    """ c = 2^(32-m), m being the CIDR mask """
    return int(-log2(c) + 32)

def parse_rir_file(filename):
    with open(filename) as f:
        rows = reader(f, delimiter='|')
        for r in rows:
            try:
                rir, country_code, ip_version, ip, mask, *_ = r
            except ValueError:
                continue
            if ip == '*':
                continue
            if ip_version == 'ipv4':
                length = int(mask)
                addr = ip_address(ip)
                yield {
                    'ip_low': addr,
                    'ip_high': addr + length - 1,
                    'rir': rir,
                    'country': country_code,
                    'range': ip+'/'+str(size_to_cidr_mask(length)),
                }

def parse_asn_file(filename):
    with open(filename) as f:
        rows = reader(f, delimiter='\t')
        for r in rows:
            try:
                ip_low, ip_high, number, country_code, org = r
            except ValueError:
                continue

            yield {
                'ip_low': ip_address(ip_low),
                'ip_high': ip_address(ip_high),
                'number': number,
                'country': country_code,
                'oganisation': org,
                'range': iprange_to_cidr(ip_low, ip_high),
            }

def parse_city_file(filename):
    with open(filename) as f:
        rows = reader(f, delimiter=',')
        for r in rows:
            try:
                ip_version, ip_low, ip_high, continent, country_code, country, state, city, zip_code, timezone, latitude, longitude, accuracy = r
            except ValueError:
                continue
            if ip_version == '4':
                tokens = ip_low.split('.')
                ip_low = f'{int(tokens[0])}.{int(tokens[1])}.{int(tokens[2])}.{int(tokens[3])}'
                tokens = ip_high.split('.')
                ip_high = f'{int(tokens[0])}.{int(tokens[1])}.{int(tokens[2])}.{int(tokens[3])}'
                yield {
                    'ip_low': ip_address(ip_low),
                    'ip_high': ip_address(ip_high),
                    'continent': continent,
                    'country_code': country_code,
                    'country': country,
                    'state': state,
                    'city': city,
                    'zip_code': zip_code,
                    'timezone': timezone,
                    'latitude': latitude,
                    'longitude': longitude,
                    'accuracy': accuracy,
                    'range': iprange_to_cidr(ip_low, ip_high),
                }

def merge_asn_dataset() -> List:
    data = list(it.chain(
        parse_asn_file('ip2asn-v4.tsv')
    ))

    return data

def merge_city_dataset() -> List:
    data = list(it.chain(
        parse_city_file('geolocationDatabaseIPv4.csv')
    ))

    return data

def merge_rir_dataset() -> List:
    data = list(it.chain(
        parse_rir_file('delegated-ripencc-extended-latest'),
        parse_rir_file('delegated-arin-extended-latest'),
        parse_rir_file('delegated-apnic-extended-latest'),
        parse_rir_file('delegated-afrinic-extended-latest'),
        parse_rir_file('delegated-lacnic-extended-latest')
    ))

    return data

def too_old_dataset() -> bool:
    try:
        m_time = datetime.fromtimestamp(path.getmtime('delegated-ripencc-extended-latest'))
    except FileNotFoundError:
        return True

    today = datetime.now()
    delta = today - m_time

    if delta.days > MAX_DAYS:
        return True
    else:
        False

def download_dataset() -> None:
    with ThreadPoolExecutor() as excecutor:
        excecutor.map(download_file, urls_dataset())
    
    with gzip.open('ip2asn-v4.tsv.gz', 'rb') as file_in:
        with open('ip2asn-v4.tsv', 'wb') as file_out:
            shutil.copyfileobj(file_in, file_out)

    with zipfile.ZipFile('geolocationDatabaseIPv4.csv.zip', 'r') as zip_ref:
        zip_ref.extractall('.')
    

def lookup(ip: str, data: str) -> str:
    data.sort(key=lambda r: r['ip_low'])
    keys = [r['ip_low'] for r in data]

    ip = ip_address(ip)
    if not ip.is_global or ip.is_multicast: # Check bogon
        return None
    i = bisect.bisect_right(keys, ip)
    entry = data[i-1]
    #assert(entry['ip_low'] <= ip <= entry['ip_high'])

    return entry

if __name__ == "__main__":
    print('IP Reputation v0.1')

    rdap = IanaRDAPDatabase(maxage=1)

    print(f'Database "{rdap.description}", version {rdap.version} published on {rdap.publication}, {len(rdap.services)} services')

    domain = f'google.fr'
    server = rdap.find(domain)
    print(server)

    response = requests.get(f'{server}domain/{domain}')
    print(response.status_code)
    print(response.content)

    """
    if too_old_dataset():
        download_dataset()

    asn_data = merge_asn_dataset()
    city_data = merge_city_dataset()


    print(lookup('82.121.189.210', data=asn_data))
    print(lookup('82.121.189.210', data=city_data))
    """