import requests

import datetime
import json
import os

class IanaRDAPDatabase():
    IANABASE = f'https://data.iana.org/rdap/dns.json'
    CACHE = f'.ianardapcache.json' 
    MAXAGE = 24 # Hours

    def __init__(self, maxage=MAXAGE, cachefile=CACHE):
        """ Retrieves the IANA databse, if not already cached. maxage is in hours. """
        cache_valid = False
        if os.path.exists(cachefile) and datetime.datetime.fromtimestamp(os.path.getmtime(cachefile)) >= (datetime.datetime.utcnow() - datetime.timedelta(hours = maxage)):
            with open(cachefile, "rb") as cache:
                content = cache.read()
            
            cache_valid = True
        else:
            response = requests.get(self.IANABASE)
            if response.status_code != 200:
                raise Exception(f'Invalid HTTPS return code when trying to get {self.IANABASE}: {response.status_code}')
            
            content = response.content
        
        database = json.loads(content)
        self.description = database["description"]
        self.publication = database["publication"]
        self.version = database["version"]
        self.services = {}
        
        for service in database["services"]:
            for tld in service[0]:
                for server in service[1]:
                    self.services[tld] = server
        
        if not cache_valid:
            with open(cachefile, "wb") as cache:
                cache.write(content)
        
    def find(self, domain):
        """ Get the RDAP server for a given domain name. None if there is none."""
        labels = domain.split(".")
        tld = labels[len(labels)-1]

        if tld in self.services:
            return self.services[tld]
        else:
            return None

if __name__ == "__main__":
    rdap = IanaRDAPDatabase(maxage=1)

    print(f'Database "{rdap.description}", version {rdap.version} published on {rdap.publication}, {len(rdap.services)} services')

    domain = f'google.fr'
    server = rdap.find(domain)
    print(server)

    response = requests.get(f'{server}domain/{domain}')
    print(response.status_code)

    json_object = json.loads(response.content)
    json_formatted_str = json.dumps(json_object, indent=2)
    print(json_formatted_str)