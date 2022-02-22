from statistics import mean

import vulners
import json

### README
### Vulnes.com API key should be set in a prof_key variable 
### We have two methods here:
###    1. get_data - read data from Vulners API and writes it to the OWASP_JSON file
###    2. count_stats - read JSON, counts stats and print to CLI
### Note! Since the get_data is a long run, we have to use a JSON file export
### You can modify queries by your needs

# TODO filename
OWASP_JSON_OUT = OWASP_JSON_IN = 'owasp.json'

# TODO api key
prof_key = ''

vulners_api = vulners.Vulners(prof_key)

ranks = [f"A{n}" for n in range(1, 11)]

search_template = 'published:[2021-01-01 TO 2021-06-30] AND ( {query} )'
search_template_2 = 'published:[2021-07-01 TO 2021-12-31] AND ( {query} )'

fields = ['id', 'type', 'cvss2', 'cvss3', 'cvelist']

queries = [
    'injection OR traversal OR lfi OR "os command" OR SSTI OR RCE OR "remote code"',  # A1 Injections
    'authentication',                                                                 # A2 Authentication
    'xss',                                                                            # A3 Cross Site Scripting
    'sensitive AND data',                                                             # A4 Sensitive Data Exposure
    'XXE OR deserialize OR deserialization OR "external entities"',                   # A5 Insecure Deserialization
    'access control',                                                                 # A6 Broken Access Control
    'logging',                                                                        # A7 Insecure Logging
    'SSRF OR "server side request forgery"',                                          # A8 SSRF
    'type:cve and (http OR web OR html)',                                             # A9 Known Vulnerabilities
    'misconfiguration OR misconfigure OR misconfig',                                  # A10 Security Misconfiguration
]


def get_data():
    result = {}

    for query, rank in zip(queries, ranks):
        # deal with the limit of 10000 output by splitting the outpunt 2 times (check manually how many pages required)
        result[rank] = vulners_api.search(search_template.format(query=query), limit=10000, fields=fields)
        result[rank] += vulners_api.search(search_template_2.format(query=query), limit=10000, fields=fields)

    with open(OWASP_JSON_OUT, 'w', encoding='utf8') as out:
        json.dump(result, out)
    print(result)


def count_stats():
    cveset = set()
    result = []
    with open(OWASP_JSON_IN, 'r') as inp:
        data = json.load(inp)
        for rank in ranks:
            if '9' in rank: continue
            cvss2 = mean([bul.get('cvss2', {}).get('cvssV2', {}).get('baseScore', 0) for bul in data[rank]])
            cvss3 = mean([bul.get('cvss3', {}).get('cvssV3', {}).get('baseScore', 0) for bul in data[rank]])
            cveset.update([cve for bul in data[rank] for cve in bul.get('cvelist', []) ])
            result.append(f"{rank} {len(data[rank])} {cvss2} {cvss3}")

    # exclude CVE listed in other classes from A9, known attacks
    a9data = [bul for bul in data['A9'] if bul['type']=='cve' and bul['id'] not in cveset]
    cvss2 = mean([bul.get('cvss2', {}).get('cvssV2', {}).get('baseScore', 0) for bul in a9data])
    cvss3 = mean([bul.get('cvss3', {}).get('cvssV3', {}).get('baseScore', 0) for bul in a9data])
    result.append(f"A9 {len(a9data)} {cvss2} {cvss3}")

    print('\n'.join(sorted(result, key=lambda x: int(x[1:3]))))
