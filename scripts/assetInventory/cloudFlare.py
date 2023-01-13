from datetime import date
from distutils.command.config import config
import requests
import json

def getall(dns_recs,allDomains, allIps):
    
    for dns in dns_recs['result']:
        if dns['type'] == "A":
            if dns['content'] not in allIps:
                allIps.append(dns['content'])

    for dns in dns_recs['result']:
        if dns['type'] == "A" or dns['type'] == "CNAME":
            if dns['name'] not in allDomains:
                allDomains.append(dns['name'])

def A_Record(dns_recs,aRecord):

    for dns in dns_recs['result']:
        if dns['type'] == "A":
            aRecord.append({"name":dns['name'],"content":dns['content']})


def CNAME_Record(dns_recs,cnameRecord):

    for dns in dns_recs['result']:
        if dns['type'] == "CNAME":
            cnameRecord.append({"name":dns['name'],"content":dns['content']})

def getConfig(companies):
    f = open('config/assetConfig.json')
    data = json.load(f)
    f.close()
    output = {}
    for company in companies:
        if data["config"][company]["check"]["cloudFlare"]:
            output[company] = data["config"][company]["cloudFlare"]
    return(output)

def getData(companies):

    config = getConfig()
    output = {}

    for company in companies:

        aRecord = []
        cnameRecord = []
        allIps = []
        allDomains = []

        zones_resp = requests.get(config[company]['url']+"zones", headers = {"Authorization": config[company]["apiKey"]})
        zones_data = zones_resp.json()

        #List all the zones
        zones = {}
        for zone in zones_data['result']:
         zones[zone['name']] = zone['id']

        #Fetch DNS records from each zone
        for zone in zones:
            dns_resp = requests.get(config[company]['url']+"zones/"+zones[zone]+"/dns_records", headers = {"Authorization": config[company]["apiKey"]})
            dns_recs = dns_resp.json()

        A_Record(dns_recs,aRecord)
        CNAME_Record(dns_recs,cnameRecord)
        getall(dns_recs,allIps,allDomains)

        temp = {}

        temp['all_Ips'] = allIps
        temp['all_Domains'] = allDomains
        temp['A_Records'] = aRecord
        temp['CNAME_Records'] = cnameRecord

        output[company] = temp

    return(output)