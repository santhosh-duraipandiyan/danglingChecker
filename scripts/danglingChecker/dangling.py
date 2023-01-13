from distutils.command.config import config
import subprocess
import requests
from netaddr import *
import json
from database import sql


def getConfig():
    f = open('config/danglingConfig.json')
    data = json.load(f)
    f.close()
    return(data)


def lookup(domain):
    proc = subprocess.run(['dig', domain, '+short'],
                          stdout=subprocess.PIPE, universal_newlines=True)
    dangling_dns = 0
    ip_addr = []
    if proc.stdout:
        data = proc.stdout.strip('\n').split('\n')
        for ip in data:
            ip_addr.append(ip)
    else:
        dangling_dns = 1

    return dangling_dns, ip_addr


def check_dns_Aliases(dangling_dns_alises, dns_ip_aliases, dns_aliase_record, all_ec2_ips, all_api_domains, subdomain_list, whitelist_dangling_records, whitelisted_dangling_alias_records, s3_buckets, cloudfront_list):

    for record in dns_aliase_record:
        dom = record['name']
        domain = record['dnsName']
        status, output = lookup(domain)
        if not status:
            for ip in output:
                if IPAddress(str(ip)).is_private() is False:
                    if ip in all_ec2_ips or domain in all_api_domains:
                        dns_ip_aliases.append(
                            {"dom": dom, "domain": domain, "ip": str(ip)})
                        subdomain_list.append(dom)
                    else:
                        if dom in whitelist_dangling_records:
                            whitelisted_dangling_alias_records.append(
                                {"dom": dom, "domain": domain, "ip": str(ip)})
                        elif domain.startswith('s3-website-') and (dom in s3_buckets):
                            pass
                        elif domain.endswith('.cloudfront.net') and (domain in cloudfront_list):
                            pass
                        else:
                            duplicateCheck = {
                                "dom": dom, "domain": domain, "output": str(output)}
                            if duplicateCheck not in dangling_dns_alises:
                                dangling_dns_alises.append(
                                    {"dom": dom, "domain": domain, "output": str(output)})
        else:
            duplicateCheck = {"dom": dom, "domain": domain}
            if duplicateCheck not in dangling_dns_alises:
                dangling_dns_alises.append({"dom": dom, "domain": domain})


def cloudflare_check_dns_A_records(cloudflare_dangling_dns_A_records, cloudflare_dns_ip_A_records, cloudflare_dns_a_records, all_ec2_ips, all_gcp_ips, cloudflare_subdomain_list, cloudflare_dangling_stream_A_records):

    for record in cloudflare_dns_a_records:
        dom = record['name']
        ip_addr = record['value']

        if ip_addr in all_ec2_ips:
            cloudflare_dns_ip_A_records.append({"domain": dom, "ip": ip_addr})
            cloudflare_subdomain_list.append(dom)
        elif ip_addr in all_gcp_ips:
            cloudflare_dns_ip_A_records.append({"domain": dom, "ip": ip_addr})
            cloudflare_subdomain_list.append(dom)
        else:
            if dom.startswith("stream-"):
                cloudflare_dangling_stream_A_records.append(
                    {"domain": dom, "ip": ip_addr})
            else:
                cloudflare_dangling_dns_A_records.append(
                    {"domain": dom, "ip": ip_addr})


def check_dns_A_records(dangling_dns_A_records, dns_ip_A_records, dns_a_record, all_ec2_ips,  subdomain_list, whitelist_dangling_records, whitelisted_dangling_A_records, dangling_stream_A_records):

    for record in dns_a_record:
        dom = record['name']
        ip_addr = record['resourceRecords']
        if ip_addr in all_ec2_ips:
            dns_ip_A_records.append({"domain": dom, "ip": str(ip_addr)})
            subdomain_list.append(dom)
        elif dom in whitelist_dangling_records:
            whitelisted_dangling_A_records.append(
                {"domain": dom, "ip": str(ip_addr)})
        else:
            if dom.startswith("stream-"):
                dangling_stream_A_records.append(
                    {"domain": dom, "ip": str(ip_addr)})
            else:
                dangling_dns_A_records.append(
                    {"domain": dom, "ip": str(ip_addr)})


def cloudflare_check_dns_CNAME(cloudflare_dangling_dns_cname, cloudflare_dns_ip_cname, cloudflare_dns_cname_records, all_ec2_ips, cloudflare_subdomain_list):

    for record in cloudflare_dns_cname_records:
        dom = record['name']
        domain = record['content']
        status, output = lookup(domain)
        if not status:
            cloudflare_dns_ip_cname.append(
                {"dom": dom, "domain": domain, "output": str(output)})
            cloudflare_subdomain_list.append(dom)
        else:
            cloudflare_dangling_dns_cname.append(
                {"dom": dom, "domain": domain})


def check_dns_CNAME(dangling_dns_cname, dns_ip_cname, dns_cname_record, all_ec2_ips, whitelist, dns_reverse_domains, subdomain_list):

    for record in dns_cname_record:
        dom = record['name']
        domain = record['resourceRecords']
        status, output = lookup(domain)
        if not status:
            dns_ip_cname.append(
                {"dom": dom, "domain": domain, "output": str(output)})
            dns_reverse_domains.append(domain)
            subdomain_list.append(dom)
        else:
            WhitelistCheck = whitelistMatch(domain, whitelist)
            duplicateCheck = {"dom": dom, "domain": domain}
            if WhitelistCheck == 'true' and duplicateCheck not in dangling_dns_cname:
                print("[*] Dangling DNS Entry found: "+dom+" - "+domain)
                dangling_dns_cname.append({"dom": dom, "domain": domain})


def whitelistMatch(domain, whitelist):
    checkPass = 'true'
    for check in whitelist:
        if domain.endswith(check):
            checkPass = 'false'
            return(checkPass)
    return(checkPass)


def cleanup_domains(subdomain_list):
    new_subdomain_list = []
    for domain in subdomain_list:
        if 'stream' in domain or '.internal' in domain or 'uncd.me' in domain:
            pass
        else:
            new_subdomain_list.append(domain)

    return new_subdomain_list


def subdomain_takeover_check(dns_cname, subdomain_list, edge_list):
    output = []

    for record in dns_cname:
        for subdomain in subdomain_list:
            if subdomain in record['content']:
                try:
                    url = "https://"+record['name']
                    resonse = requests.request(
                        method='GET', url=url, verify=False)
                    if resonse.status_code == 404:
                        output.append(
                            {"domain": record['name'], "value": record['content']})
                except requests.ConnectionError:
                    print("[-]Unable to connect. to : "+record['name'])
                    continue

    for record in dns_cname:
        for edge in edge_list:
            if edge in record['content']:
                try:
                    url = "https://"+record['name']
                    resonse = requests.request(
                        method='GET', url=url, verify=False)
                    if resonse.status_code == 404:
                        output.append(
                            {"domain": record['name'], "value": record['value']})
                except requests.ConnectionError:
                    print("[-]Unable to connect. to : "+record['name'])
                    continue

    return(output)


def getEc2Ips(data, company):

    # aws
    all_ec2_ips = data['aws'][company]['all']
    # cloudflare
    if data['cloudFlare'][company]['all_Ips']:
        all_ec2_ips = all_ec2_ips + data['cloudFlare'][company]['all_Ips']
    # cloudFlare
    if data['digitalOcean'][company]['all_Ips']:
        all_ec2_ips = all_ec2_ips + data['digitalOcean'][company]['all_Ips']

    return(all_ec2_ips)


def checkDangling(data, companies):

    config = getConfig()
    output = {}

    whitelist = config['whitelist']
    subdomain_list = config['subdomainList']
    edge_list = config['edgeList']
    cloudflare_subdomain_list = []
    cloudflare_dangling_dns_cname = []
    cloudflare_dangling_dns_A_records = []
    cloudflare_dangling_stream_A_records = []
    cloudflare_dns_ip_A_records = []
    cloudflare_dns_ip_cname = []
    cloudflare_dns_a_records = data['cloudFlare'][company]['A_Records']
    cloudflare_dns_cname_records = data['cloudFlare'][company]['CNAME_Records']

    all_ec2_ips = getEc2Ips(data, 'prepladder')

    all_gcp_ips = data['gcp']['all_Ips']

    cloudflare_check_dns_A_records(cloudflare_dangling_dns_A_records, cloudflare_dns_ip_A_records, cloudflare_dns_a_records,
                                   all_ec2_ips, all_gcp_ips, cloudflare_subdomain_list, cloudflare_dangling_stream_A_records)
    cloudflare_check_dns_CNAME(cloudflare_dangling_dns_cname, cloudflare_dns_ip_cname,
                               cloudflare_dns_cname_records, all_ec2_ips, cloudflare_subdomain_list)

    cloudflare = {}
    cloudflare['cloudflare_dangling_dns_A_records'] = cloudflare_dangling_dns_A_records
    cloudflare['cloudflare_dangling_dns_cname'] = cloudflare_dangling_dns_cname
    cloudflare['cloudflare_subdomain_list'] = cloudflare_subdomain_list.sort()
    cloudflare['cloudflare_dangling_stream_A_records'] = cloudflare_dangling_stream_A_records
    cloudflare['cloudflare_dns_ip_A_records'] = cloudflare_dns_ip_A_records
    cloudflare['cloudflare_dns_ip_cname'] = cloudflare_dns_ip_cname

    output['cloudflare'] = cloudflare

    for company in companies:
        all_ec2_ips = []
        all_api_domains = []
        dangling_dns_alises = []
        dangling_dns_cname = []
        dangling_dns_A_records = []
        dangling_stream_A_records = []
        dns_ip_A_records = []
        dns_ip_aliases = []
        dns_ip_cname = []
        dns_reverse_domains = []
        s3_buckets = []
        cloudfront_list = []

        dns_a_record = data['aws'][company]['dns_entries_a']
        dns_cname_record = data['aws'][company]['dns_entries_cname']
        dns_aliase_record = data['aws'][company]['dns_entries_aliase']

        whitelisted_dangling_A_records = []
        whitelisted_dangling_alias_records = []
        s3_buckets = data['aws'][company]['s3_buckets']
        cloudfront_list = data['aws'][company]['cloudfront']

        all_api_domains = data['aws'][company]['aws_api_gateways']

        if company == "graphy":
            all_ec2_ips = getEc2Ips(data, 'spayee')
        else:
            all_ec2_ips = getEc2Ips(data, company)

        check_dns_Aliases(dangling_dns_alises, dns_ip_aliases, dns_aliase_record, all_ec2_ips, all_api_domains,
                          subdomain_list, whitelist, whitelisted_dangling_alias_records, s3_buckets, cloudfront_list)
        check_dns_A_records(dangling_dns_A_records, dns_ip_A_records, dns_a_record, all_ec2_ips,
                            subdomain_list, whitelist, whitelisted_dangling_A_records, dangling_stream_A_records)
        check_dns_CNAME(dangling_dns_cname, dns_ip_cname, dns_cname_record,
                        all_ec2_ips, whitelist, dns_reverse_domains, subdomain_list)

        new_subdomain_list = cleanup_domains(subdomain_list)
        uniq_subdomain_list = set(new_subdomain_list)

        subdomain_takeover = subdomain_takeover_check(
            cloudflare_dns_cname_records, subdomain_list, edge_list)

        temp = {}
        temp['dangling_dns_alises'] = dangling_dns_alises
        temp['dns_ip_cname'] = dns_ip_cname
        temp['dns_reverse_domains'] = dns_reverse_domains
        temp['dangling_dns_cname'] = dangling_dns_cname
        temp['dns_ip_aliases'] = dns_ip_aliases
        temp['dangling_dns_A_records'] = dangling_dns_A_records
        temp['dangling_stream_A_records'] = dangling_stream_A_records
        temp['dns_ip_A_records'] = dns_ip_A_records
        temp['uniq_subdomain_list'] = uniq_subdomain_list
        temp['subdomain_takeover'] = subdomain_takeover

        output[company] = temp

    return(output)
