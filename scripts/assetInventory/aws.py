import re
import boto3
from netaddr import *
import json


def get_ec2_public_ips(all_ip_list, aws_ec2_ips, aws_ec2_nat_gateway_ips, aws_ec2_elastic_ips, aws_ec2_network_ips, aws_profile, region, aws_instances):
    print("[*] Getting AWS IPs for region: {}".format(region))
    try:
        session = boto3.Session(profile_name=aws_profile)
        client = session.client('ec2', region_name=region)

        print("[*] Getting IPs from EC2 Instances")
        reservation_list = client.describe_instances()
        for reservation in reservation_list.get('Reservations'):
            for instance in reservation.get('Instances'):
                ip_addr = instance.get('PublicIpAddress')
                if ip_addr is not None:
                    instance_id = instance.get('InstanceId')
                    image_id = instance.get('ImageId')
                    aws_instances.append(
                        {"instanceId": instance_id, "imageId": image_id, "ipAddress": ip_addr})
                    all_ip_list.append(ip_addr)
                    aws_ec2_ips.append(ip_addr)

        print("[*] Getting IPs from EC2 NAT Gateways")

        nat_gateways = client.describe_nat_gateways()
        for item in nat_gateways.get('NatGateways'):
            for data in item.get('NatGatewayAddresses'):
                ip = data.get('PublicIp')
                if ip is not None:
                    aws_ec2_nat_gateway_ips.append(ip)
                    all_ip_list.append(ip)

        print("[*] Getting IPs from EC2 Elastic IPs")

        elastic_instances = client.describe_addresses()
        for item in elastic_instances.get('Addresses'):
            ip = item.get('PublicIp')
            if ip is not None:
                aws_ec2_elastic_ips.append(ip)
                all_ip_list.append(ip)

        print("[*] Getting IPs from EC2 Network Interfaces")

        network_instances = client.describe_network_interfaces()
        for item in network_instances.get('NetworkInterfaces'):
            aws_ec2_network_ips.append(item['PrivateIpAddress'])
            all_ip_list.append(item['PrivateIpAddress'])
            if item.get('Association') is not None:
                ip = item.get('Association').get('PublicIp')
                if ip is not None:
                    aws_ec2_network_ips.append(ip)
                    all_ip_list.append(ip)

    except Exception as e:
        print(e)
        print("[-] An error occured getting AWS IPs")


def get_api_gateways(company, region, api_gateways):
    session = boto3.Session(profile_name=company, region_name=region)
    client = session.client('apigateway')
    gateways = client.get_domain_names()
    for gateway in gateways['items']:
        api_gateways.append(gateway['distributionDomainName'])


def get_domains_from_route53(company, region, dns_A, dns_CNAME, dns_Alias):
    session = boto3.Session(profile_name=company, region_name=region)
    client = session.client('route53')
    zones = client.list_hosted_zones()
    paginator = client.get_paginator('list_resource_record_sets')
    print("[*] Getting DNS entries from Route53")

    for zone in zones.get('HostedZones'):
        zoneId = zone.get('Id')
        source_zone_records = paginator.paginate(HostedZoneId=zoneId)
        for record_set in source_zone_records:
            for record in record_set['ResourceRecordSets']:
                if record.get('ResourceRecords') is not None:
                    if record['Type'] == 'A':
                        if IPAddress(record.get('ResourceRecords')[0].get('Value')).is_private() is False:
                            duplicateCheck = {"name": record['Name'], "resourceRecords": record.get(
                                'ResourceRecords')[0].get('Value')}
                            if duplicateCheck not in dns_A:
                                dns_A.append({"name": record['Name'], "resourceRecords": record.get(
                                    'ResourceRecords')[0].get('Value')})
                    if record['Type'] == 'CNAME':
                        duplicateCheck = {"name": record['Name'], "resourceRecords": record.get(
                            'ResourceRecords')[0].get('Value')}
                        if duplicateCheck not in dns_CNAME:
                            dns_CNAME.append({"name": record['Name'], "resourceRecords": record.get(
                                'ResourceRecords')[0].get('Value')})

                elif record.get('AliasTarget') is not None:
                    duplicateCheck = {
                        "name": record['Name'], "dnsName": record['AliasTarget']['DNSName']}
                    if duplicateCheck not in dns_Alias:
                        dns_Alias.append(
                            {"name": record['Name'], "dnsName": record['AliasTarget']['DNSName']})


def get_s3_buckets(company, s3_buckets):
    session = boto3.Session(profile_name=company)
    s3 = session.client('s3')
    for idx, bucket_obj in enumerate(s3.list_buckets().get('Buckets')):
        bucket_name = bucket_obj.get('Name')
        s3_buckets.append(bucket_name)


def get_cloudfront_list(company, cloudfront_list):
    session = boto3.Session(profile_name=company)
    cloudfront = session.client('cloudfront')
    distributions = cloudfront.list_distributions()
    if distributions['DistributionList']['Quantity'] > 0:
        for distribution in distributions['DistributionList']['Items']:
            cloudfront_list.append(distribution['DomainName'])


def getConfig(companies):
    f = open('config/assetConfig.json')
    data = json.load(f)
    f.close()
    output = {}
    for company in companies:
        if data["config"][company]["check"]["aws"]:
            output[company] = data["config"][company]["aws"]
    return(output)


def getData(companies):

    config = getConfig()

    output = {}

    for company, regions in config.items():
        all_ip_list = []
        aws_ec2_ips = []
        aws_ec2_nat_gateway_ips = []
        aws_ec2_elastic_ips = []
        aws_ec2_network_ips = []
        aws_instances = []
        s3_buckets = []
        cloudfront_list = []
        all_ip_list2 = []
        aws_ec2_ips2 = []
        aws_ec2_nat_gateway_ips2 = []
        aws_ec2_elastic_ips2 = []
        aws_ec2_network_ips2 = []
        aws_instances2 = []
        dns_A = []
        dns_CNAME = []
        dns_Alias = []
        api_gateways = []
        get_s3_buckets(company, s3_buckets)
        get_cloudfront_list(company, cloudfront_list)
        count = 1
        for region in regions:
            if count == 1:
                get_ec2_public_ips(all_ip_list, aws_ec2_ips, aws_ec2_nat_gateway_ips,
                                   aws_ec2_elastic_ips, aws_ec2_network_ips, company, region, aws_instances)
            else:
                get_ec2_public_ips(all_ip_list2, aws_ec2_ips2, aws_ec2_nat_gateway_ips2,
                                   aws_ec2_elastic_ips2, aws_ec2_network_ips2, company, region, aws_instances2)
            count = count+1
            get_domains_from_route53(
                company, region, dns_A, dns_CNAME, dns_Alias)
            try:
                get_api_gateways(company, region, api_gateways)
            except Exception as e:
                print(e)

        new_all_ip_list = all_ip_list + all_ip_list2
        uniq_all_ips = set(new_all_ip_list)

        aws_ec2_ips.sort()
        aws_ec2_nat_gateway_ips.sort()
        aws_ec2_elastic_ips.sort()
        aws_ec2_network_ips.sort()
        aws_ec2_ips2.sort()
        aws_ec2_nat_gateway_ips2.sort()
        aws_ec2_elastic_ips2.sort()
        aws_ec2_network_ips2.sort()
        s3_buckets.sort()
        api_gateways.sort()

        temp = {}

        temp['all_ips'] = uniq_all_ips,

        temp['aws_ec2_ips_ap_south_1'] = aws_ec2_ips,
        temp['aws_ec2_nat_gateway_ips_ap_south_1'] = aws_ec2_nat_gateway_ips,
        temp['aws_ec2_elastic_ips_ap_south_1'] = aws_ec2_elastic_ips,
        temp['aws_ec2_network_ips_ap_south_1'] = aws_ec2_network_ips,
        temp['aws_instances_ap_south_1'] = aws_instances,

        temp['aws_ec2_ips_us_east_1'] = aws_ec2_ips2,
        temp['aws_ec2_nat_gateway_ips_us_east_1'] = aws_ec2_nat_gateway_ips2,
        temp['aws_ec2_elastic_ips_us_east_1'] = aws_ec2_elastic_ips2,
        temp['aws_ec2_network_ips_us_east_1'] = aws_ec2_network_ips2,
        temp['aws_instances_us_east_1'] = aws_instances2,

        temp['aws_api_gateways'] = api_gateways,

        temp['dns_entries_a'] = dns_A,
        temp['dns_entries_cname'] = dns_CNAME,
        temp['dns_entries_alias'] = dns_Alias,

        temp['s3_buckets'] = s3_buckets,

        temp['cloudfront'] = cloudfront_list,

        output[company] = temp

    return(output)
