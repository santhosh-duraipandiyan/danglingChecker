# imports
import requests
import json


def getLoadBalancers(url, apikey, allips, loadbalancerips):
    headers = {'Content-Type': 'application/json',
               'Authorization':  "Bearer {}".format(apikey)}
    r = requests.get(url, headers=headers)
    response = json.loads(r.text)

    for droplet in response['load_balancers']:
        if droplet['ip'] not in allips:
            allips.append(droplet['ip'])
        if droplet['ip'] not in loadbalancerips:
            loadbalancerips.append(droplet['ip'])


def getDroplet(url, apikey, allips, dropletips):

    headers = {'Content-Type': 'application/json',
               'Authorization':  "Bearer {}".format(apikey)}
    r = requests.get(url, headers=headers)
    response = json.loads(r.text)

    for droplet in response['droplets']:
        ips = droplet['networks']['v4']
        for ip in ips:
            if ip['ip_address'] not in allips:
                allips.append(ip['ip_address'])
            if ip['ip_address'] not in dropletips:
                dropletips.append(ip['ip_address'])


def getConfig(company):
    f = open('config/assetConfig.json')
    data = json.load(f)
    f.close()
    if data["config"][company]["check"]["digitalOcean"]:
        return(data['config'][company]['digitalOcean']['apiKey'])
    else:
        return(False)


def getData(companies):

    output = {}
    for company in companies:
        allips = list()
        loadbalancerips = list()
        dropletips = list()

        apikey = getConfig(company)
        if apikey:
            getDroplet('https://api.digitalocean.com/v2/droplets?per_page=150',
                       apikey, allips, dropletips)
            getLoadBalancers(
                'https://api.digitalocean.com/v2/load_balancers?per_page=100', apikey, allips, loadbalancerips)

            temp = {}
            temp['all_Ips'] = allips
            temp['loadBalancers'] = loadbalancerips
            temp['droplets'] = dropletips
            output[company] = temp
        else:
            continue

    return(output)
