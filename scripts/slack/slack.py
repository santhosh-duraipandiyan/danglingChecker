from array import array
from datetime import datetime;
import requests;
import json;

def readFile(path):
    data = []
    file = open(path);
    for line in file:
        data.append(line)
    file.close()
    return data

def slackHandle(data, slackHandleData):
    for line in data:
            
        slackHandleData.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": line
            }
        })

def slack(slackHandleData, company, data):
    SLACK_HOOK_URL = "###"
    date = str(datetime.today().strftime('%Y-%m-%d'))
    if data:
        output = {
                "blocks": []
            }
        output['blocks'].append({
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "Dangling summary for "+company
            }
        })
        output['blocks'].append({
            "type": "context",
            "elements": [
                {
                    "text": "* Date: "+date+"*  |  * Total dangling: "+str(len(data))+"*",
                    "type": "mrkdwn"
                }
            ]
        })
        output['blocks'].append({
            "type": "divider"
        })
        for line in slackHandleData:
            
            output['blocks'].append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": line
                }
            })

        try:
            req = requests.post(SLACK_HOOK_URL, data=json.dumps(output))
        except: 
            print('Something went wrong!')
    else:
        try:
            output = {
                "text": "No Dangling domains Found for "+company 
            }
            req = requests.post(SLACK_HOOK_URL, data=json.dumps(output))
            print(req.status_code)
        except:
            print('Something went wrong!')

def push(data):
    baseDirectory = "/home/ubuntu/un_test/assets/"
    companies = ["sec_test", "dev_sec_test","codechef","graphy","relevel","prepladder","spayee"]
    files = ["dangling_dns_A_records.txt","dangling_dns_cname.txt","dangling_dns_alises.txt","dangling_dns_subdomain_takeover.txt"]
    for company in companies:
        slackHandleData = []
        for file in files:
            data = readFile(baseDirectory+company+"/"+file)
            slackHandle(data, slackHandleData)
        slack(slackHandleData,company)
