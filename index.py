import json
from scripts.database import sql
from scripts.assetInventory import aws
from scripts.assetInventory import digitalOcean
from scripts.assetInventory import cloudFlare
from scripts.assetInventory import gcp
from scripts.danglingChecker import dangling


def getAwsData():
    data = aws.getData()
    return(data)


def getDigitalOceanData():
    data = digitalOcean.getData()
    return(data)


def getCloudFlareData():
    data = cloudFlare.getData()
    return(data)


def getGcpData():
    data = gcp.getData()
    return(data)


def getProviders():
    f = open('config/generalConfig.json')
    data = json.load(f)
    f.close()
    return(data['providers'])


def getConfig():
    f = open('config/generalConfig.json')
    data = json.load(f)
    f.close()
    return(data['companies'])


if __name__ == '__main__':

    assets = {}
    assetConfig = getProviders()
    companies = getConfig()

    if "aws" in assetConfig:
        awsData = getAwsData(companies)
        assets["aws"] = awsData

    if "digitalOcean" in assetConfig:
        digitalOceanData = getDigitalOceanData(companies)
        assets["digitalOcean"] = digitalOceanData

    if "cloudFlare" in assetConfig:
        cloudFlareData = getCloudFlareData(companies)
        assets["cloudFlare"] = cloudFlareData

    if "gcp" in assetConfig:
        gcpData = getGcpData("prepladder")
        assets["gcp"] = gcpData

    if assets:
        for company in companies:
            temp = {}
            if company in assets["aws"]:
                temp["aws"] = assets["aws"][company]
            if company in assets["digitalOcean"]:
                temp["digitalOcean"] = assets["digitalOcean"][company]
            if company in assets["cloudFlare"]:
                temp["cloudFlare"] = assets["cloudFlare"][company]
            if company in assets["gcp"]:
                temp["gcp"] = assets["gcp"][company]
            sql.insert(temp, company, "asset")

    danglingDomains = dangling.checkDangling(assets, companies)

    if danglingDomains:
        for company in companies:
            sql.insert(danglingDomains[company], company, "dangling")
