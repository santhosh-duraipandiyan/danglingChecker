import os
import json

# file_path = '/home/ubuntu/un_automation/assets/prepladder/'


#cmd_set_acccount = "%s config set account security@prepladder-project.iam.gserviceaccount.com" % (gcloud_path)

def get_project_list():
    project_list = []

    os.popen(cmd_set_acccount)

    cmd_projects = "%s projects list --format=json" % (gcloud_path)
    projects = json.loads(os.popen(cmd_projects).read())

    # print "[*] Collecting Project list from GCP"
    for project in projects:
        project_list.append(project.get('projectId'))

    # print ("[*] Found %s projects in GCP" % (len(project_list)))
    # print project_list
    return project_list


def get_instances(project_name):
    cmd = "%s compute instances list --project=%s --format=json --quiet" % (
        gcloud_path, project_name)

    # print ("[*] Getting instances for Project: '%s'" % (project_name))
    raw_instances = os.popen(cmd).read()

    if "Enabling" not in raw_instances:
        try:
            instances = json.loads(raw_instances)
            return instances
        except:
            print("[-] Problem getting instances for Project: %s" %
                  (project_name))
            return None


def get_ips_from_instance(instance):
    if instance.get('networkInterfaces') is not None:
        for net_interface in instance.get('networkInterfaces'):
            if net_interface.get('accessConfigs') is not None:
                ip_addr = net_interface.get('accessConfigs')[0].get('natIP')
                if ip_addr is not None:
                    # print ("%s\t%s\t%s" % (ip_addr, net_interface.get('networkIP'), instance.get('name')))
                    return [ip_addr, net_interface.get('networkIP'), instance.get('name')]


def get_lb_instances(project_name):
    cmd = "%s compute forwarding-rules list --project=%s --format=json --quiet" % (
        gcloud_path, project_name)

    # print ("[*] Getting LB instances for Project: %s" % (project_name))
    raw_lb_instances = os.popen(cmd).read()

    try:
        lb_instances = json.loads(raw_lb_instances)
        return lb_instances
    except:
        print("[-] Problem getting LB instances for Project: %s" %
              (project_name))
        return None


def get_ips_from_lb_instance(lb_instance):
    if lb_instance.get('loadBalancingScheme') == "EXTERNAL":
        ip_addr = lb_instance.get('IPAddress')
        #print (type(ip_addr))
        # print (ip_addr)
        return ip_addr


def get_ips_from_project(project_name, all_ip_list, gcp_ip_list, gcp_project_ip_list, gcp_lb_ip_list, gcp_ip_mapping_list, gcp_ip_kube_cluster):
    # get ips from GCP instances
    # write project_name in file "gcloud_project_wise_ips.txt"
    gcp_project_ip_list.append('------------------------------------')
    gcp_project_ip_list.append(project_name)
    gcp_project_ip_list.append('------------------------------------')

    instances = get_instances(project_name)
    # write_instances = open(file_path+"all_ips.txt","a")
    #write_instances = open(file_path+"all_gcp.txt","w+")

    # print "[*] Getting IPs from instances"
    if instances is not None:
        for instance in instances:
            # ip_data[0] - PublicIP, ip_data[1] - privateIP, ip_data[2] - instance_name
            ip_data = get_ips_from_instance(instance)
            if ip_data is not None:
                # write ip_data[0] in "gcloud_project_wise_ips.txt"
                # write ip_data[0] in "all_ips_latest.txt"
                # write ip_data[0] in "gcloud_ips_latest.txt"
                # write ip_data[0],ip_data[1],ip_data[2]   "ip_mappings.txt"
                all_ip_list.append(ip_data[0])
                gcp_project_ip_list.append(ip_data[0])
                gcp_ip_list.append(ip_data[0])
                gcp_ip_mapping_list.append("%s\t%s\t%s" % (
                    ip_data[0], ip_data[1], ip_data[2]))
                # write_instances.write(ip_data[0]+"\n")
    # get ips from GCP LB instances
    lb_instance_ips = []  # use this per projet to avoid repetative IPs
    lb_instances = get_lb_instances(project_name)
    # print "[*] Getting IPs from LB Instances"
    if lb_instances is not None:
        for lb_instance in lb_instances:
            ip_addrs = get_ips_from_lb_instance(lb_instance)
            if ip_addrs is not None and ip_addrs not in lb_instance_ips:
                lb_instance_ips.append(ip_addrs)
                # write ip_addrs in "all_ips_latest.txt"
                # write ip_addrs in "gcloud_ips_latest.txt"
                all_ip_list.append(ip_addrs)
                gcp_lb_ip_list.append(ip_addrs)
                # write_instances.write(ip_addrs+"\n")

    # print(gcp_lb_ip_list)

    # get Ips from GCP Kubernates Clusters
    # print "[*] Getting IPs from Kubernate Clusters"
    kube_cluster_instances = get_kube_cluster_instances(project_name)
    if kube_cluster_instances is not None:
        # json_kube_cluster_instances = json.loads(kube_cluster_instances)
        for kube_cluster_instance in kube_cluster_instances:
            ip_addr = get_ips_from_kube_cluster(kube_cluster_instance)
            gcp_ip_kube_cluster.append(ip_addr)
            all_ip_list.append(ip_addr)
            # write_instances.write(ip_addrs+"\n")
    # write_instances.close()


def get_kube_cluster_instances(project_name):
    # print "[*] Getting Kubernate instances for Project: %s" % (project_name)
    cmd = "%s --project %s container clusters list --format json" % (
        gcloud_path, project_name)
    raw_kube_instances = os.popen(cmd).read()

    try:
        kube_cluster_instances = json.loads(raw_kube_instances)
        return kube_cluster_instances
    except:
        print("[-] Problem getting LB instances for Project: %s" %
              (project_name))
        return None


def get_ips_from_kube_cluster(kube_instance):
    if kube_instance.get('endpoint') is not None:
        ip_addr = kube_instance.get('endpoint')
        # print ip_addr
        return ip_addr


def get_dc_ips(all_ip_list, dc_ip_list):
    # static IPs, update this when get new list, mostly from @kingsly
    dc_ips = ['182.253.23.161', '182.253.23.162', '182.253.23.163', '182.253.23.164', '182.253.23.165', '182.253.23.166', '202.158.52.225', '202.158.52.226', '202.158.52.227', '202.158.52.228', '202.158.52.229', '202.158.52.230', '137.59.125.17', '137.59.125.18', '137.59.125.19', '137.59.125.20', '137.59.125.21', '137.59.125.22', '137.59.125.23',
              '137.59.125.24', '137.59.125.25', '137.59.125.26', '137.59.125.27', '137.59.125.28', '137.59.125.29', '137.59.125.30', '103.89.164.113', '103.89.164.114', '103.89.164.115', '103.89.164.116', '103.89.164.117', '103.89.164.118', '103.89.164.119', '103.89.164.120', '103.89.164.121', '103.89.164.122', '103.89.164.123', '103.58.164.124', '103.58.164.125']

    # write dc_ips in "dc_ips.txt"
    # write dc_ips in "all_ips_latest.txt"
    for ip in dc_ips:
        all_ip_list.append(ip)
        dc_ip_list.append(ip)


# def save_to_file(target_list, target_file):
 #       with open(target_file, 'w') as myfile:
  #         for line in target_list:
   #            if line:
    #               myfile.write(line)
     #              myfile.write('\n')

def get_assets_from_gcp(all_ip_list, gcp_ip_list, gcp_project_ip_list, gcp_lb_ip_list, gcp_ip_mapping_list, gcp_ip_kube_cluster):
    # Collect project list from GCP
    project_list = get_project_list()

    for project in project_list:
        get_ips_from_project(project, all_ip_list, gcp_ip_list, gcp_project_ip_list,
                             gcp_lb_ip_list, gcp_ip_mapping_list, gcp_ip_kube_cluster)


def getConfig(company):
    f = open('config/assetConfig.json')
    data = json.load(f)
    f.close()
    if data["config"][company]["check"]["gcp"]:
        return(data['config'][company]['gcp'])


def getData(company):

    config = getConfig(company)

    global gcloud_path
    gcloud_path = config['cloudPath']  # "/usr/bin/gcloud"
    global cmd_set_acccount
    cmd_set_acccount = config['account'] % (gcloud_path)

    all_ip_list = []
    gcp_ip_list = []
    gcp_project_ip_list = []
    gcp_lb_ip_list = []
    gcp_ip_mapping_list = []
    gcp_ip_kube_cluster = []
    get_assets_from_gcp(all_ip_list, gcp_ip_list, gcp_project_ip_list,
                        gcp_lb_ip_list, gcp_ip_mapping_list, gcp_ip_kube_cluster)
    uniq_all_ips = set(all_ip_list)

    output = {}
    output['all_Ips'] = uniq_all_ips

    return(output)

    # write files
    #save_to_file(uniq_all_ips, file_path+'all_ips.txt')
