## Basic Instructions [Illustrated with example]

#### Add-Metallb-IPPool
 python3 controller.py --add-ip-pool 172.17.130.1-172.17.130.17
 
#### Deploy Resources
  python3 controller.py --num-ftd 2 --name-prefix release-v1 --response /home/sabari/responses-virtual-ftd.zip
  
#### List All Resources
  python3 controller.py --list all
  
#### List Resources for a name-prefix
  python3 controller.py --list-for-name-prefix release-v1 
 
#### Delete all resources
  python3 controller.py --delete all

#### Delete Resources for a given name-prefix
  python3 controller.py --delete-for-name-prefix release-v2
 
#### Delete Resources for a given name-prefix
  python3 controller.py --delete-for-name-prefix release-v2
 
#### Delete Resources given pod's external ip
  python3 controller.py --delete-with-ips 172.17.130.1

#### Delete resources where pod's external ip is within the given range
  python3 controller.py --delete-on-range 172.17.130.1-172.17.130.3

#### Delete ip-pool specifically
  python3 controller.py --delete-ip-pool 172.17.130.1-172.17.130.17



## Advanced Usage
```
$ python3 controller.py --help
usage: controller.py [-h] [--num-ftd NUM_FTD] [--add-ip-pool ADD_IP_POOL] [--name-prefix NAME_PREFIX] [--response-zip RESPONSE_ZIP] [--fmc-ip FMC_IP] [--fmc-user FMC_USER] [--fmc-pass FMC_PASS] [--list LIST]
                     [--list-for-name-prefix LIST_FOR_NAME_PREFIX] [--delete DELETE] [--delete-for-name-prefix DELETE_FOR_NAME_PREFIX] [--delete-ip-pool DELETE_IP_POOL] [--delete-on-range DELETE_ON_RANGE]
                     [--delete-with-ips DELETE_WITH_IPS]

Runtime arguments for the application.

options:
  -h, --help            show this help message and exit
  --num-ftd NUM_FTD     Number of FTD's to deploy
  --add-ip-pool ADD_IP_POOL
                        Add Vlan IP Pool Range. Ex: 192.168.1.200-192.168.1.206
  --name-prefix NAME_PREFIX
                        Name Prefix for the pods/service to deploy
  --response-zip RESPONSE_ZIP
                        FTD Response zip Path
  --fmc-ip FMC_IP       FMC IP
  --fmc-user FMC_USER   FMC Username
  --fmc-pass FMC_PASS   FMC Password
  --list LIST           List resources of all name-prefix. Supported options: all, pods, services, storage
  --list-for-name-prefix LIST_FOR_NAME_PREFIX
                        List all resources of given name-prefix.
  --delete DELETE       Delete pods and services. Supported options: all, pods, services, storage, ippools
  --delete-for-name-prefix DELETE_FOR_NAME_PREFIX
                        Delete all resources with the given prefix
  --delete-ip-pool DELETE_IP_POOL
                        Delete specified IP pool
  --delete-on-range DELETE_ON_RANGE
                        Delete services [and associated pods] on the specified range. Ex: 192.168.1.200-192.168.1.206
  --delete-with-ips DELETE_WITH_IPS
                        Delete services [and associated pods] running on a specified comma-separated list of IPs
```
