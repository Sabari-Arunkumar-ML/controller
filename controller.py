import argparse
import os
import subprocess
import tempfile
import logging
import json
import shutil
import zipfile
import ipaddress
METALLB_IP_ANNOUNCE_TEMPLATE_PATH="deployment-templates/metallb_pool_ip_announce.yaml"
SVC_AND_STS_TEMPLATE_PATH="deployment-templates/service_and_sts_pod.yaml"
SEQUENCE_NUMBER_FILE="sequence.txt"
KUBECTL_BINARY_PATH="microk8s kubectl"
METALLB_NAMESPACE="metallb-system"
EXTRACTED_RESPONSE_ROOT_DIR="/tmp/pod-storage/"
EXTRACTED_RESPONSE_PATH=EXTRACTED_RESPONSE_ROOT_DIR+"sim-data/"
parser = argparse.ArgumentParser(description="Runtime arguments for the application.")

SERVICE_PORT_1="8080"
CONTAINER_PORT_1="8080"
SERVICE_PORT_2="80"
CONTAINER_PORT_2="80"
SIM_IDENTIFIER="vftd"

parser.add_argument(
    "--num-ftd",
    type=int,
    default=-1,
    help="Number of FTD's to deploy",
)

parser.add_argument(
    "--add-ip-pool",
    type=str,
    default="",
    help="Add Vlan IP Pool Range. Ex: 192.168.1.200-192.168.1.206",
)

parser.add_argument(
    "--name-prefix",
    type=str,
    default="",
    help="Name Prefix for the pods/service to deploy",
)

parser.add_argument(
    "--response-zip",
    type=str,
    default="",
    help="FTD Response zip Path",
)

parser.add_argument(
    "--fmc-ip",
    type=str,
    default="",
    help="FMC IP",
)

parser.add_argument(
    "--fmc-user",
    type=str,
    default="admin",
    help="FMC Username",
)

parser.add_argument(
    "--fmc-pass",
    type=str,
    default="",
    help="FMC Password",
)

parser.add_argument(
    "--list",
    type=str,
    default="",
    help="List resources of all name-prefix. Supported options: all, pods, services, storage",
)

parser.add_argument(
    "--list-for-name-prefix",
    type=str,
    default="",
    help="List all resources of given name-prefix.",
)

parser.add_argument(
    "--delete",
    type=str,
    default="",
    help="Delete pods and services. Supported options: all, pods, services, storage, ippools",
)

parser.add_argument(
    "--delete-for-name-prefix",
    type=str,
    default="",
    help="Delete all resources with the given prefix",
)

parser.add_argument(
    "--delete-ip-pool",
    type=str,
    default="",
    help="Delete specified IP pool",
)

parser.add_argument(
    "--delete-on-range",
    type=str,
    default="",
    help="Delete services [and associated pods] on the specified range. Ex: 192.168.1.200-192.168.1.206",
)

parser.add_argument(
    "--delete-with-ips",
    type=str,
    default="",
    help="Delete services [and associated pods] running on a specified comma-separated list of IPs",
)

args = parser.parse_args()

def setup_logger(name: str, log_file: str = None, level: int = logging.INFO) -> logging.Logger:
    """
    Creates and returns a configured logger.

    Args:
        name (str): Name of the logger.
        log_file (str): Optional file to log messages to.
        level (int): Logging level (default: logging.INFO).

    Returns:
        logging.Logger: Configured logger instance.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    formatter = logging.Formatter(
        fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger

logger = setup_logger("app")
KUBECTL_BINARY_PATH_PATH_AS_LIST = KUBECTL_BINARY_PATH.split(' ')  
def deploy_metallb_ippool_and_adv(ip_pool):
    temp_file_name=None
    try:
        with open(METALLB_IP_ANNOUNCE_TEMPLATE_PATH, "r") as file:
            content = file.read().replace("<ip-range>", ip_pool)
        
        with tempfile.NamedTemporaryFile(delete=False, mode="w", suffix=".yaml") as temp_file:
            temp_file_name = temp_file.name
            temp_file.write(content)
        
        logger.debug("Temporary file for deploying Metallb IPPool and l2adv: %s",temp_file_name)
        
        command = KUBECTL_BINARY_PATH_PATH_AS_LIST + ["apply", "-f", temp_file_name]
        process = subprocess.run(command, text=True, capture_output=True)
        
        if process.returncode == 0:
            logger.info("Deploy metallb_ippool_and_adv status:\n%s", process.stdout)
        else:
            logger.error("Error occurred in deploy_metallb_ippool_and_adv: %s", process.stderr)
    except Exception as e:
        logger.error("An error occurred in deploy_metallb_ippool_and_adv: %s", str(e))
    finally:
        if temp_file_name is not None and os.path.exists(temp_file_name):
            os.remove(temp_file_name)
            logger.debug("Temporary file deleted: %s",temp_file_name)

def list_ippool():
    try:
        command = KUBECTL_BINARY_PATH_PATH_AS_LIST + ["get", "ipaddresspool", "-A"]
        process = subprocess.run(command, text=True, capture_output=True)
        if process.returncode == 0:
            logger.info("IPPools :\n%s", process.stdout)
        else:
            logger.error("Failed to list ippool: %s", process.stderr)
    except Exception as e:
        logger.error("An error occurred inlisting ippool: %s", str(e))


def get_next_valid_sequence_for_pod_and_service(name_prefix):
    current_seq_data = None
    try:
        with open(SEQUENCE_NUMBER_FILE, "r") as file:
            current_seq_data = json.load(file)  
    except json.JSONDecodeError:
        logger.error("Error: The file does not contain valid JSON.")
    except FileNotFoundError:
        logger.error("Error: File not found: %s",SEQUENCE_NUMBER_FILE)
    except Exception as e:
        logger.error("An unexpected error occurred: %s",str(e))
        
    if current_seq_data is None or name_prefix not in current_seq_data:
        return 1
    else:
        seq_val = current_seq_data[name_prefix]
        while True:
            seq_val = seq_val + 1
            pod_name = name_prefix + "-"+SIM_IDENTIFIER+"-"+ str(seq_val)+"-0"
            command = KUBECTL_BINARY_PATH_PATH_AS_LIST + ["get", "pods", pod_name]
            process = subprocess.run(command, text=True, capture_output=True)
            if process.returncode == 0:
                logger.info("pod %s exist status :\n%s", pod_name, process.stdout)
            else:
                if "Error from server (NotFound)" in process.stderr:
                    return seq_val
                raise Exception("Error occurred in getting pod %s status :%s",  pod_name, process.stderr)
            
def update_seq_num(name_prefix, seq_num):
    try:
        with open(SEQUENCE_NUMBER_FILE, "r") as file:
            data = json.load(file)
        data[name_prefix] = seq_num
        with open(SEQUENCE_NUMBER_FILE, "w") as file:
            json.dump(data, file, indent=2)
    except FileNotFoundError:
        logger.error("Error: File not found: %s", SEQUENCE_NUMBER_FILE)
    except Exception as e:
        logger.error("An unexpected error occurred:: %s",str(e))

def deploy_pod_and_service(num_ftd, seq_num, name_prefix):
    try:
        with open(SVC_AND_STS_TEMPLATE_PATH, "r") as file:
            content = file.read()
        content = content.replace("<prefix>", name_prefix)
        content = content.replace("<host-sim-data-path>", EXTRACTED_RESPONSE_PATH)
        content = content.replace("<sim-identifier>", SIM_IDENTIFIER)
        content = content.replace("<service-port-1>", SERVICE_PORT_1)
        content = content.replace("<container-port-1>", CONTAINER_PORT_1)
        content = content.replace("<service-port-2>", SERVICE_PORT_2)
        content = content.replace("<container-port-2>", CONTAINER_PORT_2)
        content = content.replace("<pod-storage-dir>", EXTRACTED_RESPONSE_ROOT_DIR)
        
        for current_seq_num in range(seq_num, seq_num + num_ftd):
            pod_and_svc_dep = content.replace("<sequence>", str(current_seq_num))
            
            with tempfile.NamedTemporaryFile(delete=False, mode="w", suffix=".yaml") as temp_file:
                temp_file_name = temp_file.name
                temp_file.write(pod_and_svc_dep)
            
            
            logger.debug("Temporary file for deploying pod with sequence number %d: %s",  current_seq_num, temp_file_name)
            
            command = KUBECTL_BINARY_PATH_PATH_AS_LIST + ["apply", "-f", temp_file_name]
            process = subprocess.run(command, text=True, capture_output=True)
            
            if process.returncode == 0:
                logger.info("Deploy pod and service with sequence number %d status:\n%s", current_seq_num, process.stdout)
                update_seq_num(args.name_prefix, current_seq_num)
            else:
                logger.error("Error occurred in deploying pod and service with sequence number %d: %s",current_seq_num ,process.stderr)
            if os.path.exists(temp_file_name):
                os.remove(temp_file_name)
                logger.debug("Temporary file %s for deploying pod with sequence number %d is deleted",  temp_file_name, current_seq_num)
    except Exception as e:
        logger.error("An error occurred indeploying pod and service: %s", str(e))

def list_pods(prefix=None):
    try:
        command = KUBECTL_BINARY_PATH + " get pods"
        if prefix is not None:
            grep_command = "grep '^"+ prefix+"-"+SIM_IDENTIFIER+"'"
            command = f"{command} | {grep_command}"
        process = subprocess.run(command, shell=True, text=True, capture_output=True)
        if process.returncode == 0:
            if prefix is None:
                logger.info("Pods :\n%s", process.stdout)
            else:
                logger.info("Pods :\nNAME                       READY   STATUS    RESTARTS   AGE \n%s", process.stdout)
        else:
            if "" in process.stderr:
                logger.error("No Pods found")
            else:    
                logger.error("Failed to list pods: %s", process.stderr)
    except Exception as e:
        logger.error("Failed to list pods: %s",str(e))

def list_pv(prefix=None):
    try:
        command = KUBECTL_BINARY_PATH + " get pv"
        if prefix is not None:
            grep_command = "grep '^"+ prefix+"-"+SIM_IDENTIFIER+"'"
            command = f"{command} | {grep_command}"
        process = subprocess.run(command, shell=True, text=True, capture_output=True)
        if process.returncode == 0:
            if prefix is None:
                logger.info("Storage :\n%s", process.stdout)
            else:
                logger.info("Storage :\nNAME                        CAPACITY   "+
                            "ACCESS MODES   RECLAIM POLICY   STATUS   "+
                            "CLAIM                                STORAGECLASS   VOLUMEATTRIBUTESCLASS   REASON   AGE\n%s", process.stdout)
        else:
            if "" in process.stderr:
                logger.error("No Storage found")
            else:
                logger.error("Failed to list storage: %s", process.stderr)
    except Exception as e:
        logger.error("Failed to list storage: %s",str(e))
        
def list_svc(prefix=None):
    try:
        command = KUBECTL_BINARY_PATH + " get svc --field-selector spec.type=LoadBalancer" 
        if prefix is not None:
            grep_command = "grep '^"+ prefix+"-"+SIM_IDENTIFIER+"'"
            command = f"{command} | {grep_command}"
        process = subprocess.run(command, shell=True, text=True, capture_output=True)
        if process.returncode == 0:
            if prefix is None:
                logger.info("Services :\n%s", process.stdout)
            else:
                logger.info("Services :\nNAME                     TYPE           CLUSTER-IP"
                            +"       EXTERNAL-IP    PORT(S)                       AGE\n%s", process.stdout)
        else:
            if "" in process.stderr:
                logger.error("No service found")
            else:
                logger.error("Failed to list Services: %s", process.stderr)
    except Exception as e:
        logger.error("Failed to list Services: %s",str(e))

def get_svc_name_for_ips(ips):
    try:
        get_service_command = KUBECTL_BINARY_PATH+" get svc"
        formatted_ips=''
        for ip in ips:
            formatted_ips = formatted_ips + ip + "\|"
        formatted_ips = formatted_ips.rstrip("\|")
        grep_command = f"grep '{formatted_ips}'"
        awk_command = "awk '{print $1}'"
        command = f"{get_service_command} | {grep_command} | {awk_command} "
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            services = result.stdout.splitlines()
            logger.debug("Services names for ips %s :%s", str(ips), str(services))
            return services
        else:
            logger.error("Error occurred in getting Services : %s", result.stderr)
    except Exception as e:
        logger.error("An error occurred in gettibg Services: %s",str(e))


def get_ips_and_svcname_map_all_vftd():
    try:
        get_service_command = KUBECTL_BINARY_PATH+" get svc"
        grep_command = f"grep '{SIM_IDENTIFIER}'"
        awk_command = "awk '{print $1, $4}'"
        ip_svc_map={}
        command = f"{get_service_command} | {grep_command} | {awk_command} "
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            services_and_ips = result.stdout.splitlines()
            for svc_with_ip in services_and_ips:
                svc_ip_split = svc_with_ip.split(' ')
                ip_svc_map[svc_ip_split[1]] = svc_ip_split[0]
            logger.debug("IP-Services map for ftds :%s", str(ip_svc_map))
            return ip_svc_map
        else:
            logger.error("Error occurred in getting IP-Services map for ftds : %s", result.stderr)
    except Exception as e:
        logger.error("An error occurred in gettibg IP-Services map for ftds: %s",str(e))

def delete_sts_pods(prefix=None):
    get_statefulsets_command = KUBECTL_BINARY_PATH+" get statefulsets"
    awk_command = "awk '{print $1}'"
    if prefix is not None:
        if SIM_IDENTIFIER in prefix:
            grep_command = "grep '^"+ prefix+"'"
        else:
            grep_command = "grep '^"+ prefix+"-"+SIM_IDENTIFIER+"'"
        command = f"{get_statefulsets_command} | {awk_command} | {grep_command}"
    else:
        command = f"{get_statefulsets_command} | {awk_command}"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        statefulsets_to_delete = result.stdout.splitlines()
        for statefulset in statefulsets_to_delete:
            if SIM_IDENTIFIER not in statefulset:
                continue
            delete_command = KUBECTL_BINARY_PATH_PATH_AS_LIST + ["delete", "statefulset", statefulset, "--force", "--grace-period=0"] 
            delete_result = subprocess.run(delete_command, capture_output=True, text=True)
            if delete_result.returncode == 0:
                    logger.info("%s", delete_result.stdout)
            else:
                if "No resources found" in delete_result.stderr or "" in delete_result.stderr:
                    logger.error("No Pods found")
                else:
                    logger.error("Failed to delete StatefulSet %s: %s",statefulset,delete_result.stderr)
    else:
        if "No resources found" in result.stderr or "" in result.stderr:
            logger.error("No Pods found")
        else:
            logger.error("Failed to filter StatefulSet for deletion: %s", result.stderr)

def delete_pv_and_pvc(prefix=None):

    
    get_pvc_command = KUBECTL_BINARY_PATH+" get pvc"
    awk_command = "awk '{print $1}'"
    if prefix is not None:
        if SIM_IDENTIFIER in prefix:
            grep_command = "grep '^"+ prefix+"'"
        else:
            grep_command = "grep '^"+ prefix+"-"+SIM_IDENTIFIER+"'"
        command = f"{get_pvc_command} | {awk_command} | {grep_command}"
    else:
        command = f"{get_pvc_command} | {awk_command}"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        pvc_to_delete = result.stdout.splitlines()
        for pvc in pvc_to_delete:
            if SIM_IDENTIFIER not in pvc:
                continue
            patch_command = KUBECTL_BINARY_PATH +" patch pvc "+ pvc + " --type=json -p='[{\"op\": \"remove\", \"path\": \"/metadata/finalizers\"}]'"
            patch_result = subprocess.run(patch_command, capture_output=True, shell=True)
            if patch_result.returncode == 0:
                logger.debug("%s", patch_result.stdout)
            else:
                logger.debug("Patching is not complete %s", patch_result)
            delete_command = KUBECTL_BINARY_PATH_PATH_AS_LIST + ["delete", "pvc", pvc, "--force", "--grace-period=0"] 
            delete_result = subprocess.run(delete_command, capture_output=True, text=True)
            if delete_result.returncode == 0:
                logger.info("%s", delete_result.stdout)
            else:
                if "No resources found" in delete_result.stderr or "" in delete_result.stderr:
                    logger.error("No PV found")
                else:
                    logger.error("Failed to delete pvc %s: %s",pvc,delete_result.stderr)
    else:
        if "No resources found" in result.stderr or "" in result.stderr:
            logger.error("No pvc found")
        else:
            logger.error("Failed to filter pvc for deletion: %s", result.stderr)

    
def delete_service(prefix=None):
    get_svc_command = KUBECTL_BINARY_PATH+" get svc"
    awk_command = "awk '{print $1}'"
    if prefix is not None:
        if SIM_IDENTIFIER in prefix:
            grep_command = "grep '^"+ prefix+"'"
        else:
            grep_command = "grep '^"+ prefix+"-"+SIM_IDENTIFIER+"'"
        command = f"{get_svc_command} | {awk_command} | {grep_command}"
    else:
        command = f"{get_svc_command} | {awk_command}"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        services_to_delete = result.stdout.splitlines()
        for service in services_to_delete:
            if SIM_IDENTIFIER not in service:
                continue
            delete_command = KUBECTL_BINARY_PATH_PATH_AS_LIST + ["delete", "svc", service] 
            delete_result = subprocess.run(delete_command, capture_output=True, text=True)
            if delete_result.returncode == 0:
                logger.info("%s", delete_result.stdout)
            else:
                if "No resources found" in delete_result.stderr or "" in delete_result.stderr:
                    logger.error("No Service found")
                else:
                    logger.error("Failed to delete service %s: %s",service,delete_result.stderr)
    else:
        if "No resources found" in result.stderr or "" in result.stderr:
            logger.error("No service found")
        else:
            logger.error("Failed to filter service for deletion %s; Probably no services exist with given prefix.", result.stderr)

def delete_ippool_and_adv(ip_pool=None):
    try:
        if ip_pool is None:
            command = KUBECTL_BINARY_PATH_PATH_AS_LIST + ["delete", "ipaddresspool","--all" ,"-n", METALLB_NAMESPACE]
        else:
            command = KUBECTL_BINARY_PATH_PATH_AS_LIST + ["delete", "ipaddresspool", "pool-"+ip_pool , "-n", METALLB_NAMESPACE]
        process = subprocess.run(command, text=True, capture_output=True)
        if process.returncode == 0:
            logger.info("Ippool delete status :\n%s", process.stdout)
        else:
            logger.error("Error occurred in deleteing ippool: %s", process.stderr)
    except Exception as e:
        logger.error("An error occurred deleteing ippool:  %s", str(e))
    try:
        if ip_pool is None:
            command = KUBECTL_BINARY_PATH_PATH_AS_LIST + ["delete", "l2advertisement", "--all" ,"-n", METALLB_NAMESPACE]
        else:
            command = KUBECTL_BINARY_PATH_PATH_AS_LIST + ["delete", "l2advertisement", "adv-"+ip_pool , "-n", METALLB_NAMESPACE]
        process = subprocess.run(command, text=True, capture_output=True)
        if process.returncode == 0:
            logger.info("l2advertisement delete status :\n%s", process.stdout)
        else:
            logger.error("Error occurred in deleteing l2advertisement: %s", process.stderr)
    except Exception as e:
        logger.error("An error occurred deleteing l2advertisement:  %s", str(e))

            
if args.add_ip_pool != '':
    deploy_metallb_ippool_and_adv(args.add_ip_pool)


if args.list != '':
    if args.list == "all":
        list_pods()
        list_pv()
        list_svc()
        list_ippool()
    if args.list == "pods":
        list_pods()
    if args.list == "services":
        list_svc()
    if args.list == "storage":
        list_pv()
    if args.list == "ippools":
        list_ippool()        
    os._exit(0)

if args.list_for_name_prefix != '':
    list_pods(args.list_for_name_prefix)
    list_pv(args.list_for_name_prefix)
    list_svc(args.list_for_name_prefix)
    os._exit(0)
    

if args.delete != '':
    if args.delete == "all":
        delete_sts_pods()
        delete_service()
        delete_pv_and_pvc()
        delete_ippool_and_adv()
    if args.delete == "pods":
        delete_sts_pods()
    if args.delete == "services":
        delete_service()
    if args.delete == "storage":
        delete_pv_and_pvc()
    if args.delete == "ippools":
        delete_ippool_and_adv()     
    os._exit(0)

if args.delete_for_name_prefix != '':
    delete_sts_pods(args.delete_for_name_prefix)
    delete_service(args.delete_for_name_prefix)
    delete_pv_and_pvc(args.delete_for_name_prefix)
    os._exit(0)
    
if args.delete_ip_pool != '':
    delete_ippool_and_adv(args.delete_ip_pool)
    os._exit(0)
    
if args.delete_with_ips != "":
    for prefix in get_svc_name_for_ips(args.delete_with_ips.split(",")):
        delete_sts_pods(prefix)
        delete_pv_and_pvc(prefix)
        delete_service(prefix)
    os._exit(0)

if args.delete_on_range != "":
    try:
        start_ip, end_ip = args.delete_on_range.split('-')
        start_ip = ipaddress.IPv4Address(start_ip)
        end_ip = ipaddress.IPv4Address(end_ip)
        ip_svcname_map =  get_ips_and_svcname_map_all_vftd()
        for target_ip, prefix in ip_svcname_map.items():
            if start_ip <= ipaddress.IPv4Address(target_ip) <= end_ip:
                delete_sts_pods(prefix)
                delete_pv_and_pvc(prefix)
                delete_service(prefix)
    except ValueError as e:
        logger.error("Given ip range is invalid: %s", str(e))
        os._exit(1)
    

if args.num_ftd > 0 and args.name_prefix != '' and args.response_zip:
    if not os.path.exists(EXTRACTED_RESPONSE_ROOT_DIR):
        os.makedirs(EXTRACTED_RESPONSE_ROOT_DIR,mode=0o777)

    if os.path.exists(EXTRACTED_RESPONSE_PATH):
        shutil.rmtree(EXTRACTED_RESPONSE_PATH)
    
    with zipfile.ZipFile(args.response_zip, 'r') as zip_ref:
        zip_ref.extractall(EXTRACTED_RESPONSE_ROOT_DIR)
    logger.debug("Extracted sim data zip %s to %s",args.response_zip ,EXTRACTED_RESPONSE_ROOT_DIR)
    starting_seq_num = get_next_valid_sequence_for_pod_and_service(args.name_prefix)
    deploy_pod_and_service(args.num_ftd, starting_seq_num,args.name_prefix)
    

