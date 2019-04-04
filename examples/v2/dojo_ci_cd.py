"""
Example written by Aaron Weaver <aaron.weaver@owasp.org>
as part of the OWASP DefectDojo and OWASP AppSec Pipeline Security projects

Description: CI/CD example for DefectDojo
"""
from defectdojo_api import defectdojo_apiv2 as defectdojo
from datetime import datetime, timedelta
import os, sys
import argparse
import time

import requests.packages.urllib3

requests.packages.urllib3.add_stderr_logger()

test_cases = []

def junit(toolName, file):

    junit_xml = junit_xml_output.JunitXml(toolName, test_cases, total_tests=None, total_failures=None)
    with open(file, 'w') as file:
        print("Writing Junit test files")
        file.write(junit_xml.dump())

def dojo_connection(host, api_key, user, proxy,debug=False):
    #Optionally, specify a proxy
    proxies = None
    if proxy:
        proxies = {
          'http': proxy,
          'https': proxy,
        }

    # Instantiate the DefectDojo api wrapper
    dd = defectdojo.DefectDojoAPIv2(host, api_key, user, api_version="v2", proxies=proxies, verify_ssl=False, timeout=360, debug=debug)

    return dd
    # Workflow as follows:
    # 1. Scan tool is run against build
    # 2. Reports is saved from scan tool
    # 3. Call this script to load scan data, specifying scanner type
    # 4. Script returns along with a pass or fail results: Example: 2 new critical vulns, 1 low out of 10 vulnerabilities

def get_user_id(dd, user_name):
    users = dd.list_users(user_name, limit=200)
    user_id = None

    if users.success:
        print("users.success")
        user_id = users.data["results"][0]["id"]
        return user_id
    else:
        raise ValueError('user not found: ' + str(username))

def get_product_id(dd, product_id, product_name):
    if product_id != None:
         product = dd.get_product(product_id)
         return product_id
    elif product_name != None:
         products_response = dd.list_products()
         for product in products_response.data["results"]:
             #print(product["name"])
             if product["name"] == product_name:
                 return product["id"]
    else:
        raise ValueError('product_id or product_name required')

def get_engagement_id(dd, product_id, user_id, engagement_id, engagement_name, branch_name, build_id=None, commit_hash=None):
    if engagement_id != None:
        engagement = dd.get_engagement(engagement_id = engagement_id)
        return engagement_id
    elif engagement_name != None:
        engagement_name_plus_branch = engagement_name
        if branch_name is not None:
            engagement_name_plus_branch = engagement_name + " (" + branch_name + ")"
            engagements_reponse = dd.list_engagements(product_id=product_id, status="In Progress")
            for engagement in engagements_reponse.data["results"]:
                print(engagement["name"])
                if engagement["name"] == engagement_name_plus_branch:
                    return engagement["id"]
    else:
        raise ValueError('engagement id or name required')

# no engagement found by id or by name, so create a new one

    start_date = datetime.now()
    end_date = start_date+timedelta(days=365)

    engagement_description = "CI/CD Engagement created by ci/cd script"

    engagement_id = dd.create_engagement(engagement_name_plus_branch, product_id, str(user_id),
    "In Progress", start_date.strftime("%Y-%m-%d"), end_date.strftime("%Y-%m-%d"), branch_tag=branch_name, description=engagement_description, build_id=build_id, commit_hash=commit_hash)
    return str(engagement_id.data["id"])

def process_findings(dd, engagement_id, dir, build=None):
    test_ids = []
    for root, dirs, files in os.walk(dir):
        for name in files:
            file = os.path.join(os.getcwd(),root, name)
            test_id = processFiles(dd, engagement_id, file)
            if test_id is not None:
                test_ids.append(str(test_id))
    return ','.join(test_ids)

def processFiles(dd, engagement_id, file, active, verified, close_old_findings, skip_duplicates, scanner=None, build=None):
    upload_scan = None
    scannerName = None
    path=os.path.dirname(file)
    name = os.path.basename(file)
    tool = os.path.basename(path)
    tool = tool.lower()

    test_id = None
    date = datetime.now()
    dojoDate = date.strftime("%Y-%m-%d")

    if scanner == None:
        #Tools without an importer in Dojo; attempted to import as generic
        if "generic" in name:
            scanner = "Generic Findings Import"
            if tool == "nikto":
                print("Uploading nikto scan: " + file)
                test_id = dd.upload_scan(engagement_id, scanner, file, "true", dojoDate, build)
            elif tool == "bandit":
                print("Uploading bandit scan: " + file)
                test_id = dd.upload_scan(engagement_id, scanner, file, "true", dojoDate, build)
        else:
            if tool == "burp":
                scannerName = "Burp Scan"
            elif tool == "nessus":
                scannerName = "Nessus Scan"
            elif tool == "nmap":
                scannerName = "Nmap Scan"
            elif tool == "nexpose":
                scannerName = "Nexpose Scan"
            elif tool == "veracode":
                scannerName = "Veracode Scan"
            elif tool == "checkmarx":
                scannerName = "Checkmarx Scan"
            elif tool == "zap":
                scannerName = "ZAP Scan"
            elif tool == "appspider":
                scannerName = "AppSpider Scan"
            elif tool == "Arachni Scan":
                scannerName = "Arachni Scan"
            elif tool == "vcg":
                scannerName = "VCG Scan"
            elif tool == "dependency":
                scannerName = "Dependency Check Scan"
            elif tool == "retirejs":
                scannerName = "Retire.js Scan"
            elif tool == "nodesecurity":
                scannerName = "Node Security Platform Scan"
            elif tool == "qualys":
                scannerName = "Qualys Scan"
            elif tool == "qualyswebapp":
                scannerName = "Qualys Webapp Scan"
            elif tool == "openvas":
                scannerName = "OpenVAS CSV"
            elif tool == "snyk":
                scannerName = "Snyk Scan"

    else: 
        scannerName = scanner
                
    if scannerName is not None:
        print("Uploading " + scannerName + " scan: " + file + " for engagement: " + str(engagement_id))
        test_id = dd.upload_scan(engagement_id, scannerName, file, active, verified, close_old_findings, skip_duplicates, dojoDate, tags="ci/cd", build=build)
        if test_id.success == False:
            raise ValueError("Upload failed: Detailed error message: " + test_id.data)
    else:
         print("unable to determine scannerName")
         sys.exit()

    return test_id

def create_findings(dd, engagement_id, scanner, file, build=None):
    # Upload the scanner export
    if engagement_id > 0:
        print("Uploading scanner data.")
        date = datetime.now()

        upload_scan = dd.upload_scan(engagement_id, scanner, file, "true", date.strftime("%Y-%m-%d"), build=build)

        if upload_scan.success:
            test_id = upload_scan.id()
        else:
            print(upload_scan.message)
            quit()

def summary(dd, engagement_id, test_ids, max_critical=0, max_high=0, max_medium=0):
        findings = dd.list_findings(engagement_id_in=engagement_id, duplicate="false", active="true", verified="true")
        print("==============================================")
        print("Total Number of Vulnerabilities: " + str(findings.data["count"]))
        print("==============================================")
        print_findings(sum_severity(findings))
        print("")
        findings = dd.list_findings(test_id_in=test_ids, duplicate="true")
        print("==============================================")
        print("Total Number of Duplicate Findings: " + str(findings.data["count"]))
        print("==============================================")
        print_findings(sum_severity(findings))
        print("")
        #Delay while de-dupes
        sys.stdout.write("Sleeping for 10 seconds for de-dupe celery process:")
        sys.stdout.flush()
        for i in range(5):
            time.sleep(2)
            sys.stdout.write(".")
            sys.stdout.flush()

        findings = dd.list_findings(test_id_in=test_ids, duplicate="false", limit=500)
        if findings.count() > 0:
            """
            for finding in findings.data["objects"]:
                test_cases.append(junit_xml_output.TestCase(finding["title"] + " Severity: " + finding["severity"], finding["description"],"failure"))
            if not os.path.exists("reports"):
                os.mkdir("reports")
            junit("DefectDojo", "reports/junit_dojo.xml")
            """

        print("\n==============================================")
        print("Total Number of New Findings: " + str(findings.data["count"]))
        print("==============================================")
        sum_new_findings = sum_severity(findings)
        print_findings(sum_new_findings)
        print ("")
        print("==============================================")

        strFail = None
        if max_critical is not None:
            if sum_new_findings[4] > max_critical:
                strFail =  "Build Failed: Max Critical"
        if max_high is not None:
            if sum_new_findings[3] > max_high:
                strFail = strFail +  " Max High"
        if max_medium is not None:
            if sum_new_findings[2] > max_medium:
                strFail = strFail +  " Max Medium"
        if strFail is None:
            print("Build Passed!")
        else:
            print("Build Failed: " + strFail)
        print("==============================================")

def sum_severity(findings):
    severity = [0,0,0,0,0]
    for finding in findings.data["results"]:
        if finding["severity"] == "Critical":
            severity[4] = severity[4] + 1
        if finding["severity"] == "High":
            severity[3] = severity[3] + 1
        if finding["severity"] == "Medium":
            severity[2] = severity[2] + 1
        if finding["severity"] == "Low":
            severity[1] = severity[1] + 1
        if finding["severity"] == "Info":
            severity[0] = severity[0] + 1

    return severity

def print_findings(findings):
    print("Critical: " + str(findings[4]))
    print("High: " + str(findings[3]))
    print("Medium: " + str(findings[2]))
    print("Low: " + str(findings[1]))
    print("Info: " + str(findings[0]))

class Main:
    if __name__ == "__main__":
        parser = argparse.ArgumentParser(description='CI/CD integration for DefectDojo')
        parser.add_argument('--host', help="DefectDojo Hostname", required=True)
        parser.add_argument('--proxy', help="Proxy ex:localhost:8080", required=False, default=None)
        parser.add_argument('--api_key', help="API Key", required=True)
        parser.add_argument('--branch_name', help="Reference to branch being scanned", required=False)
        parser.add_argument('--build_id', help="Reference to build id or build url", required=False)
        parser.add_argument('--commit_hash', help="Reference to commit hash being scanned", required=False)
        parser.add_argument('--user', help="User", required=True)

        parser.add_argument('--file', help="Scanner file", required=False)
        parser.add_argument('--dir', help="Scanner directory, needs to have the scanner name with the scan file in the folder. Ex: reports/nmap/nmap.csv", required=False)
        parser.add_argument('--scanner', help="Type of scanner", required=False)
        parser.add_argument('--build', help="Build ID", required=False)

        group1 = parser.add_mutually_exclusive_group(required=True)
        group1.add_argument('--engagement', help="Engagement ID", required=False, type=int)
        group1.add_argument('--engagement_name', help="Engagement Name", required=False)
        
        group2 = parser.add_mutually_exclusive_group(required=True)
        group2.add_argument('--product', help="DefectDojo Product ID", required=False, type=int)
        group2.add_argument('--product_name', help='DefectDojo Product Name', required=False)

        parser.add_argument('--critical', help="Maximum new critical vulns to pass the build.", required=False, type=int)
        parser.add_argument('--high', help="Maximum new high vulns to pass the build.", required=False, type=int)
        parser.add_argument('--medium', help="Maximum new medium vulns to pass the build.", required=False, type=int)

        parser.add_argument('--active', help="Should uploaded findings be marked as active?", required=False, default=False)
        parser.add_argument('--verified', help="Should uploaded findings be marked as verified?", required=False, default=False)
        parser.add_argument('--close_old_findings', help="Should findings not present in this uplaod be closed?", required=False, default=False)
        parser.add_argument('--skip_duplicates', help="Should findings already present in DefectDojo be skipped?", required=False, default=False)

        #Parse out arguments
        args = vars(parser.parse_args())
        host = args["host"]
        api_key = args["api_key"]
        user = args["user"]
        product_id = args["product"]
        product_name = args["product_name"]
        file = args["file"]
        dir = args["dir"]
        scanner = args["scanner"]
        engagement_id = args["engagement"]
        engagement_name = args["engagement_name"]
        max_critical = args["critical"]
        max_high = args["high"]
        max_medium = args["medium"]
        build = args["build"]
        proxy = args["proxy"]
        branch_name = args["branch_name"]
        build_id = args["build_id"]
        commit_hash = args["commit_hash"]

        active = args["active"]
        verified = args["verified"]
        close_old_findings = args["close_old_findings"]
        skip_duplicates = args["skip_duplicates"]



        if dir is not None or file is not None:
            print("create connection")
            dd = dojo_connection(host, api_key, user, proxy=proxy, debug=True)
            print("created")

            user_id = get_user_id(dd, user)
            print('user_id derived from paramaters: ', str(user_id))

            product_id = get_product_id(dd, product_id, product_name)
            print('product_id derived from paramaters: ', str(product_id))
            
            engagement_id = get_engagement_id(dd, product_id, user_id, engagement_id, engagement_name, branch_name, build_id=build_id, commit_hash=commit_hash)
            print('engagement_id derived from paramaters: ', str(engagement_id))

            test_ids = None
            if file is not None:
                if scanner is not None:
                    test_ids = processFiles(dd, engagement_id, file, active, verified, close_old_findings, skip_duplicates, scanner=scanner)
                else:
                    print("Scanner type must be specified for a file import. --scanner")
                    sys.exit()
            else:
                test_ids = process_findings(dd, engagement_id, dir, build)

            #Close the engagement_id
            #dd.close_engagement(engagement_id)
            summary(dd, engagement_id, test_ids, max_critical, max_high, max_medium)
        else:
            print("No file or directory to scan specified.")
