"""
Example written by Aaron Weaver <aaron.weaver@owasp.org>
as part of the OWASP DefectDojo and OWASP AppSec Pipeline Security projects

Description: CI/CD example for DefectDojo
"""
from defectdojo_api import defectdojo
from datetime import datetime, timedelta
import os
import argparse

def sum_severity(findings):
    severity = [0,0,0,0,0]
    for finding in findings.data["objects"]:
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
    print "Critical: " + str(findings[4])
    print "High: " + str(findings[3])
    print "Medium: " + str(findings[2])
    print "Low: " + str(findings[1])
    print "Info: " + str(findings[0])

def create_findings(host, api_key, user, product_id, file, scanner, engagement_id=None, max_critical=0, max_high=0, max_medium=0):

    #Optionally, specify a proxy
    proxies = {
      'http': 'http://localhost:8080',
      'https': 'http://localhost:8080',
    }
    """
    proxies=proxies
    """

    # Instantiate the DefectDojo api wrapper
    dd = defectdojo.DefectDojoAPI(host, api_key, user, proxies=proxies, timeout=90, debug=False)

    # Workflow as follows:
    # 1. Scan tool is run against build
    # 2. Reports is saved from scan tool
    # 3. Call this script to load scan data, specifying scanner type
    # 4. Script returns along with a pass or fail results: Example: 2 new critical vulns, 1 low out of 10 vulnerabilities

    #Specify the product id
    product_id = product_id
    engagement_id = None

    # Check for a CI/CD engagement_id
    engagements = dd.list_engagements(product_in=product_id, status="In Progress")
    if engagements.success:
        for engagement in engagements.data["objects"]:
            if "Recurring CI/CD Integration" == engagement['name']:
                engagement_id = engagement['id']

    # Engagement doesn't exist, create it
    if engagement_id == None:
        start_date = datetime.now()
        end_date = start_date+timedelta(days=180)
        users = dd.list_users("admin")
        user_id = None
        if users.success:
            user_id = users.data["objects"][0]["id"]
        engagement_id = dd.create_engagement("Recurring CI/CD Integration", product_id, user_id,
        "In Progress", start_date.strftime("%Y-%m-%d"), end_date.strftime("%Y-%m-%d"))

    # Upload the scanner export
    dir_path = os.path.dirname(os.path.realpath(__file__))

    print "Uploading scanner data."
    date = datetime.now()
    upload_scan = dd.upload_scan(engagement_id, scanner, dir_path + file, "true", date.strftime("%Y/%m/%d"), "API")

    if upload_scan.success:
        test_id = upload_scan.id()
    else:
        print upload_scan.message

    findings = dd.list_findings(engagement_id_in=engagement_id, duplicate="false", active="true", verified="true")
    print"=============================================="
    print "Total Number of Vulnerabilities: " + str(findings.data["meta"]["total_count"])
    print"=============================================="
    print_findings(sum_severity(findings))
    print
    findings = dd.list_findings(test_id_in=test_id, duplicate="true")
    print"=============================================="
    print "Total Number of Duplicate Findings: " + str(findings.data["meta"]["total_count"])
    print"=============================================="
    print_findings(sum_severity(findings))
    print
    findings = dd.list_findings(test_id_in=test_id, duplicate="false")
    print"=============================================="
    print "Total Number of New Findings: " + str(findings.data["meta"]["total_count"])
    print"=============================================="
    sum_new_findings = sum_severity(findings)
    print_findings(sum_new_findings)
    print
    print"=============================================="

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
        print "Build Passed!"
    else:
        print "Build Failed: " + strFail
    print"=============================================="

class Main:
    if __name__ == "__main__":
        parser = argparse.ArgumentParser(description='CI/CD integration for DefectDojo')
        parser.add_argument('--host', help="Dojo Hostname", required=True)
        parser.add_argument('--api_key', help="API Key", required=True)
        parser.add_argument('--user', help="User", required=True)
        parser.add_argument('--product', help="Dojo Product ID", required=True)
        parser.add_argument('--file', help="Scanner file", required=True)
        parser.add_argument('--scanner', help="Type of scanner", required=True)
        parser.add_argument('--engagement', help="Engagement ID (optional)", required=False)
        parser.add_argument('--critical', help="Maximum new critical vulns to pass the build.", required=False)
        parser.add_argument('--high', help="Maximum new high vulns to pass the build.", required=False)
        parser.add_argument('--medium', help="Maximum new medium vulns to pass the build.", required=False)

        #Parse out arguments
        args = vars(parser.parse_args())
        host = args["host"]
        api_key = args["api_key"]
        user = args["user"]
        product_id = args["product"]
        file = args["file"]
        scanner = args["scanner"]
        engagement_id = args["engagement"]
        max_critical = args["critical"]
        max_high = args["high"]
        max_medium = args["medium"]

        create_findings(host, api_key, user, product_id, file, scanner, engagement_id, max_critical, max_high, max_medium)
