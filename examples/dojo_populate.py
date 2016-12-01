"""
Example written by Aaron Weaver <aaron.weaver@owasp.org>
as part of the OWASP DefectDojo and OWASP AppSec Pipeline Security projects

Description: Imports test data into DefectDojo and creates products,
engagements and tests along with findings.
"""
from defectdojo_api import defectdojo
from random import randint
import os
from datetime import datetime, timedelta

# Setup DefectDojo connection information
host = 'http://localhost:8000'
api_key = os.environ['DOJO_API_KEY']
user = 'admin'

"""
#Optionally, specify a proxy
proxies = {
  'http': 'http://localhost:8080',
  'https': 'http://localhost:8080',
}
#proxies=proxies
"""

# Instantiate the DefectDojo api wrapper
dd = defectdojo.DefectDojoAPI(host, api_key, user, debug=False)

user_id = 1 #Default user

def create_finding_data(product_id, engagement_id, test_id):
    cwe = [352, 22, 676, 863, 134, 759, 798]
    cwe_desc = ['Cross-Site Request Forgery (CSRF)', 'Improper Limitation of a Pathname to a Restricted Directory (\'Path Traversal\')',
    'Use of Potentially Dangerous Function', 'Incorrect Authorization', 'Uncontrolled Format String',
    'Use of a One-Way Hash without a Salt', 'Use of Hard-coded Credentials']
    severity=['Low','Medium','High', 'Critical']
    user_id = 1
    finding_date = datetime.now()
    finding_date = finding_date+timedelta(days=randint(-30,0))
    finding_cwe = randint(0,6)

    finding = dd.create_finding(cwe_desc[finding_cwe], cwe_desc[finding_cwe], severity[randint(0,3)],
    cwe[finding_cwe], finding_date.strftime("%Y-%m-%d"), product_id, engagement_id, test_id, user_id,
    "None", "true", "true", "References")

def create_load_data(product_name, product_desc, file=None, file_test_type=None):
    # Create a product
    prod_type = 1 #1 - Research and Development, product type
    print "Creating product: " + product_name
    product = dd.create_product(product_name, product_desc, prod_type)
    if product.success:
        # Get the product id
        product_id = product.id()

        # Create an engagement
        start_date = datetime.now()
        end_date = start_date+timedelta(days=randint(2,8))

        print "Creating engagement: " + "Intial " + product_name + " Engagement"
        engagement = dd.create_engagement("Intial " + product_name + " Engagement", product_id, user_id,
        "In Progress", start_date.strftime("%Y-%m-%d"), end_date.strftime("%Y-%m-%d"))
        engagement_id = engagement.id()

        # Create some tests
        print "Creating tests"

        #Load scanner test data
        if file is not None:
            print "Loading scanner results from scanner export"
            dir_path = os.path.dirname(os.path.realpath(__file__))
            date = datetime.now()
            upload_scan = dd.upload_scan(engagement_id, file_test_type, dir_path + file,
            "true", date.strftime("%Y/%m/%d"), "API")

        i = 0
        while i < 6:
            test_type = i+1 #Select some random tests
            environment = randint(1,6) #Select random environments
            test = dd.create_test(engagement_id, test_type, environment,
            start_date.strftime("%Y-%m-%d"), start_date.strftime("%Y-%m-%d"))
            test_id = test.id()

            f = 0
            f_max = randint(4,10)
            while f < f_max:
                # Load findings
                create_finding_data(product_id, engagement_id, test_id)
                f = f + 1

            i = i + 1
    else:
        print product.message

##### Create Products, Engagements and Tests ########
create_load_data("BodgeIt", "Product description.", "/tests/scans/Bodgeit-burp.xml", "Burp Scan")
create_load_data("A CRM App", "Product description.")
create_load_data("An Engineering Application", "Product description.")
create_load_data("A Marketing Site", "Product description.")
