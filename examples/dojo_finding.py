"""
Example written by Aaron Weaver <aaron.weaver@owasp.org>
as part of the OWASP DefectDojo and OWASP AppSec Pipeline Security projects

Description: Creates a manual finding in DefectDojo and returns information about the newly created finding
"""
from defectdojo_api import defectdojo
from datetime import datetime, timedelta
from random import randint
import os

# Setup DefectDojo connection information
host = 'http://localhost:8000'
api_key = os.environ['DOJO_API_KEY']
user = 'admin'
user_id = 1 #Default user


#Optionally, specify a proxy
proxies = {
  'http': 'http://localhost:8080',
  'https': 'http://localhost:8080',
}
"""
proxies=proxies
"""

def create_finding_data(product_id, engagement_id, test_id, build):
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
    "None", "true", "true", "References", build=build)

# Instantiate the DefectDojo api wrapper
dd = defectdojo.DefectDojoAPI(host, api_key, user, debug=False, proxies=proxies)

# Search and see if product exists so that we don't create multiple product entries
product_name = "Acme API Finding Demo"
products = dd.list_products(name_contains=product_name)
product_id = None

if products.count() > 0:
    for product in products.data["objects"]:
        product_id = product['id']
else:
    # Create a product
    prod_type = 1 #1 - Research and Development, product type
    product = dd.create_product(product_name, "This is a detailed product description.", prod_type)

    # Get the product id
    product_id = product.id()
    print "Product successfully created with an id: " + str(product_id)

# Retrieve the newly created product
product = dd.get_product(product_id)

product_name = "Acme API Finding Demo"
engagement = dd.list_engagements(product_in=product_id, name_contains="Intial " + product_name + " Engagement")
engagement_id = None

start_date = datetime.now()
end_date = start_date+timedelta(days=randint(2,8))

if engagement.count() > 0:
    for engagement in engagement.data["objects"]:
        engagement_id = engagement['id']
else:
    # Create an engagement
    print "Creating engagement: " + "Intial " + product_name + " Engagement"
    engagement = dd.create_engagement("Intial " + product_name + " Engagement", product_id, user_id,
    "In Progress", start_date.strftime("%Y-%m-%d"), end_date.strftime("%Y-%m-%d"))
    engagement_id = engagement.id()

print "Creating the test"
# Create Test
test_type = 5 #Web Test
environment = 3 #Production environment
test = dd.create_test(engagement_id, test_type, environment,
start_date.strftime("%Y-%m-%d"), start_date.strftime("%Y-%m-%d"))
test_id = test.id()

print "Creating the finding"
build = "Jenkins-" + str(randint(100,999))
# Create Finding
create_finding_data(product_id, engagement_id, test_id, build=build)

print "Listing the new findings for this build"

i = 0
#Creating four tests
while i < 4:
    test_type = i+1 #Select some random tests
    environment = randint(1,6) #Select random environments
    test = dd.create_test(engagement_id, test_type, environment,
    start_date.strftime("%Y-%m-%d"), start_date.strftime("%Y-%m-%d"))
    test_id = test.id()

    f = 0
    f_max = randint(2,4)
    while f < f_max:
        # Load findings
        create_finding_data(product_id, engagement_id, test_id, build=build)
        f = f + 1

    i = i + 1

#Summarize the findings loaded
print "***************************************"
findings = dd.list_findings(build=build)
print "Build ID: " + build
print "Total Created: " + str(findings.count())
print "***************************************"
print
if findings.count() > 0:
    for finding in findings.data["objects"]:
        print finding["title"] + ", Severity: " + finding["severity"]
