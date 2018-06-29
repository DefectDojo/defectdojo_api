"""
Example written by Aaron Weaver <aaron.weaver@owasp.org>
as part of the OWASP DefectDojo and OWASP AppSec Pipeline Security projects

Description: Creates a product in DefectDojo and returns information about the newly created product
"""
from defectdojo_api import defectdojo

import os
import json

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
proxies=proxies
"""

# Instantiate the DefectDojo api wrapper
dd = defectdojo.DefectDojoAPI(host, api_key, user, debug=True)

# Add languages to a product
product_id = 1
language_type_id = 3
user_id = 1

dd.delete_all_app_analysis_product(product_id)

#language =
data = json.load(open('/tmp/wap.json'))
for app in data["applications"]:
    name = app["name"]
    confidence = app["confidence"]
    version = app["version"]
    icon = app["icon"]
    website = app["website"]

    dd.create_app_analysis(product_id, user_id, name, confidence, version, icon, website)
"""
#language =
data = json.load(open('/Users/aweaver/git/AppSecPipelineReports/4cd987e4-6550-48c7-815c-21cf0c4f33fe/reports/cloc/languages.json'))

for language in data:
    if "header" not in language and "SUM" not in language:
        print data[language]["code"]
        files   = data[language]['nFiles']
        code    = data[language]['code']
        blank   = data[language]['blank']
        comment = data[language]['comment']
        dd.create_language(product_id, user_id, files, code, blank, comment, language_name=language)

#dd.delete_language(1)
languages = dd.list_language_types(language_name="Python")

if languages.success:
    for language in languages.data["objects"]:
        print language['resource_uri']
"""
#language_product = dd.list_languages(product_id=1)
#dd.delete_all_languages_product(1)
#print language_product
"""
# List Products
products = dd.list_products()

if products.success:
    #print(products.data_json(pretty=True))  # Decoded JSON object
    print "********************************"
    print "Total Number of Products: " + str(products.data["meta"]["total_count"])
    print "********************************"

    for product in products.data["objects"]:
        print(product['id'])
        print(product['name'])  # Print the name of each product
        print(product['description'])
        print "******************"
else:
    print products.message
"""
