"""
Example written by Aaron Weaver <aaron.weaver@owasp.org>
as part of the OWASP DefectDojo and OWASP AppSec Pipeline Security projects

Description: Creates a product in DefectDojo and returns information about the newly created product
"""
from defectdojo_api import defectdojo

import os

# Setup DefectDojo connection information
host = 'http://localhost:8000'
api_key = os.environ['DOJO_API_KEY']
user = 'admin'

#Optionally, specify a proxy
proxies = {
  'http': 'http://localhost:8080',
  'https': 'http://localhost:8080',
}
#proxies=proxies


# Instantiate the DefectDojo api wrapper
dd = defectdojo.DefectDojoAPI(host, api_key, user, debug=True)

print "\n\n###############################"
print "Tool Types"
print "###############################"
print dd.list_tool_types().data_json(pretty=True)

print "\n\n###############################"
print "Tool Listings"
print "###############################"
print dd.list_tools().data_json(pretty=True)

print "\n\n###############################"
print "Tool Products"
print "###############################"
print dd.list_tool_products(product_id=1).data_json(pretty=True)
