from defectdojo_api import defectdojo

import os

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
dd = defectdojo.DefectDojoAPI(host, api_key, user, debug=False)

# Create a product
prod_type = 1 #1 - Research and Development, product type
product = dd.create_product("API Product Test", "This is a detailed product description.", prod_type)

if product.success:
    # Get the product id
    product_id = product.id()
    print "Product successfully created with an id: " + str(product_id)

    # Retrieve the newly created product
    product = dd.get_product(product_id)
    if product.success:
        print(product.data_json(pretty=True))  # Decoded JSON object

    # Update the product
    product = dd.set_product(product_id, name="Newly Updated Name")

    if product.success:
        print "Product successfully updated."

        # Retrieve the new product name
        product = dd.get_product(product_id)
        if product.success:
            print "********************************"
            print "Updated name:" + product.data['name']
            print "********************************"

else:
    print product.message

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
