DefectDojo API
==============

A Python API wrapper to facilitate interactions with `DefectDojo <https://github.com/OWASP/django-DefectDojo>`_.

This package implements API functionality available within Dojo.

Quick Start
-----------

Several quick start options are available:

- Install with pip (recommended): :code:`pip install defectdojo_api`
- `Download the latest release <https://github.com/aaronweaver/defectdojo_api/releases/latest>`_
- Clone the repository: :code:`git clone https://github.com/aaronweaver/defectdojo_api`

Example
-------

.. code-block:: python

    # import the package
    from defectdojo_api import defectdojo

    # setup DefectDojo connection information
    host = 'http://localhost:8000/'
    api_key = 'your_api_key_from_DefectDojo'
    user = 'admin'

    # instantiate the DefectDojo api wrapper
    dd = defectdojo.DefectDojoAPI(host, api_key, user, debug=False)

    # If you need to disable certificate verification, set verify_ssl to False.
    # dd = defectdojo.DefectDojoAPI(host, api_key, user, verify_ssl=False)

    # Create a product
    prod_type = 1 #1 - Research and Development, product type
    product = dd.create_product("API Product Test", "This is a detailed product description.", prod_type)

    if product.success:
        # Get the product id
        product_id = product.id()
        print "Product successfully created with an id: " + str(product_id)

    #List Products
    products = dd.list_products()

    if products.success:
        print(products.data_json(pretty=True))  # Decoded JSON object

        for product in products.data["objects"]:
            print(product['name'])  # Print the name of each product
    else:
        print products.message

Supporting information for each method available can be found in the `documentation <https://github.com/aaronweaver/defectdojo_api/tree/master/docs>`_.

Bugs and Feature Requests
-------------------------

Have a bug or a feature request? Please first search for existing and closed issues. If your problem or idea is not addressed yet, `please open a new issue <https://github.com/aaronweaver/defectdojo_api/issues/new>`_.

Copyright and License
---------------------

- `Licensed under MIT <https://github.com/aaronweaver/defectdojo_api/blob/master/LICENSE.txt>`_.
