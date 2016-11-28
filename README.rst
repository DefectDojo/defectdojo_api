DefectDojo API
=============

A Python API wrapper to facilitate interactions with `DefectDojo <https://github.com/OWASP/django-DefectDojo>`_.

This package implements API functionality available within Dojo.

Quick Start
-----------

Several quick start options are available:

- Install with pip (recommended): :code:`pip install defect_dojo_api`
- `Download the latest release <https://github.com/aaronweaver/dojo_api/releases/latest>`_
- Clone the repository: :code:`git clone https://github.com/aaronweaver/defect_dojo_api`

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

    # You can also specify a local cert to use as client side certificate, as a
    # single file (containing the private key and the certificate) or as a tuple
    # of both file's path.
    # cert=('/path/server.crt', '/path/key')
    # dd = defectdojo.DefectDojoAPI(host, api_key, user, cert=cert)

    #List Products
    products = dd.get_products()

    print(products.data_json(pretty=True))  # Decoded JSON object

    for product in products.data["objects"]:
        print(product['name'])  # Print the name of each product

Supporting information for each method available can be found in the `documentation <https://github.com/aaronweaver/DefectDojo_api/tree/master/docs>`_.

Bugs and Feature Requests
-------------------------

Have a bug or a feature request? Please first search for existing and closed issues. If your problem or idea is not addressed yet, `please open a new issue <https://github.com/aaronweaver/Defect_Dojo_api/issues/new>`_.

Copyright and License
---------------------

- `Licensed under MIT <https://github.com/aaronweaver/Defect_Dojo_api/blob/master/LICENSE.txt>`_.
