DefectDojo API Examples
=======================

The following examples are available in this directory:

- Dojo CI CD (dojo_ci_cd.py): Automatically imports a scanner file into a Dojo Engagement, reports on new issues discovered in the build, total vulnerability count and thresholds can be set to determine if the build should pass or fail.
- Dojo Populate (dojo_populate.py): Populates Dojo with sample data, which includes products, engagements, tests and importing scan files.
- Dojo Product (dojo_product.py): Demonstrates creating and querying Dojo products.

Quick Start
-----------

- Install with pip (recommended): :code:`pip install defectdojo_api`
- Clone the repository: :code:`git clone https://github.com/aaronweaver/defectdojo_api`
- CD into examples

Dojo CI CD (dojo_ci_cd.py)
--------------------------
A simple example of integrating Dojo in your CI/CD pipeline.

Pass in the following:
- product: ID of the product in DefectDojo
- file: Path to the scanner output file
- high, medium or low: Maximum number of vulnerabilities allowed to Pass or Fail a build
- host: URL to Defect Dojo
- api_key: Defect Dojo API Key
- User: User associated with the API Key

.. code-block:: bash

    dojo_ci_cd.py --product=1 --file "/tests/scans/Bodgeit-burp.xml" --scanner="Burp Scan" --high=0 --host=http://localhost:8000 --api_key=<api_key> --user=admin

Dojo Populate
--------------------------
Populate Dojo with sample data. *Note it is not recommend to run this on a production server as it will create test data.

- :code:`export DOJO_API_KEY=<apikey>`
- :code:`python dojo_product.py`

Dojo Product
--------------------------
Demonstrates creating and querying Dojo products.

- :code:`export DOJO_API_KEY=<apikey>`
- :code:`python dojo_populate.py`


Supporting information for each method available can be found in the `documentation <https://defectdojo-api.readthedocs.io>`_.

Bugs and Feature Requests
-------------------------

Have a bug or a feature request? Please first search for existing and closed issues. If your problem or idea is not addressed yet, `please open a new issue <https://github.com/aaronweaver/defectdojo_api/issues/new>`_.

Copyright and License
---------------------

- `Licensed under MIT <https://github.com/aaronweaver/defectdojo_api/blob/master/LICENSE.txt>`_.
