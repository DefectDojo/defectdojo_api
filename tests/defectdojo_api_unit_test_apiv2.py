"""
UnitTests written by Aaron Weaver <aaron.weaver@owasp.org>
as part of the OWASP DefectDojo and OWASP AppSec Pipeline Security projects

Description: Tests the functionality of the DefectDojo API.
"""
from defectdojo_api import defectdojo_apiv2 as defectdojo

import unittest
import os
from datetime import datetime

class TestDefectDojoAPI(unittest.TestCase):

    def setUp(self):
        host = os.environ['DOJO_URL']
        api_key = os.environ['DOJO_API_KEY']
        user = 'admin'

        """
        proxies = {
          'http': 'http://localhost:8080',
          'https': 'http://localhost:8080',
        }
        proxies=proxies
        """
        self.dd = defectdojo.DefectDojoAPIv2(host, api_key, user, api_version="v2", verify_ssl=False, debug=True)

    #### USER API TESTS ####
    def test_01_get_user(self):
        user = self.dd.get_user(1)
        self.assertIsNotNone(user.data['username'])

    def test_02_list_users(self):
        users = self.dd.list_users()
        #print users.data_json(pretty=True)
        #Test that the total count is not zero
        self.assertTrue(users.data["count"]>0)

    #### Product API TESTS ####
    @unittest.skip
    def test_03_create_product(self):
        product = self.dd.create_product("_DD Python API Wrapper unit tests", "Description", 1)
        self.__class__.product_id = product.id()
        self.assertIsNotNone(product.id())

    def test_04_get_product(self):
        self.__class__.product_id = 41
        product = self.dd.get_product(self.__class__.product_id)
        #print product.data_json(pretty=True)
        self.assertIsNotNone(product.data['name'])

    @unittest.skip
    def test_05_set_product(self):
        product = self.dd.create_product("_DD Python API Wrapper unit tests", "Description", 1)
        new_product_id = product.id()
        self.dd.set_product(new_product_id, name="_DD Python API Wrapper unit tests2")
        product = self.dd.get_product(new_product_id)
        #print product.data_json(pretty=True)
        self.assertEqual("Product Update Test", product.data['name'])

    def test_06_list_products(self):
        products = self.dd.list_products()
        #print products.data_json(pretty=True)
        #Test that the total count is not zero
        self.assertTrue(products.data["count"]>0)

    #### Engagement API TESTS ####
    def test_07_create_engagement(self):
        print("test 07 create engagement")
        product_id = self.__class__.product_id
        user_id = 1
        engagement = self.dd.create_engagement("API Engagement", product_id, user_id, "In Progress", "2016-11-01", "2016-12-01")
        self.__class__.engagement_id = engagement.id()
        self.assertIsNotNone(engagement.id())

    def test_08_get_engagement(self):
        engagement = self.dd.get_engagement(self.__class__.engagement_id)
        #print engagement.data_json(pretty=True)
        self.assertIsNotNone(str(engagement.data["name"]))

    def test_09_list_engagements(self):
        engagements = self.dd.list_engagements()
        #print engagements.data_json(pretty=True)
        self.assertTrue(engagements.data["count"]>0)

    #Note: Fails b/c of issue with DefectDojo's API
    def test_10_set_engagement(self):
        user_id = 1
        product_id = self.__class__.product_id

        engagement = self.dd.create_engagement("API Engagement", product_id, user_id, "In Progress", "2016-11-01", "2016-12-01")
        new_engagement_id = engagement.id()
        self.dd.set_engagement(new_engagement_id, name="Engagement Update Test")
        engagement = self.dd.get_engagement(new_engagement_id)
        #print engagement.data_json(pretty=True)
        self.assertEqual("Engagement Update Test", engagement.data['name'])

    #### Test API TESTS ####
    def test_11_create_test(self):
        print("test_11_create_test")
        engagement_id = self.__class__.engagement_id
        test_type = 1 #1 is the API Test
        environment = 1 #1 is the Development Environment
        test = self.dd.create_test(engagement_id, test_type, environment, "2019-04-01T00:00", "2019-05-01T00:00")
        self.__class__.test_id = test.id()
        self.assertIsNotNone(test.id())

    def test_12_get_test(self):
        test = self.dd.get_test(self.__class__.test_id)
        #print test.data_json(pretty=True)
        self.assertIsNotNone(str(test.data["engagement"]))

    def test_13_list_tests(self):
        tests = self.dd.list_tests()
        #print tests.data_json(pretty=True)
        self.assertTrue(tests.data["count"]>0)


    @unittest.skip
    #Fails b/c of DojoAPI Issue
    def test_14_set_test(self):
        print("test_14_set_test")
        self.dd.set_test(self.__class__.test_id, percent_complete="99")
        test = self.dd.get_test(self.__class__.test_id)
        #print test.data_json(pretty=True)
        self.assertEqual(99, test.data['percent_complete'])

    #### Findings API TESTS ####
    #Fails b/c of DojoAPI Issue
    @unittest.skip
    def test_15_create_finding(self):
        cwe = 25
        product_id = self.__class__.product_id
        engagement_id = self.__class__.engagement_id
        test_id = self.__class__.test_id
        user_id = 1
        finding = self.dd.create_finding("API Created", "Description", "Critical", cwe, "2016-11-01", product_id, engagement_id, test_id, user_id, "None", "true", "false", "References")
        self.__class__.finding_id = finding.id()
        self.assertIsNotNone(finding.id())

    #Fails b/c of DojoAPI Issue
    def test_16_get_finding(self):
        self.__class__.finding_id = 2393
        finding = self.dd.get_finding(self.__class__.finding_id)
        #print finding.data_json(pretty=True)
        self.assertIsNotNone(str(finding.data["title"]))

    def test_17_list_findings(self):
        findings = self.dd.list_findings()
        #print findings.data_json(pretty=True)
        self.assertTrue(findings.data["count"]>0)

    #Fails b/c of DojoAPI Issue
    @unittest.skip
    def test_18_set_finding(self):
        self.dd.set_finding(self.__class__.finding_id, self.__class__.product_id, self.__class__.engagement_id,
        test_id, title="API Finding Updates")
        finding = self.dd.get_finding(1)
        #print test.data_json(pretty=True)
        self.assertEqual("API Finding Updates", finding.data['title'])

    #### Upload API TESTS ####
    def test_19_upload_scan(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))

        date = datetime.now()
        upload_scan = self.dd.upload_scan(self.__class__.engagement_id, "Burp Scan", dir_path + "/scans/Bodgeit-burp.xml",
        "true", "false", "false", "false", date.strftime("%Y-%m-%d"), "API")

        #upload_scan = self.dd.upload_scan(self.__class__.engagement_id, "NPM Audit Scan", dir_path + "/report.json",
        #"true", date.strftime("%Y-%m-%d"), "API")

        # response doesn't contain an id, so check for engagement instead
        self.assertIsNotNone(upload_scan.data["engagement"])

    #### Re-upload API Test ####
    #Fails b/c of DojoAPI Issue with no id in response of test_19
    @unittest.skip
    def test_20_reupload_scan(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))

        date = datetime.now()
        upload_scan = self.dd.upload_scan(self.__class__.test_id, "Burp Scan", dir_path + "/scans/Bodgeit-burp.xml",
        "true", date.strftime("%Y-%m-%d"), "API")

        # response doesn't contain an id, so check for engagement instead
        self.assertIsNotNone(upload_scan.data["engagement"])

if __name__ == '__main__':
    unittest.main()
