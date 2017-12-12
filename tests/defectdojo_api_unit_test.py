"""
UnitTests written by Aaron Weaver <aaron.weaver@owasp.org>
as part of the OWASP DefectDojo and OWASP AppSec Pipeline Security projects

Description: Tests the functionality of the DefectDojo API.
"""
from defectdojo_api import defectdojo

import unittest
import os
from datetime import datetime

class TestDefectDojoAPI(unittest.TestCase):

    def setUp(self):
        host = 'http://localhost:8000'
        api_key = os.environ['DOJO_API_KEY']
        user = 'admin'

        """
        proxies = {
          'http': 'http://localhost:8080',
          'https': 'http://localhost:8080',
        }
        proxies=proxies
        """
        self.dd = defectdojo.DefectDojoAPI(host, api_key, user, debug=False)

    #### USER API TESTS ####
    def test_01_get_user(self):
        user = self.dd.get_user(1)
        self.assertIsNotNone(user.data['username'])

    def test_02_list_users(self):
        users = self.dd.list_users()
        #print users.data_json(pretty=True)
        #Test that the total count is not zero
        self.assertTrue(users.data["meta"]["total_count"]>0)

    #### Product API TESTS ####
    def test_03_create_product(self):
        product = self.dd.create_product("API Product Test", "Description", 1)
        self.__class__.product_id = product.id()
        self.assertIsNotNone(product.id())

    def test_04_get_product(self):
        product = self.dd.get_product(self.__class__.product_id)
        #print product.data_json(pretty=True)
        self.assertIsNotNone(product.data['name'])

    def test_05_set_product(self):
        product = self.dd.create_product("API Product Test", "Description", 1)
        new_product_id = product.id()
        self.dd.set_product(new_product_id, name="Product Update Test")
        product = self.dd.get_product(new_product_id)
        #print product.data_json(pretty=True)
        self.assertEqual("Product Update Test", product.data['name'])

    def test_06_list_products(self):
        products = self.dd.list_products()
        #print products.data_json(pretty=True)
        #Test that the total count is not zero
        self.assertTrue(products.data["meta"]["total_count"]>0)

    #### Engagement API TESTS ####
    def test_07_create_engagement(self):
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
        self.assertTrue(engagements.data["meta"]["total_count"]>0)

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
        engagement_id = 1
        test_type = 1 #1 is the API Test
        environment = 1 #1 is the Development Environment
        test = self.dd.create_test(engagement_id, test_type, environment, "2016-11-01", "2016-12-01")
        self.__class__.test_id = test.id()
        self.assertIsNotNone(test.id())

    def test_12_get_test(self):
        test = self.dd.get_test(self.__class__.test_id)
        #print test.data_json(pretty=True)
        self.assertIsNotNone(str(test.data["engagement"]))

    def test_13_list_tests(self):
        tests = self.dd.list_tests()
        #print tests.data_json(pretty=True)
        self.assertTrue(tests.data["meta"]["total_count"]>0)

    def test_14_set_test(self):
        self.dd.set_test(self.__class__.test_id, percent_complete="99")
        test = self.dd.get_test(self.__class__.test_id)
        #print test.data_json(pretty=True)
        self.assertEqual(99, test.data['percent_complete'])

    #### Findings API TESTS ####
    #Fails b/c of DojoAPI Issue
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
        finding = self.dd.get_finding(self.__class__.finding_id)
        #print finding.data_json(pretty=True)
        self.assertIsNotNone(str(finding.data["title"]))

    def test_17_list_findings(self):
        findings = self.dd.list_findings()
        #print findings.data_json(pretty=True)
        self.assertTrue(findings.data["meta"]["total_count"]>0)

    #Fails b/c of DojoAPI Issue
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
        "true", date.strftime("%Y/%m/%d"), "API")

        self.assertIsNotNone(upload_scan.id())

    #### Re-upload API Test ####
    def test_20_reupload_scan(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))

        date = datetime.now()
        upload_scan = self.dd.upload_scan(self.__class__.test_id, "Burp Scan", dir_path + "/scans/Bodgeit-burp.xml",
        "true", date.strftime("%Y/%m/%d"), "API")

        self.assertIsNotNone(upload_scan.id())

if __name__ == '__main__':
    unittest.main()
