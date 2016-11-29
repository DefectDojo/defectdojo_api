from defectdojo_api import defectdojo

import unittest
import os

class TestDefectDojoAPI(unittest.TestCase):

    def setUp(self):
        host = 'http://localhost:8000'
        api_key = os.environ['DOJO_API_KEY']
        user = 'admin'

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
        self.assertIsNotNone(product.id())

    def test_04_get_product(self):
        product = self.dd.get_product(1)
        #print product.data_json(pretty=True)
        self.assertIsNotNone(product.data['name'])

    def test_05_set_product(self):
        self.dd.set_product(1, name="Product Update Test")
        product = self.dd.get_product(1)
        #print product.data_json(pretty=True)
        self.assertEqual("Product Update Test", product.data['name'])

    def test_06_list_products(self):
        products = self.dd.list_products()
        #print products.data_json(pretty=True)
        #Test that the total count is not zero
        self.assertTrue(products.data["meta"]["total_count"]>0)

    #### Engagement API TESTS ####
    def test_07_create_engagement(self):
        product_id = 1
        user_id = 1
        engagement = self.dd.create_engagement("API Engagement", product_id, user_id, "In Progress", "2016-11-01", "2016-12-01")
        self.assertIsNotNone(engagement.id())

    def test_08_get_engagement(self):
        engagement = self.dd.get_engagement(1)
        #print engagement.data_json(pretty=True)
        self.assertIsNotNone(str(engagement.data["name"]))

    def test_09_list_engagements(self):
        engagements = self.dd.list_engagements()
        #print engagements.data_json(pretty=True)
        self.assertTrue(engagements.data["meta"]["total_count"]>0)

    def test_10_set_engagement(self):
        self.dd.set_engagement(1, name="Engagement Update Test")
        engagement = self.dd.get_engagement(1)
        #print engagement.data_json(pretty=True)
        self.assertEqual("Engagement Update Test", engagement.data['name'])

    #### Test API TESTS ####
    def test_11_create_test(self):
        engagement_id = 1
        test_type = 1 #1 is the API Test
        environment = 1 #1 is the Development Environment
        test = self.dd.create_test(engagement_id, test_type, environment, "2016-11-01", "2016-12-01")
        self.assertIsNotNone(test.id())

    def test_12_get_test(self):
        test = self.dd.get_test(1)
        #print test.data_json(pretty=True)
        self.assertIsNotNone(str(test.data["engagement"]))

    def test_13_list_tests(self):
        tests = self.dd.list_tests()
        #print tests.data_json(pretty=True)
        self.assertTrue(tests.data["meta"]["total_count"]>0)

    def test_14_set_test(self):
        self.dd.set_test(1, percent_complete="99")
        test = self.dd.get_test(1)
        #print test.data_json(pretty=True)
        self.assertEqual(99, test.data['percent_complete'])

    #### Findings API TESTS ####
    def test_15_create_finding(self):
        cwe = 25
        product_id = 1
        engagement_id = 1
        test_id = 1
        user_id = 1
        finding = self.dd.create_finding("API Created", "Description", "Critical", cwe, "2016-11-01", product_id, engagement_id, test_id, user_id, "None", "true", "false", "References")
        self.assertIsNotNone(finding.id())

    def test_16_get_finding(self):
        finding = self.dd.get_finding(1)
        #print finding.data_json(pretty=True)
        self.assertIsNotNone(str(finding.data["title"]))

    def test_17_list_findings(self):
        findings = self.dd.list_findings()
        #print findings.data_json(pretty=True)
        self.assertTrue(findings.data["meta"]["total_count"]>0)

    def test_18_set_finding(self):
        self.dd.set_finding(1, 1, 1, 1, title="API Finding Updates")
        finding = self.dd.get_finding(1)
        #print test.data_json(pretty=True)
        self.assertEqual("API Finding Updates", finding.data['title'])

    #### Upload API TESTS ####
    def test_19_upload_scan(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        engagement_id = 1
        upload_scan = self.dd.upload_scan(engagement_id, "Burp Scan", dir_path + "/scans/Bodgeit-burp.xml",
        "true", "01/11/2016", "Burp Upload")
        #print upload_scan.data_json(pretty=True)
        self.assertEqual("Bodgeit-burp.xml", upload_scan.data['file'])

if __name__ == '__main__':
    unittest.main()
