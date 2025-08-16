import requests
import sys
import json
from datetime import datetime

class HealthPlatformAPITester:
    def __init__(self, base_url="https://great-pike.preview.emergentagent.com"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api"
        self.patient_token = None
        self.clinician_token = None
        self.patient_user = None
        self.clinician_user = None
        self.tests_run = 0
        self.tests_passed = 0

    def run_test(self, name, method, endpoint, expected_status, data=None, token=None):
        """Run a single API test"""
        url = f"{self.api_url}/{endpoint}"
        headers = {'Content-Type': 'application/json'}
        if token:
            headers['Authorization'] = f'Bearer {token}'

        self.tests_run += 1
        print(f"\n🔍 Testing {name}...")
        print(f"   URL: {url}")
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, timeout=10)
            elif method == 'POST':
                response = requests.post(url, json=data, headers=headers, timeout=10)
            elif method == 'PUT':
                response = requests.put(url, json=data, headers=headers, timeout=10)
            elif method == 'DELETE':
                response = requests.delete(url, headers=headers, timeout=10)

            success = response.status_code == expected_status
            if success:
                self.tests_passed += 1
                print(f"✅ Passed - Status: {response.status_code}")
                try:
                    response_data = response.json()
                    print(f"   Response: {json.dumps(response_data, indent=2)[:200]}...")
                except:
                    print(f"   Response: {response.text[:200]}...")
            else:
                print(f"❌ Failed - Expected {expected_status}, got {response.status_code}")
                try:
                    error_data = response.json()
                    print(f"   Error: {error_data}")
                except:
                    print(f"   Error: {response.text}")

            return success, response.json() if response.text else {}

        except Exception as e:
            print(f"❌ Failed - Error: {str(e)}")
            return False, {}

    def test_health_check(self):
        """Test basic health endpoint"""
        return self.run_test("Health Check", "GET", "health", 200)

    def test_root_endpoint(self):
        """Test root API endpoint"""
        return self.run_test("Root Endpoint", "GET", "", 200)

    def test_patient_registration(self):
        """Test patient registration"""
        timestamp = datetime.now().strftime('%H%M%S')
        patient_data = {
            "email": f"patient_{timestamp}@test.com",
            "password": "testpass123",
            "full_name": "John Patient",
            "role": "patient",
            "phone": "123-456-7890",
            "date_of_birth": "1990-01-01"
        }
        
        success, response = self.run_test(
            "Patient Registration",
            "POST",
            "register",
            200,
            data=patient_data
        )
        
        if success:
            self.patient_user = {**patient_data, "id": response.get("id")}
            return True
        return False

    def test_clinician_registration(self):
        """Test clinician registration"""
        timestamp = datetime.now().strftime('%H%M%S')
        clinician_data = {
            "email": f"doctor_{timestamp}@test.com",
            "password": "testpass123",
            "full_name": "Dr. Jane Smith",
            "role": "clinician",
            "license_number": "MD123456",
            "specialty": "Cardiology"
        }
        
        success, response = self.run_test(
            "Clinician Registration",
            "POST",
            "register",
            200,
            data=clinician_data
        )
        
        if success:
            self.clinician_user = {**clinician_data, "id": response.get("id")}
            return True
        return False

    def test_duplicate_registration(self):
        """Test duplicate email registration"""
        if not self.patient_user:
            print("❌ Skipping duplicate registration test - no patient user")
            return False
            
        duplicate_data = {
            "email": self.patient_user["email"],
            "password": "differentpass",
            "full_name": "Different Name",
            "role": "patient"
        }
        
        success, _ = self.run_test(
            "Duplicate Email Registration",
            "POST",
            "register",
            400,
            data=duplicate_data
        )
        return success

    def test_invalid_role_registration(self):
        """Test registration with invalid role"""
        invalid_data = {
            "email": "invalid@test.com",
            "password": "testpass123",
            "full_name": "Invalid User",
            "role": "invalid_role"
        }
        
        success, _ = self.run_test(
            "Invalid Role Registration",
            "POST",
            "register",
            400,
            data=invalid_data
        )
        return success

    def test_clinician_missing_fields(self):
        """Test clinician registration without required fields"""
        incomplete_data = {
            "email": "incomplete@test.com",
            "password": "testpass123",
            "full_name": "Incomplete Clinician",
            "role": "clinician"
            # Missing license_number and specialty
        }
        
        success, _ = self.run_test(
            "Clinician Missing Required Fields",
            "POST",
            "register",
            400,
            data=incomplete_data
        )
        return success

    def test_patient_login(self):
        """Test patient login"""
        if not self.patient_user:
            print("❌ Skipping patient login test - no patient user")
            return False
            
        login_data = {
            "email": self.patient_user["email"],
            "password": self.patient_user["password"]
        }
        
        success, response = self.run_test(
            "Patient Login",
            "POST",
            "login",
            200,
            data=login_data
        )
        
        if success and 'access_token' in response:
            self.patient_token = response['access_token']
            print(f"   Patient token obtained: {self.patient_token[:20]}...")
            return True
        return False

    def test_clinician_login(self):
        """Test clinician login"""
        if not self.clinician_user:
            print("❌ Skipping clinician login test - no clinician user")
            return False
            
        login_data = {
            "email": self.clinician_user["email"],
            "password": self.clinician_user["password"]
        }
        
        success, response = self.run_test(
            "Clinician Login",
            "POST",
            "login",
            200,
            data=login_data
        )
        
        if success and 'access_token' in response:
            self.clinician_token = response['access_token']
            print(f"   Clinician token obtained: {self.clinician_token[:20]}...")
            return True
        return False

    def test_invalid_login(self):
        """Test login with invalid credentials"""
        invalid_data = {
            "email": "nonexistent@test.com",
            "password": "wrongpassword"
        }
        
        success, _ = self.run_test(
            "Invalid Login",
            "POST",
            "login",
            401,
            data=invalid_data
        )
        return success

    def test_get_current_user_patient(self):
        """Test getting current user info for patient"""
        if not self.patient_token:
            print("❌ Skipping patient /me test - no token")
            return False
            
        success, _ = self.run_test(
            "Get Current User (Patient)",
            "GET",
            "me",
            200,
            token=self.patient_token
        )
        return success

    def test_get_current_user_clinician(self):
        """Test getting current user info for clinician"""
        if not self.clinician_token:
            print("❌ Skipping clinician /me test - no token")
            return False
            
        success, _ = self.run_test(
            "Get Current User (Clinician)",
            "GET",
            "me",
            200,
            token=self.clinician_token
        )
        return success

    def test_unauthorized_access(self):
        """Test accessing protected route without token"""
        success, _ = self.run_test(
            "Unauthorized Access to /me",
            "GET",
            "me",
            401
        )
        return success

    def test_patient_dashboard(self):
        """Test patient dashboard access"""
        if not self.patient_token:
            print("❌ Skipping patient dashboard test - no token")
            return False
            
        success, _ = self.run_test(
            "Patient Dashboard",
            "GET",
            "dashboard",
            200,
            token=self.patient_token
        )
        return success

    def test_clinician_dashboard(self):
        """Test clinician dashboard access"""
        if not self.clinician_token:
            print("❌ Skipping clinician dashboard test - no token")
            return False
            
        success, _ = self.run_test(
            "Clinician Dashboard",
            "GET",
            "dashboard",
            200,
            token=self.clinician_token
        )
        return success

    def test_patient_profile_access(self):
        """Test patient-only profile endpoint"""
        if not self.patient_token:
            print("❌ Skipping patient profile test - no token")
            return False
            
        success, _ = self.run_test(
            "Patient Profile Access",
            "GET",
            "patient/profile",
            200,
            token=self.patient_token
        )
        return success

    def test_clinician_patients_access(self):
        """Test clinician-only patients endpoint"""
        if not self.clinician_token:
            print("❌ Skipping clinician patients test - no token")
            return False
            
        success, _ = self.run_test(
            "Clinician Patients Access",
            "GET",
            "clinician/patients",
            200,
            token=self.clinician_token
        )
        return success

    def test_role_based_access_control(self):
        """Test role-based access control violations"""
        results = []
        
        # Patient trying to access clinician endpoint
        if self.patient_token:
            success, _ = self.run_test(
                "Patient Accessing Clinician Endpoint (Should Fail)",
                "GET",
                "clinician/patients",
                403,
                token=self.patient_token
            )
            results.append(success)
        
        # Clinician trying to access patient endpoint
        if self.clinician_token:
            success, _ = self.run_test(
                "Clinician Accessing Patient Endpoint (Should Fail)",
                "GET",
                "patient/profile",
                403,
                token=self.clinician_token
            )
            results.append(success)
        
        return all(results) if results else False

def main():
    print("🏥 Starting Patient-Clinician Health Data Platform API Tests")
    print("=" * 60)
    
    tester = HealthPlatformAPITester()
    
    # Basic connectivity tests
    print("\n📡 CONNECTIVITY TESTS")
    tester.test_health_check()
    tester.test_root_endpoint()
    
    # Registration tests
    print("\n👤 REGISTRATION TESTS")
    tester.test_patient_registration()
    tester.test_clinician_registration()
    tester.test_duplicate_registration()
    tester.test_invalid_role_registration()
    tester.test_clinician_missing_fields()
    
    # Authentication tests
    print("\n🔐 AUTHENTICATION TESTS")
    tester.test_patient_login()
    tester.test_clinician_login()
    tester.test_invalid_login()
    
    # Authorization tests
    print("\n🛡️ AUTHORIZATION TESTS")
    tester.test_get_current_user_patient()
    tester.test_get_current_user_clinician()
    tester.test_unauthorized_access()
    
    # Dashboard tests
    print("\n📊 DASHBOARD TESTS")
    tester.test_patient_dashboard()
    tester.test_clinician_dashboard()
    
    # Role-specific endpoint tests
    print("\n🎭 ROLE-SPECIFIC ENDPOINT TESTS")
    tester.test_patient_profile_access()
    tester.test_clinician_patients_access()
    
    # Role-based access control tests
    print("\n🚫 ROLE-BASED ACCESS CONTROL TESTS")
    tester.test_role_based_access_control()
    
    # Print final results
    print("\n" + "=" * 60)
    print(f"📊 FINAL RESULTS: {tester.tests_passed}/{tester.tests_run} tests passed")
    
    if tester.tests_passed == tester.tests_run:
        print("🎉 All tests passed! Backend API is working correctly.")
        return 0
    else:
        failed_tests = tester.tests_run - tester.tests_passed
        print(f"⚠️  {failed_tests} test(s) failed. Please check the issues above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())