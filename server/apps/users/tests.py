print("Loading tests.py")

from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient
from .models import User, OTP

class OTPTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.register_url = reverse('farmer-register')
        self.verify_otp_url = reverse('verify-otp')
        self.user_data = {
            "name": "John Doe",
            "email": "jnyarko342@gmail.com",
            "password": "wise1234",
            "password2": "wise1234",
            "role": "customer"
        }

    def test_register_and_verify_otp(self):
        # Register a new user
        response = self.client.post(self.register_url, self.user_data, format='json')
        print(response.content)  # Print the response content for debugging
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        user = User.objects.get(email=self.user_data['email'])
        self.assertFalse(user.is_active)

        # Get the OTP from the database
        otp = OTP.objects.get(user=user)
        otp_code = otp.otp_code

        # Verify the OTP
        verify_data = {
            "email": self.user_data['email'],
            "otp_code": otp_code
        }
        response = self.client.post(self.verify_otp_url, verify_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Check if the user is now active
        user.refresh_from_db()
        self.assertTrue(user.is_active)