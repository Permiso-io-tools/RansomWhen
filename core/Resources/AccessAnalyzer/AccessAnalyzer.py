import sys

from core.Authentication.Authentication import authenticate
from core.Other.PrintOutput.PrintOutput import printOutput

class AccessAnalyzer:
    def __init__(self, profile):
        self.profile = profile
        self.client = authenticate(
            Profile=self.profile,
            AccessKey=None,
            SecretKey=None,
            SessionToken=None,
            UserAgent=None,
            Service="accessanalyzer"
        )

    def analyze_policy(self, policyDocument):
        try:
            response = self.client.validate_policy(
                maxResults=123,
                policyDocument=policyDocument,
                policyType='IDENTITY_POLICY',
            )["findings"]
            del (response['locations'])
            return response
        except:
            printOutput(f"Error analyzing policy: {sys.exc_info()}", "failure")
            return None
