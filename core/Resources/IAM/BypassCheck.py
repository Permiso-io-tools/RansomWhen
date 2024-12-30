import sys

import botocore

from core.Authentication.Authentication import authenticate
from core.Other.PrintOutput.PrintOutput import printOutput
from core.Resources.CloudTrail.GetCTEvents import GetCTEvents

class BypassCheck:
    def __init__(self, profile):
        self.profile = profile
        self.client = authenticate(
            Profile=self.profile,
            AccessKey=None,
            SecretKey=None,
            SessionToken=None,
            UserAgent=None,
            Service="iam"
        )

    #--------------------------------------------------------
    #                Users
    #--------------------------------------------------------

    def list_roles(self):
        printOutput("Listing Roles", "loading")
        try:
            users = self.client.list_roles()['Roles']
            printOutput(f"Found {str(len(users))} Roles in the infrastructure", "success")
            if len(users) > 0:
                retusers = [i['RoleName'] for i in users]
                return retusers
            else:
                return []
        except:
            printOutput(f"Error listing Roles: {sys.exc_info()}", "failure")
            return None

    def get_attached_role_policies(self, role):
        printOutput(f"Listing Attached Policies for role {role}", "loading")
        try:
            policies = self.client.list_attached_role_policies(RoleName=role)['AttachedPolicies']
            printOutput(f"Found {str(len(policies))} attached to {role}", "success")
            policydocs = []
            if len(policies) > 0:
                for policyarn in policies:
                    #if policyarn['PolicyArn'] == "arn:aws:iam::aws:policy/AWSCompromisedKeyQuarantineV2" or \
                    #policyarn['PolicyArn'] == "arn:aws:iam::aws:policy/AWSCompromisedKeyQuarantine":
                    #    continue
                    try:
                        policyVersion = self.client.get_policy(PolicyArn=policyarn['PolicyArn'])['Policy']["DefaultVersionId"]
                        policyDoc = self.client.get_policy_version(PolicyArn=policyarn['PolicyArn'], VersionId=policyVersion)['PolicyVersion']['Document']
                        policydocs.append(policyDoc)
                    except Exception as e:
                        printOutput(
                            message=f"[*] Policy {policyarn} error: {str(e)}", type="error"
                        )
            return policydocs
        except:
            printOutput(f"Error listing Attached policies for role {role}: {sys.exc_info()}", "failure")
            return None

    def get_role_permission_boundary(self, role):
        printOutput(f"Getting Permission Boundary for role {role}", "loading")
        try:
            policies = self.client.get_role(RoleName=role)['Role']
            printOutput(f"Got Permission Boundary  attached to {role}", "success")
            policyDoc = None
            if 'PermissionsBoundary' in policies:
                policyarn = policies['PermissionsBoundary']['PermissionsBoundaryArn']
                try:
                    policyVersion = self.client.get_policy(PolicyArn=policyarn)['Policy']["DefaultVersionId"]
                    policyDoc = self.client.get_policy_version(PolicyArn=policyarn, VersionId=policyVersion)['PolicyVersion']['Document']
                except Exception as e:
                    printOutput(
                        message=f"[*] Policy {policyarn} error: {str(e)}", type="error"
                    )
            return policyDoc
        except self.client.exceptions.NoSuchEntityException:
            printOutput(f"role {role} does not exist", "failure")
            exit()

        except:
            printOutput(f"Error Getting Permission Boundary for role {role}: {sys.exc_info()}", "failure")
            return None

    def get_role_inline_policies(self, role):
        printOutput(f"Listing Inline Policies for role {role}", "loading")
        try:
            policies = self.client.list_role_policies(RoleName=role)['PolicyNames']
            printOutput(f"Found {str(len(policies))} inline policies to {role}", "success")
            policydocs = []
            for policy in policies:
                policydocs.append(self.client.get_role_policy(RoleName=role, PolicyName=policy)['PolicyDocument'])
            return policydocs
        except:
            printOutput(f"Error listing Inline policies for role {role}: {sys.exc_info()}", "failure")
            return None

    def list_users(self):
        printOutput("Listing Users", "loading")
        try:
            users = self.client.list_users()['Users']
            printOutput(f"Found {str(len(users))} Users in the infrastructure", "success")
            if len(users) > 0:
                retusers = [i['UserName'] for i in users]
                return retusers
            else:
                return []
        except:
            printOutput(f"Error listing users: {sys.exc_info()}", "failure")
            return None

    def get_attached_user_policies(self, user):
        printOutput(f"Listing Attached Policies for user {user}", "loading")
        try:
            policies = self.client.list_attached_user_policies(UserName=user)['AttachedPolicies']
            printOutput(f"Found {str(len(policies))} attached to {user}", "success")
            policydocs = []
            if len(policies) > 0:
                for policyarn in policies:
                    #if policyarn['PolicyArn'] == "arn:aws:iam::aws:policy/AWSCompromisedKeyQuarantineV2" or \
                    #policyarn['PolicyArn'] == "arn:aws:iam::aws:policy/AWSCompromisedKeyQuarantine":
                    #    continue
                    try:
                        policyVersion = self.client.get_policy(PolicyArn=policyarn['PolicyArn'])['Policy']["DefaultVersionId"]
                        policyDoc = self.client.get_policy_version(PolicyArn=policyarn['PolicyArn'], VersionId=policyVersion)['PolicyVersion']['Document']
                        policydocs.append(policyDoc)
                    except Exception as e:
                        printOutput(
                            message=f"[*] Policy {policyarn} error: {str(e)}", type="error"
                        )
            return policydocs
        except:
            printOutput(f"Error listing Attached policies for user {user}: {sys.exc_info()}", "failure")
            return None

    def get_user_permission_boundary(self, user):
        printOutput(f"Getting Permission Boundary for user {user}", "loading")
        try:
            policies = self.client.get_user(UserName=user)['User']
            printOutput(f"Got Permission Boundary  attached to {user}", "success")
            policyDoc = None
            if 'PermissionsBoundary' in policies:
                policyarn = policies['PermissionsBoundary']['PermissionsBoundaryArn']
                try:
                    policyVersion = self.client.get_policy(PolicyArn=policyarn)['Policy']["DefaultVersionId"]
                    policyDoc = self.client.get_policy_version(PolicyArn=policyarn, VersionId=policyVersion)['PolicyVersion']['Document']
                except Exception as e:
                    printOutput(
                        message=f"[*] Policy {policyarn} error: {str(e)}", type="error"
                    )
            return policyDoc
        except self.client.exceptions.NoSuchEntityException:
            printOutput(f"User {user} does not exist", "failure")
            exit()

        except:
            printOutput(f"Error Getting Permission Boundary for user {user}: {sys.exc_info()}", "failure")
            return None

    def get_user_inline_policies(self, user):
        printOutput(f"Listing Inline Policies for user {user}", "loading")
        try:
            policies = self.client.list_user_policies(UserName=user)['PolicyNames']
            printOutput(f"Found {str(len(policies))} inline policies to {user}", "success")
            policydocs = []
            for policy in policies:
                policydocs.append(self.client.get_user_policy(UserName=user, PolicyName=policy)['PolicyDocument'])
            return policydocs
        except:
            printOutput(f"Error listing Inline policies for user {user}: {sys.exc_info()}", "failure")
            return None

    def get_user_groups(self, user):
        printOutput(f"Listing Groups for user {user}", "loading")
        try:
            groups = self.client.list_groups_for_user(UserName=user)['Groups']
            printOutput(f"Found {str(len(groups))} attached to {user}", "success")
            return groups
        except:
            printOutput(f"Error listing groups for user {user}: {sys.exc_info()}", "failure")
            return None

    def get_attached_group_policies(self, group):
        printOutput(f"Listing Attached Policies for group {group['GroupName']}", "loading")
        try:
            policies = self.client.list_attached_group_policies(GroupName=group['GroupName'])['AttachedPolicies']
            printOutput(f"Found {str(len(policies))} attached to {group['GroupName']}", "success")
            policydocs = []
            if len(policies) > 0:
                for policyarn in policies:
                    try:
                        policyVersion = self.client.get_policy(PolicyArn=policyarn['PolicyArn'])['Policy'][
                            "DefaultVersionId"]
                        policyDoc = self.client.get_policy_version(PolicyArn=policyarn['PolicyArn'], VersionId=policyVersion)[
                            'PolicyVersion']['Document']
                        policydocs.append(policyDoc)
                    except Exception as e:
                        printOutput(
                            message=f"[*] Policy {policyarn} error: {str(e)}", type="error"
                        )
            return policydocs
        except:
            printOutput(f"Error listing Attached policies for group {group['GroupName']}: {sys.exc_info()}", "failure")
            return None

    def get_group_inline_policies(self, group):
        printOutput(f"Listing Inline Policies for group {group['GroupName']}", "loading")
        policydocs = []
        try:
            policies = self.client.list_group_policies(GroupName=group['GroupName'])['PolicyNames']
            printOutput(f"Found {str(len(policies))} inline policies to {group['GroupName']}", "success")
            for policy in policies:
                policydocs.append(self.client.get_group_policy(GroupName=group['GroupName'], PolicyName=policy)['PolicyDocument'])
            return policydocs
        except Exception as e:
            printOutput(f"Error listing Inline policies for group {group['GroupName']}: {str(e)}", "failure")
            return None

    def list_all_identities(self):
        users = self.list_users()
        roles = self.list_roles()
        return list(set(users + roles))

    def validate_policy(self, policyDocument):
        try:
            response = self.client.validate_policy(
                maxResults=123,
                policyDocument=policyDocument,
                policyType='IDENTITY_POLICY',
            )["findings"]
            del (response['locations'])
            return response
        except Exception as e:
            printOutput(f"Error analyzing policy: {str(e)}", "failure")
            return None

    def find_permissions_in_policy(self, policyDocumentList, SCENARIOS, permissionBoundaryList):
        returnDict = {}
        for name, scenario in SCENARIOS.items():
            returnDict[name] = {
                "status": "",
                "allowed": [],
                "denied": []
            }
            try:
                #print(permissionBoundaryList)
                if permissionBoundaryList is not None:
                    evaluationResponse = self.client.simulate_custom_policy(
                        PolicyInputList=policyDocumentList,
                        PermissionsBoundaryPolicyInputList=permissionBoundaryList,
                        ActionNames=scenario
                    )

                else:
                    evaluationResponse = self.client.simulate_custom_policy(
                        PolicyInputList=policyDocumentList,
                        ActionNames=scenario
                    )

                for evaluation in evaluationResponse['EvaluationResults']:
                    if evaluation['EvalDecision'] == "allowed":
                        returnDict[name]['allowed'].append(evaluation['EvalActionName'])
                    else:
                        returnDict[name]['denied'].append(evaluation['EvalActionName'])

                if len(returnDict[name]['denied'] ) > 0 and len(returnDict[name]['allowed']) > 0:
                    returnDict[name]['status'] = f"partially"
                elif len(returnDict[name]['denied']) == 0:
                    #if checkall:
                    #    returnDict[name]['allowed'] = [f"{name}:*"]
                    returnDict[name][
                        'status'] = f"allowed"
                else:
                    returnDict[name][
                        'status'] = f"denied"

            except Exception as e:
                returnDict[name]['status'] = f"Error analyzing policy: {str(e)}"

        return returnDict

    def filterInterestingIdentities(self, evaluationResponse):
        for name, scenario in evaluationResponse.items():
            if scenario['status'] == 'allowed' or scenario['status'] == 'partially':
                return True
        return False