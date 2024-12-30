import argparse

from core.Other.Arguments.Banner import printBanner

def parseArgs():
    printBanner()
    parser = argparse.ArgumentParser(
        prog='DetentionDodger',
        description='DetentionDodger is a tool designed to find users whose credentials have been leaked/compromised and the impact they have on the target',
    )

    parser.add_argument('-p', '--profile', help="The AWS Profile Name to authenticate as. Default is 'default'. The credentials need to have access to iam:ListUsers, iam:GetUser, iam:ListUserPolicies, iam:ListAttachedUserPolicies, iam:ListGroupsForUser, iam:ListGroupPolicies, iam:ListAttachedGroupPolicies, cloudtrail:LookupEvents, iam:GetPolicyVersion, iam:GetPolicy", default="default")
    parser.add_argument('-i', '--identity-name', help="The AWS Identity to test. If not set, a list of users and roles will be taken using iam:ListUsers and iam:ListRoles")
    parser.add_argument('-it', '--identity-type', help="The AWS Identity Type. Should be USER or ROLE", choices=['USER', 'ROLE'])
    parser.add_argument('-v', '--verbose', help="Include denied identities too", action="store_true")

    args = parser.parse_args()
    return args

