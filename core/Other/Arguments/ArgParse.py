import argparse
from core.Other.Arguments.Banner import printBanner

def parseArgs():
    printBanner()
    parser = argparse.ArgumentParser(description='RansomWhen???')
    subparsers = parser.add_subparsers(dest='provider',
                                       help="Select the check on the account (the choices are IDENTITIES, EVENTS)"
                                       )
    # -----------------------------------------------------------
    # IDENTITIES
    # -----------------------------------------------------------
    identities_parser = subparsers.add_parser('IDENTITIES', help='IDENTITIES specific arguments')
    identities_parser.add_argument('-p', '--profile',
                        help="The AWS Profile Name to authenticate as. Default is 'default'. The credentials need to have access to iam:ListUsers, iam:GetUser, iam:ListUserPolicies, iam:ListAttachedUserPolicies, iam:ListGroupsForUser, iam:ListGroupPolicies, iam:ListAttachedGroupPolicies, cloudtrail:LookupEvents, iam:GetPolicyVersion, iam:GetPolicy",
                        default="default",
                        required=True)
    identities_parser.add_argument('-i', '--identity-name',
                        help="The AWS Identity to test. If not set, a list of users and roles will be taken using iam:ListUsers and iam:ListRoles")
    identities_parser.add_argument('-it', '--identity-type', help="The AWS Identity Type. Should be USER or ROLE",
                        choices=['USER', 'ROLE'])
    identities_parser.add_argument('-id', '--include-denied', help="By default, the tool will only list the identities that will allow at least one Permission from the scenarios.json file. If you put this flag, it will include identities which are not allowed any privileges too", action="store_true")
    identities_parser.add_argument('-v', '--verbose', help="Use this flag to also print out the verbose text", action="store_true")

    # -----------------------------------------------------------
    # EVENTS
    # -----------------------------------------------------------
    events_parser = subparsers.add_parser('EVENTS', help='EVENTS specific arguments')
    events_parser.add_argument('-p', '--profile',
                        help="The AWS Profile Name to authenticate as. Default is 'default'. The credentials need to have access to iam:ListUsers, iam:GetUser, iam:ListUserPolicies, iam:ListAttachedUserPolicies, iam:ListGroupsForUser, iam:ListGroupPolicies, iam:ListAttachedGroupPolicies, cloudtrail:LookupEvents, iam:GetPolicyVersion, iam:GetPolicy",
                        default="default",
                        required=True)
    events_parser.add_argument('-i', '--identity-name',
                                   help="The AWS Identity to test. If not set, a list of users and roles will be taken using iam:ListUsers and iam:ListRoles")
    events_parser.add_argument('-v', '--verbose', help="Use this flag to also print out the verbose text",
                                   action="store_true")
    args = parser.parse_args()
    return args



