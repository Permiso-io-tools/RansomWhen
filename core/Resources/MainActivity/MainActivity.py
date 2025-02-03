from core.Other.PrintOutput.PrintOutput import printOutput
from core.Other.TablePrint import TablePrint
from core.Resources.IAM.BypassCheck import BypassCheck
from core.Resources.CloudTrail.GetCTEvents import GetCTEvents
import json
from core.Resources.OutputDump.OutputDump import dumpCSV, dumpEventsCSV
from core.Authentication.Authentication import authenticate
import botocore

class ListEvents:
    def __init__(self, profile, accountID, verbose, identity_name):
        self.profile = profile
        self.verbose = verbose
        self.bypassCheckObj = BypassCheck(profile=profile, verbose=self.verbose)
        self.cloudTrailObj = GetCTEvents(profile=profile, verbose=self.verbose)
        self.accountID = accountID
        self.identity_name = identity_name

    def list_events(self):
        try:
            scenariofile = "scenarios/events.json"
            with open(scenariofile) as scenariosfile:
                SCENARIOS = json.load(scenariosfile)

            if self.identity_name is not None:
                iamClient = authenticate(Profile=self.profile, AccessKey=None, SecretKey=None, SessionToken=None, UserAgent=None, Service="iam")
                if iamClient is None:
                    exit()
                try:
                    userarn = iamClient.get_user(UserName=self.identity_name)['User']["Arn"]
                    users = [userarn]
                except iamClient.exceptions.NoSuchEntityException:
                    try:
                        userarn = \
                        authenticate(Profile=self.profile, AccessKey=None, SecretKey=None, SessionToken=None, UserAgent=None,
                                     Service="iam").get_role(RoleName=self.identity_name)['Role']["Arn"]
                        users = [userarn]
                    except iamClient.exceptions.NoSuchEntityException:
                        printOutput(message=f"Identity {self.identity_name} does not exist on this account", type="failure")
                        exit()

                    except Exception as e:
                        printOutput(message=f"Error checking if identity exists: {str(e)}", type="failure")
                        exit()

                except Exception as e:
                    printOutput(message=f"Error checking if identity exists: {str(e)}", type="failure")
                    exit()

            else:
                users = self.bypassCheckObj.list_users_arn()
                users.extend(self.bypassCheckObj.list_roles_arn())

            if users is not None and len(users) > 0:
                for user in users:
                    printOutput("----------------------------------------------------", type="loading", verbose=True)
                    printOutput(f"           {user}", type="loading", verbose=True)
                    printOutput("----------------------------------------------------", type="loading", verbose=True)
                    allidentityevents = []
                    for eventname, eventAttributes in self.cloudTrailObj.eventsJSON.items():
                        allidentityevents.extend(self.cloudTrailObj.getCTAPIEvents(identityArn=user, eventName=eventname))

                    tablePrintObj = TablePrint(self.verbose)
                    rolefields = tablePrintObj.eventTableprint(allidentityevents)
                    dumpEventsCSV(rolefields, self.accountID, user.split("/")[-1])
        except KeyboardInterrupt:
            exit()

        except Exception as e:
            printOutput(f"Error looking at events: {str(e)}", "failure")



class IdentitiesEnumeration:
    def __init__(self, profile, accountID, args):
        self.bypassCheckObj = BypassCheck(profile=profile, verbose=args.verbose)
        #self.cloudTrailObj = GetCTEvents(profile=profile)
        self.accountID = accountID
        self.identity = args.identity_name
        self.identitytype = args.identity_type
        self.include_denied = args.include_denied
        self.verbose = args.verbose

    def identities_enumeration(self):
        scenariofile = "scenarios/scenarios.json"

        with open(scenariofile) as scenariosfile:
            SCENARIOS = json.load(scenariosfile)

        if self.identity is None:
            users = self.bypassCheckObj.list_users()
            roles = self.bypassCheckObj.list_roles()
        else:
            if self.identitytype == "USER":
                users = [self.identity]
                roles = None
            else:
                roles = [self.identity]
                users = None

        if users is not None and len(users) > 0:
            for user in users:
                printOutput("----------------------------------------------------", type="loading", verbose=True)
                printOutput(f"           {user}", type="loading", verbose=True)
                printOutput("----------------------------------------------------", type="loading", verbose=True)
                policyDefinition = {
                    "Policies": []
                }

                userPermissionBoundary = self.bypassCheckObj.get_user_permission_boundary(user)

                if userPermissionBoundary is not None:
                    userPermissionBoundary = [json.dumps(userPermissionBoundary)]

                attachedPolices = self.bypassCheckObj.get_attached_user_policies(user)
                if attachedPolices is not None:
                    policyDefinition["Policies"] = attachedPolices

                inlinePolices = self.bypassCheckObj.get_user_inline_policies(user)
                if inlinePolices is not None:
                    policyDefinition["Policies"].extend(inlinePolices)

                groups = self.bypassCheckObj.get_user_groups(user)
                if groups is not None:
                    for group in groups:
                        groupAttachedPolices = self.bypassCheckObj.get_attached_group_policies(group)
                        if groupAttachedPolices is not None:
                            policyDefinition["Policies"].extend(groupAttachedPolices)

                        groupPolices = self.bypassCheckObj.get_group_inline_policies(group)

                        if groupPolices is not None:
                            policyDefinition["Policies"].extend(groupPolices)

                #userPolicies[user] = policyDefinition
                stringPolicies = []
                for policy in policyDefinition['Policies']:
                    stringPolicies.append(json.dumps(policy))
                evaluationResponse = self.bypassCheckObj.find_permissions_in_policy(policyDocumentList=stringPolicies, permissionBoundaryList=userPermissionBoundary, SCENARIOS=SCENARIOS)

                if self.include_denied:
                    tablePrintObj = TablePrint(self.verbose)
                    userfields = tablePrintObj.tableprint(evaluationResponse)
                    dumpCSV(userfields, self.accountID, user)
                else:
                    if self.bypassCheckObj.filterInterestingIdentities(evaluationResponse):
                        tablePrintObj = TablePrint(self.verbose)
                        userfields = tablePrintObj.tableprint(evaluationResponse)
                        dumpCSV(userfields, self.accountID, user)
                    else:
                        printOutput(
                            f"User '{user}' is not allowed to execute any of the scenario calls and is skipped. Use -v if you want it included",
                            "success", verbose=True)


        if roles is not None and len(roles) > 0:
            for role in roles:
                printOutput("----------------------------------------------------", type="loading", verbose=True)
                printOutput(f"           {role}", type="loading", verbose=True)
                printOutput("----------------------------------------------------", type="loading", verbose=True)
                policyDefinition = {
                    "Policies": []
                }

                rolePermissionBoundary = self.bypassCheckObj.get_role_permission_boundary(role)

                if rolePermissionBoundary is not None:
                    rolePermissionBoundary = [json.dumps(rolePermissionBoundary)]

                attachedPolices = self.bypassCheckObj.get_attached_role_policies(role)
                if attachedPolices is not None:
                    policyDefinition["Policies"] = attachedPolices

                inlinePolices = self.bypassCheckObj.get_role_inline_policies(role)
                if inlinePolices is not None:
                    policyDefinition["Policies"].extend(inlinePolices)

                #rolePolicies[role] = policyDefinition
                stringPolicies = []
                for policy in policyDefinition['Policies']:
                    stringPolicies.append(json.dumps(policy))
                evaluationResponse = self.bypassCheckObj.find_permissions_in_policy(policyDocumentList=stringPolicies, permissionBoundaryList=rolePermissionBoundary, SCENARIOS=SCENARIOS)

                if self.include_denied:
                    tablePrintObj = TablePrint(self.verbose)
                    rolefields = tablePrintObj.tableprint(evaluationResponse)
                    dumpCSV(rolefields, self.accountID, role)
                else:
                    if self.bypassCheckObj.filterInterestingIdentities(evaluationResponse):
                        tablePrintObj = TablePrint(self.verbose)
                        rolefields = tablePrintObj.tableprint(evaluationResponse)
                        dumpCSV(rolefields, self.accountID, role)
                    else:
                        printOutput(f"Role '{role}' is not allowed to execute any of the scenario calls and is skipped. Use -v if you want it included", "success", verbose=self.verbose)