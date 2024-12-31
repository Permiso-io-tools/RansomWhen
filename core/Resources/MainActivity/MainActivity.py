from core.Other.PrintOutput.PrintOutput import printOutput
from core.Other.TablePrint import TablePrint
from core.Resources.IAM.BypassCheck import BypassCheck
from core.Resources.CloudTrail.GetCTEvents import GetCTEvents
import json
from core.Resources.OutputDump.OutputDump import dumpCSV

class ListEvents:
    def __init__(self, profile, accountID):
        self.bypassCheckObj = BypassCheck(profile=profile)
        self.cloudTrailObj = GetCTEvents(profile=profile)
        self.accountID = accountID

    def list_events(self):
        scenariofile = "scenarios/events.json"

        with open(scenariofile) as scenariosfile:
            SCENARIOS = json.load(scenariosfile)

        users = self.bypassCheckObj.list_users_arn()
        users.extend(self.bypassCheckObj.list_roles_arn())

        eventsperidentity = {}

        if users is not None and len(users) > 0:
            for user in users:
                printOutput("----------------------------------------------------", type="loading")
                printOutput(f"           {user}", type="loading")
                printOutput("----------------------------------------------------", type="loading")
                allidentityevents = []
                for eventname, eventAttributes in self.cloudTrailObj.eventsJSON.items():
                    allidentityevents.extend(self.cloudTrailObj.getCTAPIEvents(identityArn=user, eventName=eventname))

                eventsperidentity[user] = allidentityevents

        return eventsperidentity

class IdentitiesEnumeration:
    def __init__(self, profile, accountID, args):
        self.bypassCheckObj = BypassCheck(profile=profile)
        #self.cloudTrailObj = GetCTEvents(profile=profile)
        self.accountID = accountID
        self.identity = args.identity_name
        self.identitytype = args.identity_type
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
                printOutput("----------------------------------------------------", type="loading")
                printOutput(f"           {user}", type="loading")
                printOutput("----------------------------------------------------", type="loading")
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

                if self.verbose:
                    tablePrintObj = TablePrint()
                    userfields = tablePrintObj.tableprint(evaluationResponse)
                    dumpCSV(userfields, self.accountID, user)
                else:
                    if self.bypassCheckObj.filterInterestingIdentities(evaluationResponse):
                        tablePrintObj = TablePrint()
                        userfields = tablePrintObj.tableprint(evaluationResponse)
                        dumpCSV(userfields, self.accountID, user)
                    else:
                        printOutput(
                            f"User '{user}' is not allowed to execute any of the scenario calls and is skipped. Use -v if you want it included",
                            "success")


        if roles is not None and len(roles) > 0:
            for role in roles:
                printOutput("----------------------------------------------------", type="loading")
                printOutput(f"           {role}", type="loading")
                printOutput("----------------------------------------------------", type="loading")
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

                if self.verbose:
                    tablePrintObj = TablePrint()
                    rolefields = tablePrintObj.tableprint(evaluationResponse)
                    dumpCSV(rolefields, self.accountID, role)
                else:
                    if self.bypassCheckObj.filterInterestingIdentities(evaluationResponse):
                        tablePrintObj = TablePrint()
                        rolefields = tablePrintObj.tableprint(evaluationResponse)
                        dumpCSV(rolefields, self.accountID, role)
                    else:
                        printOutput(f"Role '{role}' is not allowed to execute any of the scenario calls and is skipped. Use -v if you want it included", "success")