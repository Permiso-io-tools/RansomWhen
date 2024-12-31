import os, json

from core.Other.Arguments.ArgParse import parseArgs
from core.Other.PrintOutput.PrintOutput import printOutput
from core.Authentication.Authentication import authenticate
from core.Resources.MainActivity.MainActivity import IdentitiesEnumeration, ListEvents

args = parseArgs()

if not os.path.exists("./output"):
    os.mkdir("./output")

profile = args.profile
accountid = None


try:
    client = authenticate(
        Profile=profile,
        AccessKey=None,
        SecretKey=None,
        SessionToken=None,
        Service="sts",
        UserAgent=None
    )
    accountid = client.get_caller_identity()['Account']
    printOutput(f"Testing Account {accountid}", "loading")

except Exception as e:
    printOutput(f"Error with credentials provided: {str(e)}", "error")
    exit()

if accountid is None:
    printOutput(f"Error with credentials provided", "error")
    exit()

if not os.path.exists(f'./output/{accountid}'):
    os.mkdir(f"./output/{accountid}")

if args.provider == "IDENTITIES":
    if args.identity_name is not None:
        if args.identity_type is None:
            printOutput(
                "You need to also provide the identity type using -it if you provide the identity name using -i",
                "failure")
            exit()
    mainactivity = IdentitiesEnumeration(profile=profile, accountID=accountid, args=args)
    mainactivity.identities_enumeration()

elif args.provider == "EVENTS":
    mainactivity = ListEvents(profile=profile, accountID=accountid)
    print(json.dumps(mainactivity.list_events(), indent=4, default=str))

else:
    printOutput("Provider should either be IDENTITIES or EVENTS", "failure")