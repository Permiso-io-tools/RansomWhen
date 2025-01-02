import json
import sys
import datetime

from core.Authentication.Authentication import authenticate
from core.Other.PrintOutput.PrintOutput import printOutput


class GetCTEvents:
    def __init__(self, profile, verbose):
        self.profile = profile
        self.client = authenticate(
            Profile=self.profile,
            AccessKey=None,
            SecretKey=None,
            SessionToken=None,
            UserAgent=None,
            Service="cloudtrail"
        )
        self.verbose = verbose
        with open("./scenarios/events.json") as scfile:
            self.eventsJSON = json.load(scfile)

    def filterMaliciousEvents(self, identityArn, events):
        printOutput(
            f"Filtering Events for identity '{identityArn}'", "loading", verbose=self.verbose)

        """
        Identity Types:
            AssumedRole
            AWSAccount
            AWSService
            WebIdentityUser
            IAMUser
            
            Unknown
            Directory
            SAMLUser
            Root
            Role
        """

        try:
            importantEvents = []
            for event in events:
                ##print(type(event['CloudTrailEvent']))
                eventData = json.loads(event['CloudTrailEvent'])
                ##print(eventData)
                if event['EventName'] in self.eventsJSON and event["EventSource"] == self.eventsJSON[event['EventName']]["EventSource"]:
                    ##print(event)
                    if self.eventsJSON[event['EventName']]['UserAgent'] is not None and not self.eventsJSON[event['EventName']]['UserAgent'] in eventData['userAgent']:
                        #print(self.eventsJSON[event['EventName']]['UserAgent'])
                        continue
                    if self.eventsJSON[event['EventName']]['RequestParameters'] is not None:
                        #print(self.eventsJSON[event['EventName']]['RequestParameters'])
                        for key, value in self.eventsJSON[event['EventName']]['RequestParameters'].items():
                            if key in eventData['requestParameters'] and eventData['requestParameters'][key] != value:
                                continue
                    if self.eventsJSON[event['EventName']]['ResponseElements'] is not None:
                        #print(self.eventsJSON[event['EventName']]['ResponseElements'])
                        for key, value in self.eventsJSON[event['EventName']]['ResponseElements'].items():
                            if key in eventData['responseElements'] and eventData['responseElements'][key] != value:
                                continue
                    if self.eventsJSON[event['EventName']]['Identity'] is not None:
                        identitytocheck = self.eventsJSON[event['EventName']]['Identity']
                    else:
                        identitytocheck = identityArn

                    #print(self.eventsJSON[event['EventName']]['Identity'])
                    if eventData['userIdentity']['type'] == "IAMUser" and not identitytocheck == eventData['userIdentity']['arn']:
                        continue
                    if eventData['userIdentity']['type'] == "AssumedRole" and not identitytocheck == eventData['userIdentity']['arn'].replace(f"/{event['UserName']}"):
                        continue
                    #if eventData['userIdentity']['type'] == "IAMUser" and not self.eventsJSON[event['EventName']]['Identity'] == eventData['userIdentity']['arn']:
                    #    continue


                    #importantEvents.append(event)
                    importantEvents.append({
                        "EventTime": event['EventTime'].strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "EventName": f"{event['EventSource'].split('.')[0]}:{event['EventName']}",
                        "AccessKeyId": event['AccessKeyId'],
                        "SourceIP": eventData['sourceIPAddress'],
                        "Region": eventData['awsRegion'],
                        "RequestParameters": json.dumps(eventData['requestParameters'], indent=4, default=str) if type(eventData['requestParameters']) == list or type(eventData['requestParameters']) == dict else "",
                        "ResponseElements": json.dumps(eventData['responseElements'], indent=4, default=str) if type(eventData['requestParameters']) == list or type(eventData['requestParameters']) == dict else ""
                    })

            printOutput(f"Found {str(len(importantEvents))} events for identity", "success", verbose=self.verbose)
            return importantEvents

        except Exception as e:
            printOutput(f"Error looking at events: {str(e)}", "failure")
            return []


    def getCTAPIEvents(self, identityArn, eventName):
        printOutput(
            f"Finding malicious '{eventName}' events for identity '{identityArn}'", "loading", verbose=self.verbose)

        startTime = datetime.datetime.now() - datetime.timedelta(days=90)
        try:
            response = self.client.lookup_events(
                LookupAttributes=[
                    {
                        'AttributeKey': 'EventName',
                        'AttributeValue': eventName
                    }
                ],
                StartTime=startTime
            )
            logs = response['Events']
            events = self.filterMaliciousEvents(identityArn=identityArn, events=logs)


            while "NextToken" in response:
                response = self.client.lookup_events(
                    LookupAttributes=[
                        {
                            'AttributeKey': 'EventName',
                            'AttributeValue': eventName
                        }
                    ],
                    StartTime=startTime,
                    NextToken=response["NextToken"]
                )
                logs = response['Events']
                events.extend(self.filterMaliciousEvents(identityArn=identityArn, events=logs))

            return events

        except:
            printOutput(f"Error looking at events: {sys.exc_info()}", "failure")
            return []

    def getCTS3Events(self, identityArn, eventName):
        printOutput(
            f"Finding malicious '{eventName}' events for identity '{identityArn}'", "loading", verbose=self.verbose)

        startTime = datetime.datetime.now() - datetime.timedelta(days=90)
        try:
            response = self.client.lookup_events(
                LookupAttributes=[
                    {
                        'AttributeKey': 'EventName',
                        'AttributeValue': eventName
                    }
                ],
                StartTime=startTime
            )
            logs = response['Events']
            events = self.filterMaliciousEvents(identityArn=identityArn, events=logs)


            while "NextToken" in response:
                response = self.client.lookup_events(
                    LookupAttributes=[
                        {
                            'AttributeKey': 'EventName',
                            'AttributeValue': eventName
                        }
                    ],
                    StartTime=startTime,
                    NextToken=response["NextToken"]
                )
                logs = response['Events']
                events.extend(self.filterMaliciousEvents(identityArn=identityArn, events=logs))

        except:
            printOutput(f"Error looking at events: {sys.exc_info()}", "failure")
            return None