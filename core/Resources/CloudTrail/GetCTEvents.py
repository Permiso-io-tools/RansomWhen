import json
import sys
import datetime

from core.Authentication.Authentication import authenticate
from core.Other.PrintOutput.PrintOutput import printOutput


class GetCTEvents:
    def __init__(self, profile):
        self.profile = profile
        self.client = authenticate(
            Profile=self.profile,
            AccessKey=None,
            SecretKey=None,
            SessionToken=None,
            UserAgent=None,
            Service="cloudtrail"
        )
        with open("./scenarios/events.json") as scfile:
            self.eventsJSON = json.load(scfile)

    def filterMaliciousEvents(self, identityArn, events):
        printOutput(
            f"Filtering Events for identity '{identityArn}'", "loading"
        )

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
                eventData = json.loads(event['CloudTrailEvent'])

                if event['EventName'] in self.eventsJSON and event["EventSource"] == self.eventsJSON[event['EventName']]["EventSource"]:
                    if self.eventsJSON[event['EventName']]['UserAgent'] is not None and not self.eventsJSON[event['EventName']]['UserAgent'] in eventData['userAgent']:
                        continue
                    if self.eventsJSON[event['EventName']]['UserAgent'] is not None and not self.eventsJSON[event['EventName']]['UserAgent'] in eventData['userAgent']:
                        continue
                    if self.eventsJSON[event['EventName']]['Identity'] is not None:
                        if eventData['userIdentity']['arn'] == "IAMUser" and not self.eventsJSON[event['EventName']]['Identity'] == eventData['userIdentity']['arn']:
                            continue
                        if eventData['userIdentity']['arn'] == "AssumedRole" and not self.eventsJSON[event['EventName']]['Identity'] == eventData['userIdentity']['arn'].replace(f"/{event['UserName']}"):
                            continue
                        if eventData['userIdentity']['arn'] == "IAMUser" and not self.eventsJSON[event['EventName']]['Identity'] == eventData['userIdentity']['arn']:
                            continue
                    importantEvents.append(event)

            printOutput(f"Found {str(len(importantEvents))} events with quarantine policy attachment", "success")
            return list(set(importantEvents))
        except:
            printOutput(f"Error looking at events: {sys.exc_info()}", "failure")
            return []


    def getCTAPIEvents(self, identityArn, eventName):
        printOutput(
            f"Finding malicious '{eventName}' events for identity '{identityArn}'", "loading"
        )
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
            f"Finding malicious '{eventName}' events for identity '{identityArn}'", "loading"
        )
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