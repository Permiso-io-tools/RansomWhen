import json
import re
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


    def groupMaliciousEvents(self, identityEvents, identityArn):
        printOutput(
            f"Finding Malicious Activity for '{identityArn}'", "loading", verbose=self.verbose)

        maliciousAttacks = []

        try:
            with open("./scenarios/scenarios.json") as scenariofile:
                SCENARIOS = json.load(scenariofile)
        except Exception as e:
            printOutput(f"Error Opening ./scenarios/scenarios.json: {str(e)}", "failure")
            exit()

        fieldNames = {
            "EventTime": "",
            "EventName": "",
            "AccessKeyId": "",
            "SourceIP": "",
            "Region": "",
            "RequestParameters": "",
            "ResponseElements": "",
            "Resources": ""
        }
        singleEvent = []

        for event in identityEvents:
            if event['EventName'] == "kms:CreateKey" or event['EventName'] == "kms:CreateKey":
                if event['Resources'] != "":
                    keyresources = json.loads(event['Resources'])
                    for kmskeyres in keyresources:
                        if kmskeyres['ResourceType'] == "AWS::KMS::Key" and "arn:aws:kms:" in kmskeyres['ResourceName']:
                            kmskey = kmskeyres['ResourceName']
                            singleEvent.append(event)

                            for allevent in identityEvents:
                                if allevent['EventName'] == "kms:PutKeyPolicy" or allevent['EventName'] == "s3:PutBucketEncryptionConfiguration":
                                    if event['Resources'] != "":
                                        keyresources = json.loads(allevent['Resources'])
                                        for kmskeyres in keyresources:
                                            if kmskeyres['ResourceType'] == "AWS::KMS::Key" and "arn:aws:kms:" in kmskeyres[
                                                'ResourceName']:
                                                if kmskey == kmskeyres['ResourceName']:
                                                    singleEvent.append(allevent)
                                            if allevent['EventName'] == "s3:PutBucketEncryptionConfiguration" and kmskeyres['ResourceType'] == "AWS::S3::Bucket":
                                                s3bucket = kmskeyres['ResourceName']



            if len(singleEvent) > 0:
                maliciousAttacks.append(singleEvent)
                singleEvent = []






        printOutput(
            f"Found {str(len(maliciousAttacks))} Malicious Activity for '{identityArn}'", "loading", verbose=self.verbose)

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

                if not "UserName" in event and "Username" in event:
                    event['UserName'] = event['Username']
                    del(event['Username'])

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
                    if eventData['userIdentity']['type'] == "AssumedRole" and not identitytocheck == eventData['userIdentity']['arn'].replace(f"/{event['UserName']}", ""):
                        continue
                    #if eventData['userIdentity']['type'] == "IAMUser" and not self.eventsJSON[event['EventName']]['Identity'] == eventData['userIdentity']['arn']:
                    #    continue


                    #importantEvents.append(event)
                    importantEvents.append({
                        "EventTime": event['EventTime'].strftime("%Y-%m-%d %H:%M:%S"),
                        "EventName": f"{event['EventSource'].split('.')[0]}:{event['EventName']}",
                        "AccessKeyId": event['AccessKeyId'],
                        "SourceIP": eventData['sourceIPAddress'],
                        "Region": eventData['awsRegion'],
                        "RequestParameters": json.dumps(eventData['requestParameters'], indent=4, default=str) if type(eventData['requestParameters']) == list or type(eventData['requestParameters']) == dict else "",
                        "ResponseElements": json.dumps(eventData['responseElements'], indent=4, default=str) if type(eventData['requestParameters']) == list or type(eventData['requestParameters']) == dict else "",
                        "Resources": json.dumps(event['Resources'], indent=4, default=str) if type(event['Resources']) == list or type(event['Resources']) == dict else ""
                    })

            printOutput(f"Found {str(len(importantEvents))} events for identity", "success", verbose=self.verbose)
            importantEvents.sort(key=lambda item: item['EventTime'], reverse=True)
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