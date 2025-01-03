import csv
from core.Other.PrintOutput.PrintOutput import printOutput

def dumpCSV(result, outputdir, identity):
    csvfilename = f'./output/{outputdir}/{identity}-predefined-scenarios.csv'

    csvfile = csv.writer(open(csvfilename, "w"))

    csvfile.writerow(["Scenario", "Status", "Allowed", "Denied"])
    #writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    for row in result:
        csvfile.writerow(row.values())

    #writer.writeheader()
    #del (result[0])
    printOutput(f"Outputfile {csvfilename} successfully created", "success", verbose=True)


def dumpEventsCSV(result, outputdir, identity):
    csvfilename = f'./output/{outputdir}/{identity}-events.csv'

    csvfile = csv.writer(open(csvfilename, "w"))

    csvfile.writerow([
            "EventTime",
            "EventName",
            "AccessKeyId",
            "SourceIP",
            "Region",
            "RequestParameters",
            "ResponseElements",
            "Resources"
        ]
    )
    #writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    for row in result:
        #csvfile.writerow(row.values())
        csvfile.writerow(row)

    #writer.writeheader()
    #del (result[0])
    printOutput(f"Outputfile {csvfilename} successfully created", "success", verbose=True)