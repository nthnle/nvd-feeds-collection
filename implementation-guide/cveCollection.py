import requests
import re
from bs4 import BeautifulSoup
import pandas as pd
import gzip
import csv
import os
import boto3
import json
from decimal import Decimal

cveTable = os.environ['CVE_TABLE']
awsRegion = os.environ['AWS_REGION']

dynamodb = boto3.resource('dynamodb', region_name = awsRegion)

def collect_exploit():
    print("Collecting CVE reference map for source EXPLOIT-DB")
    csv_file = open('Exploit_CVE.csv', 'w')
    csv_writer = csv.writer(csv_file)
    exploitUrl = 'https://cve.mitre.org/data/refs/refmap/source-EXPLOIT-DB.html'
    req = requests.get(exploitUrl, allow_redirects=True)
    # get status code
    print ("Exploit status code: " + str(req.status_code))
    # read the data from the URL and print it in html form
    # this is the full html, not just the table's html
    # we will need to parse through this to only grab the table we are interested in
    # use BeautifulSoup to parse through the html
    soup = BeautifulSoup(req.text, "html.parser")

    # find all the tables that fit these attributes
    # we only want the ExploitDB/CVENum table, so we index with [1] to grab table #2
    table = soup.findAll("table", attrs={"cellpadding":"2", "cellspacing":"2", "border":"2"})[1]

    # The first tr contains the field names.
    headings = ["ExploitId", "CveId"]
    datasets = []

    for row in table.find_all("tr")[0:]:
        row = list(td.get_text() for td in row.find_all("td"))
        #print(type(dataset))
        #df.append(dataset, ignore_index = True)
        #df = pd.DataFrame(dataset, columns=['ExploitDB Number', 'CVE Number'])
        datasets.append(row)
        #print(dataset)

    df = pd.DataFrame(datasets, columns = headings) # creating data frame with the proper headings and loading in the data
    df = df.astype('string') # converting the pandas objects (default) to strings
    df.drop(df.tail(2).index, inplace = True) # dropping the last two rows because they don't have exploit db Id's 
    df[headings[0]] = df[headings[0]].str.replace(r'\D', '') # removing the prefix "EXPLOIT-DB" from the ExploitDBId column
    df[headings[1]] = df[headings[1]].str.rstrip("\n") # removing the trailing newline from the CVEId column
    df[headings[1]] = df[headings[1]].str.lstrip(' ') # removing the leading white space from the CVEId column
    df[headings[1]] = df[headings[1]].str.split(' ') # splitting the column based on white space within the entries
    df = df.set_index([headings[0]])[headings[1]].apply(pd.Series).stack().reset_index().drop('level_1',axis = 1).rename(columns = {0: headings[1]}) # creating multiple rows for exploits that correspond to multiple CVE #'s
    print(df)
    #print(df[headings[1]].nunique()) # find the number of unique CVE values
    #print(df[headings[0]].nunique()) # find the number of unique Exploit values
    #print(pd.concat(g for _, g in df.groupby("CveId") if len(g) > 1)) # find the CVEs that have more than one exploit

    n = len(df[headings[1]]) # find the number of rows in the dataframe
    csv_writer.writerow(headings)
    for i in range(n - 1):
        csv_writer.writerow(df.loc[i]) # writing data frame to a csv file
        
    csv_file.close()

    df.to_json("Exploit_CVE.json", indent = 2, orient = 'records') # writing the dataframe to a json file
    
def collect_nvd_feeds():
    print("Collecting JSON vulnerability feeds from NVD")
    nvdJson = []
    req = requests.get('https://nvd.nist.gov/vuln/data-feeds#JSON_FEED')
    
    # scan for all yearly gzip files
    for gzFile in re.findall("nvdcve-1.1-[0-9]*\.json\.gz", req.text):
        #print(gzFile)
        url = 'https://nvd.nist.gov/feeds/json/cve/1.1/' + gzFile
        reqFile = requests.get(url, stream=True, allow_redirects=True)
        # get status code
        print (gzFile + " status code: " + str(reqFile.status_code))
        # write response
        with open(gzFile, 'wb') as file:
            file.write(reqFile.content)
        with gzip.open(gzFile) as openGz:
            nvdDF = pd.read_json(openGz)
        for x in nvdDF['CVE_Items']:
            cveId = str(x['cve']['CVE_data_meta']['ID'])
            cveSrcUrl = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + cveId
            try:
                cweId = str(x['cve']['problemtype']['problemtype_data'][0]['description'][0]['value'])
            except:
                cweId = 'NONE_PROVIDED'
            try:
                reference = str(x['cve']['references']['reference_data'][0]['url'])
            except:
                reference = 'NONE_PROVIDED'
            try:
                description = str(x['cve']['description']['description_data'][0]['value'])
            except:
                description = 'NONE_PROVIDED'
            try:
                cvssV2Version = str('CVSSv' + x['impact']['baseMetricV2']['cvssV2']['version'])
                cvssV2AccessVector = str(x['impact']['baseMetricV2']['cvssV2']['accessVector'])
                cvssV2AccessComplexity = str(x['impact']['baseMetricV2']['cvssV2']['accessComplexity'])
                cvssV2Authentication = str(x['impact']['baseMetricV2']['cvssV2']['authentication'])
                cvssV2ConfidentialityImpact = str(x['impact']['baseMetricV2']['cvssV2']['confidentialityImpact'])
                cvssV2IntegrityImpact = str(x['impact']['baseMetricV2']['cvssV2']['integrityImpact'])
                cvssV2AvailabilityImpact = str(x['impact']['baseMetricV2']['cvssV2']['availabilityImpact'])
                cvssV2Score = float(x['impact']['baseMetricV2']['cvssV2']['baseScore'])
                cvssV2Severity = str(x['impact']['baseMetricV2']['severity'])
            except:
                cvssV2Version = 'NONE_PROVIDED'
                cvssV2AccessVector = 'Unknown'
                cvssV2AccessComplexity = 'Unknown'
                cvssV2Authentication = 'Unknown'
                cvssV2ConfidentialityImpact = 'Unknown'
                cvssV2IntegrityImpact = 'Unknown'
                cvssV2AvailabilityImpact = 'Unknown'
                cvssV2Score = float(0.0)
                cvssV2Severity = 'Unknown'
            try:
                cvssV3Version = str('CVSSv' + x['impact']['baseMetricV3']['cvssV3']['version'])
                cvssV3AttackVector = str(x['impact']['baseMetricV3']['cvssV3']['attackVector'])
                cvssV3AttackComplexity = str(x['impact']['baseMetricV3']['cvssV3']['attackComplexity'])
                cvssV3PrivilegesRequired = str(x['impact']['baseMetricV3']['cvssV3']['privilegesRequired'])
                cvssV3UserInteraction = str(x['impact']['baseMetricV3']['cvssV3']['userInteraction'])
                cvssV3Scope = str(x['impact']['baseMetricV3']['cvssV3']['scope'])
                cvssV3ConfidentialityImpact = str(x['impact']['baseMetricV3']['cvssV3']['confidentialityImpact'])
                cvssV3IntegrityImpact = str(x['impact']['baseMetricV3']['cvssV3']['integrityImpact'])
                cvssV3AvailabilityImpact = str(x['impact']['baseMetricV3']['cvssV3']['availabilityImpact'])
                cvssV3Score = float(x['impact']['baseMetricV3']['cvssV3']['baseScore'])
                cvssV3Severity = str(x['impact']['baseMetricV3']['cvssV3']['baseSeverity'])
            except:
                cvssV3Version = 'NONE_PROVIDED'
                cvssV3AttackVector = 'Unknown'
                cvssV3AttackComplexity = 'Unknown'
                cvssV3PrivilegesRequired = 'Unknown'
                cvssV3UserInteraction = 'Unknown'
                cvssV3Scope = 'Unknown'
                cvssV3ConfidentialityImpact = 'Unknown'
                cvssV3IntegrityImpact = 'Unknown'
                cvssV3AvailabilityImpact = 'Unknown'
                cvssV3Score = float(0.0)
                cvssV3Severity = 'Unknown'
            
            try:
                nvdJson.append({
                    'CveId': cveId,
                    'CveSourceUrl': cveSrcUrl,
                    'CweId': cweId,
                    'Reference': reference,
                    'Description': description,
                    'CvssV2Version': cvssV2Version,
                    'CvssV2AccessVector': cvssV2AccessVector,
                    'CvssV2AccessComplexity': cvssV2AccessComplexity,
                    'CvssV2Authentication': cvssV2Authentication,
                    'CvssV2ConfidentialityImpact': cvssV2ConfidentialityImpact,
                    'CvssV2IntegrityImpact': cvssV2IntegrityImpact,
                    'CvssV2AvailabilityImpact': cvssV2AvailabilityImpact,
                    'CvssV2Score': cvssV2Score,
                    'CvssV2Severity': cvssV2Severity,
                    'CvssV3Version': cvssV3Version,
                    'CvssV3AttackVector': cvssV3AttackVector,
                    'CvssV3AttackComplexity': cvssV3AttackComplexity,
                    'CvssV3PrivilegesRequired': cvssV3PrivilegesRequired,
                    'CvssV3UserInteraction': cvssV3UserInteraction,
                    'CvssV3Scope': cvssV3Scope,
                    'CvssV3ConfidentialityImpact': cvssV3ConfidentialityImpact,
                    'CvssV3IntegrityImpact': cvssV3IntegrityImpact,
                    'CvssV3AvailabilityImpact': cvssV3AvailabilityImpact,
                    'CvssV3Score': cvssV3Score,
                    'CvssV3Severity': cvssV3Severity
                })
            except Exception as e:
                print(e)
    
    with open("NVD_Feeds.json", "w") as file:
        json.dump(nvdJson, file)
                
def cve_population():
    table = dynamodb.Table(cveTable)
    exploitDF = pd.read_json('./Exploit_CVE.json')
    nvdDF = pd.read_json('./NVD_Feeds.json')
    exploitDF['ExploitId'] = exploitDF['ExploitId'].apply(str)
    
    print("Merging Exploit and NVD data feeds")
    cveV2Merge = nvdDF.merge(
        exploitDF,
        how = 'left',
        on = 'CveId',
    )
    print(cveV2Merge)
    
    cveV2Merge.to_json(
        path_or_buf = './cveV2.json',
        orient = 'table',
        index = False,
        indent = 4
    )

    with open('./cveV2.json') as jsonfile: # comment this out if you don't use DynamoDB
        for x in json.load(jsonfile)['data']:
            if str(x['ExploitId']) == 'None':
                hasExploit = 'False'
                exploitId = 'NOT_AVAILABLE'
            else:
                hasExploit = 'True'
                exploitId = str(x['ExploitId'])
            try:
                table.put_item(
                    Item = {
                        'CveId': str(x['CveId']),
                        'CveSourceUrl': str(x['CveSourceUrl']),
                        'CweId': str(x['CweId']),
                        'Reference': str(x['Reference']),
                        'Description': str(x['Description']),
                        'ExploitId': exploitId,
                        'HasExploit': hasExploit,
                        'CvssV2Version': str(x['CvssV2Version']),
                        'CvssV2AccessVector': str(x['CvssV2AccessVector']),
                        'CvssV2AccessComplexity': str(x['CvssV2AccessComplexity']),
                        'CvssV2Authentication': str(x['CvssV2Authentication']),
                        'CvssV2ConfidentialityImpact': str(x['CvssV2ConfidentialityImpact']),
                        'CvssV2IntegrityImpact': str(x['CvssV2IntegrityImpact']),
                        'CvssV2AvailabilityImpact': str(x['CvssV2AvailabilityImpact']),
                        'CvssV2Score': json.loads(json.dumps(x['CvssV2Score']), parse_float = Decimal),
                        'CvssV2Severity': str(x['CvssV2Severity']),
                        'CvssV3Version': str(x['CvssV3Version']),
                        'CvssV3AttackVector': str(x['CvssV3AttackVector']),
                        'CvssV3AttackComplexity': str(x['CvssV3AttackComplexity']),
                        'CvssV3PrivilegesRequired': str(x['CvssV3PrivilegesRequired']),
                        'CvssV3UserInteraction': str(x['CvssV3UserInteraction']),
                        'CvssV3Scope': str(x['CvssV3Scope']),
                        'CvssV3ConfidentialityImpact': str(x['CvssV3ConfidentialityImpact']),
                        'CvssV3IntegrityImpact': str(x['CvssV3IntegrityImpact']),
                        'CvssV3AvailabilityImpact': str(x['CvssV3AvailabilityImpact']),
                        'CvssV3Score': json.loads(json.dumps(x['CvssV3Score']), parse_float = Decimal),
                        'CvssV3Severity': str(x['CvssV3Severity'])
                    }
                )
            except Exception as e:
                print(e)

def cve_v2():
    collect_exploit()
    collect_nvd_feeds()
    cve_population()
    
cve_v2()