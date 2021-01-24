# NVD Data Feeds Collection - Implementation Guide

## Background

The automation plan is as follows: use CloudFormation to deploy resources (CodeBuild, CodeCommit, DynamoDB table, IAM Roles),
and then CodeBuild will run a python file that scrapes the MITRE's CVE Reference Map, pulls NVD's JSON Vulnerability Feeds, and populates the DynamoDB table.

## Prerequisites

- Access to an AWS Account with permissions to deploy CloudFormation

## Deploying

1. Download `codecommit-archive.zip` which includes `cveCollection.py` and `buildspec.yml`. `cveCollection.py` handles the collecting, merging, and writing the data. You can run `cveCollection.py` independently if you just want a JSON file of the data. `buildspec.yml` provides commands for CodeBuild project.

2. Upload `codecommit-archive.zip` to an S3 bucket. Note down the name of the bucket.

3. Use

4. Zip the `buildspec.yml` and the `cveV2.py` files together into a compressed file called `codecommit-archive.zip`.
The easiest way to do this is to download both these files from your Cloud9 directory and zip them in your file folder.
Once zipped, upload `codecommit-archive.zip` to the S3 bucket you created.

5. Create a YAML CloudFormation template in your directory called `CVE_Collection_CloudFormation.yml`.
You can copy and paste the text for this file from the `automation` folder within this directory.
This CloudFormation template is responsible for creating the DynamoDB table, CodeCommit Repo, CodeBuild project, CodeBuild Event,
as well as the associated IAM roles that will be neccessary.

6. Use this CloudFormation template to create a stack in the CloudFormation console.
When it completes, you should see a green `CREATE_COMPLETE` by your stack.

![cloudFormationSuccess](./screenshots/cloudFormationSuccess.PNG)

7. Go to CodeBuild, and verify that your repo was created and the build ran successfully.

![CodeBuildSuccess](./screenshots/CodeBuildSuccess.PNG)

### Resources Deployed

- 1x S3 Bucket
- 1x CodeBuild Project
- 1x CodeCommit Repository
- 2x IAM Roles for CodeBuild
- 1x DynamoDB Table

### Future Considerations

If possible, find a way to grab the verified/not verified data from ExploitDB  to then join with the table in DynamoDB based on Exploit ID

## Contributing

To contribute to this repo create another fork based on `master` and open a PR. Update the code, code comments, readme and architecture as required.
