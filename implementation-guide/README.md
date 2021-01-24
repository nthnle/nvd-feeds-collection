# NVD Data Feeds Collection - Implementation Guide

## Background

The automation plan is as follows: use CloudFormation to deploy resources (CodeBuild, CodeCommit, DynamoDB table, IAM Roles),
and then CodeBuild will run a python file that scrapes the MITRE's CVE Reference Map, pulls NVD's JSON Vulnerability Feeds, and populates the DynamoDB table.

## Prerequisites

- Access to an AWS Account with permissions to deploy CloudFormation

## Deploying

1. Download `codecommit-archive.zip` which includes `cveCollection.py` and `buildspec.yml`

    - `cveCollection.py` handles the collecting, merging, and writing the data. You can run `cveCollection.py` independently if you just want a JSON file of the data
    - `buildspec.yml` provides commands for CodeBuild project

2. Upload `codecommit-archive.zip` to an S3 bucket. Note down the name of the bucket

3. Use `CVE_Collection_CFN.yml` to create stack with CloudFormation. Put the S3 bucket name in _InitialCommitBucket_ parameter

4. Once the stack has been created. Check CodeBuild project to see if the project is running. If it's not, start it manually.

5. Once the build is finished (it takes roughy 20 minutes), check the `CVECollectionTable` in DynamoDB for data.

### Resources Deployed

- 1x CodeBuild Project
- 1x CodeCommit Repository
- 2x IAM Roles
- 1x DynamoDB Table
- 1x Events Rule

## Contributing

To contribute to this repo create another fork based on `master` and open a PR. Update the code, code comments, readme and architecture as required.
