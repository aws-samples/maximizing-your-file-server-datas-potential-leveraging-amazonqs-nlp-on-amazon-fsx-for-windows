# Maximizing Your File Server Data's Potential: Leveraging Amazon Q's NLP on Amazon FSx for Windows

This repository provides the supporting infrastructure and configuration guidelines to integrate with Amazon Q Business FSx connector, as detailed in the associated AWS Blog post. It includes automated deployment scripts and step-by-step instructions to help you successfully set up and configure the necessary AWS services.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Cloning the Repository](#cloning-the-repository)
3. [CloudFormation Stack Deployment](#cloudformation-stack-deployment)
4. [Accessing the Windows EC2 Instance](#accessing-the-windows-ec2-instance)
5. [Running the PowerShell Script](#running-the-powershell-script)
6. [Validation Steps](#validation-steps)
7. [Identity Center Configuration](#identity-center-configuration)
8. [Cleanup Procedures](#cleanup-procedures)
9. [Troubleshooting](#troubleshooting)

## [Prerequisites](#prerequisites)

Before beginning this implementation, ensure you have the following in place:

- [ ] Active AWS account with administrative permissions
- [ ] AWS CLI installed and configured with credentials
- [ ] Valid EC2 key pair in your target region
- [ ] Git installed on your local machine

## [Cloning the Repository](cloningtherepository)

First, you'll need to clone the repository containing all necessary scripts and templates. Open your terminal and run:

```bash
# Clone the repository
git clone https://github.com/your-repo-url/amazonq-connector-for-fsx-windows.git

# Navigate to the cloned directory
cd amazonq-connector-for-fsx-windows
```

## [CloudFormation Stack Deployment](#cloudformation-stack-deployment)

This step creates the core infrastructure including VPC, EC2 instance, and FSx file system. You can choose either the console or CLI method.

### Using AWS Management Console

1. **Access CloudFormation**
   - Open the [AWS CloudFormation Console](https://console.aws.amazon.com/cloudformation)
   - Click "Create stack" → "With new resources (standard)"

2. **Upload Template**
   - Upload the template file: `fsx-windows-environment-setup.yaml`

3. **Configure Stack**
   ```
   Stack Name: <your-unique-stack-name>
   Parameters:
   - VPCName: amazonq-connector-for-win-fsx-blog
   - CIDRBlock: 10.0.0.0/16
   - AZCount: 2
   - InstanceType: m5.large
   - KeyPair: <your-keypair-name>
   ```

### Using AWS CLI

```bash
# Create the CloudFormation stack
aws cloudformation create-stack \
  --stack-name your-stack-name \
  --template-body file://fsx-windows-environment-setup.yaml \
  --parameters \
    ParameterKey=VPCName,ParameterValue=amazonq-connector-for-win-fsx-blog \
    ParameterKey=CIDRBlock,ParameterValue=10.0.0.0/16 \
    ParameterKey=AZCount,ParameterValue=2 \
    ParameterKey=InstanceType,ParameterValue=m5.large \
    ParameterKey=KeyPair,ParameterValue=your-key-pair-name \
  --capabilities CAPABILITY_IAM

# Monitor stack creation status
aws cloudformation describe-stacks \
  --stack-name your-stack-name \
  --query Stacks[0].StackStatus
```

Wait for the stack creation to complete (approximately 20-30 minutes). You'll see the status change to "CREATE_COMPLETE" when finished.

## [Accessing the Windows EC2 Instance](#accessing-the-windows-ec2-instance)

Once the CloudFormation stack is successfully created, you can access the Windows instance:

1. **Locate the Instance**
   - Navigate to the EC2 Console
   - In the instances list, find the instance named "FSx/W Windows Instance"
   - Verify that the instance status is "running"

2. **Connect via Fleet Manager**
   - Select the instance
   - Click "Connect" button
   - Choose "RDP client" and then Connection type as "Connect using fleet manager"
   - Clikc on "Fleet Manager Remote Desktop"
   - Use these credentials:
   ```
   Username: admin@example.com
   Password: [Retrieve from AWS Secrets Manager]
   Secret Name: QBusiness-fsx-creds
   ```

## [Running the PowerShell Script](#running-the-powershell-script)

After successfully connecting to the Windows instance, you'll configure the environment:

1. **Open PowerShell**
   - Right-click the Windows Start button
   - Select "Windows PowerShell (Admin)"

2. **Clone Repository**
   ```powershell
   # Clone the repository
   git clone https://github.com/your-repo-url/amazonq-connector-for-fsx-windows.git
   
   # Navigate to the directory
   cd amazonq-connector-for-fsx-windows
   ```

3. **Execute Configuration Script**
   ```powershell
   # Run the configuration script
   .\configure_ad_users_groups_and_fsx.ps1
   ```

4. **Script Actions**
   The script will automatically:
   - [x] Set up logging
   - [x] Retrieve AWS Secrets Manager credentials
   - [x] Create Active Directory groups and users
   - [x] Mount Amazon FSx for Windows File Server
   - [x] Configure file permissions
   - [x] Perform cleanup operations

Monitor the script output for any errors. The process typically takes 3-5 minutes to complete.

## [Validation Steps](#validation-steps)

After the script completes, verify the setup:

### File System Access

1. **Mount File System**
   ```powershell
   # Replace with your FSx DNS name
   net use X: \\<dns-name>.example.com\share
   ```

2. **Verify Files**
   - Open File Explorer
   - Navigate to X: drive
   - Confirm presence of:
     - `generative-ai-on-aws-how-to-choose.pdf`
     - `aws-security-incident-response-guide.pdf`

3. **Check Permissions**
   ```powershell
   # View file permissions
   Get-Acl "X:\generative-ai-on-aws-how-to-choose.pdf" | Format-List
   Get-Acl "X:\aws-security-incident-response-guide.pdf" | Format-List
   ```

## [Identity Center Configuration](#identity-center-configuration)

Now that the infrastructure is ready, let's configure IAM Identity Center:

### Enable IAM Identity Center
Note: Perform #1 only if you it is not enabled in your AWS Account
1. **Service Activation**
   - Navigate to IAM Identity Center in AWS Console
   - Click "Enable"
   - Select "Enable in only this AWS Account"
   - Click "Continue"
   - Wait for activation to complete (approximately 2-3 minutes)

### Configure MFA Settings

1. **Access MFA Configuration**
   - Go to "Settings" → "Authentication"
   - Click "Configure" under MFA section

2. **Update Settings**
   ```
   Prompt users for MFA: Never
   Click: Save changes
   ```

Note: This MFA setting is for demonstration purposes. In production environments, always enable MFA.

### Configure Identity Source

1. **Change Identity Source**
   - Navigate to "Settings" → "Identity source"
   - Click "Actions" → "Change identity source"
   - Select "Active Directory"
   - Choose `example.com` from the Existing Directories dropdown
   - Review and confirm changes

Wait for the identity source change to complete (approximately 5 minutes).

### Configure Group Synchronization

1. **Add Groups**
   ```
   Navigate to: Settings → Groups
   Click: Add users and groups
   Select: Groups
   Add:
   - ml-engineers
   - security-engineers
   Note: If you see a banner with "Resume Sync" option, click on it to resume the Sync
   ```

2. **Sync Status**
   - It takes 3-5 minutes for the sync
   - Verify group members are properly synchronized


## [Cleanup Procedures](#cleanup-procedures)

When you're ready to remove all resources, follow these steps in order:

### Identity Center Cleanup

1. **Delete IAM Identity Center**
   - Navigate to IAM Identity Center console
   - Go to "Settings" → "Management"
   - Click "Delete"
   - Check all confirmation boxes
   - Enter Instance ID when prompted
   - Wait for complete deletion (approximately 5-10 minutes)

### Infrastructure Cleanup

1. **Delete CloudFormation Stack**
   ```bash
   # Delete stack using AWS CLI
   aws cloudformation delete-stack \
     --stack-name your-stack-name

   # Monitor deletion status
   aws cloudformation describe-stacks \
     --stack-name your-stack-name \
     --query Stacks[0].StackStatus
   ```

2. **Clean Up Secrets**
   ```bash
   # Delete all associated secrets
   aws secretsmanager delete-secret \
     --secret-id QBusiness-fsx-creds \
     --force-delete-without-recovery

   aws secretsmanager delete-secret \
     --secret-id jdoe \
     --force-delete-without-recovery

   aws secretsmanager delete-secret \
     --secret-id jsmith \
     --force-delete-without-recovery
   ```

3. **Remove Amazon Q Business Application**
   - Navigate to Amazon Q console
   - Select "Applications"
   - Choose your Q Business Application
   - Click "Delete" and confirm

### Resource Verification

After cleanup, verify all resources are properly removed:

1. **Verify Stack Deletion**
   ```bash
   # Check stack status
   aws cloudformation list-stacks \
     --query 'StackSummaries[?StackName==`your-stack-name`].StackStatus'
   ```

2. **Verify Network Resources**
   ```bash
   # List remaining ENIs in VPC
   aws ec2 describe-network-interfaces \
     --filters Name=vpc-id,Values=<your-vpc-id>

   # Delete any remaining ENIs if necessary
   aws ec2 delete-network-interface \
     --network-interface-id <eni-id>
   ```

3. **Final Verification Checklist**
   - [ ] CloudFormation stack deleted
   - [ ] VPC removed
   - [ ] EC2 instances terminated
   - [ ] FSx file system deleted
   - [ ] Secrets removed from Secrets Manager
   - [ ] IAM Identity Center disabled
   - [ ] Amazon Q Business Application removed

## [Troubleshooting](#troubleshooting)

### Q: Why am I seeing only "Sorry, I could not find relevant information to complete your request." as response from Amazon Q?  

**A:** There can be multiple reasons:
1. Ensure the user has permissions on the file in the FSx file system 
2. Check in the Amazon Cloudwatch to check if the file is considered under crawling and indexed successfully 
3. Verify if the question has the relevance in the indexed documents

### Q: Why am I seeing "KendraCustomerSession is not authorized to perform: fsx:DescribeFileSystems on resource:" during the data sync?

**A:** The role is missing the FSx permissions. Add the FSx permissions and run again.

### Q: Why am I seeing "Kendra is unable to assume index IAM role, please ensure that service principal kendra.amazonaws.com is added to IAM role trust policy" during the data sync?
 
**A:** Add the below JSON in the IAM Role, Trusted relationships section:
```json
{
    "Sid": "AllowKendraToAssumeRole",
    "Effect": "Allow",
    "Principal": {
        "Service": "kendra.amazonaws.com"
    },
    "Action": "sts:AssumeRole"
}
```

### Q: Why am I seeing "Message":"Connector sync failed due to following exception","Exception":"Dangling meta character '*' near index"?

**A:** In the Sync scope section of Data source, remove * in front of the file types.
The correct way to add file types is:
```
.txt,.pdf,.png
```

## [Support Resources](#support-resources)

1. **Documentation**
   - [AWS FSx Documentation](https://docs.aws.amazon.com/fsx/)
   - [IAM Identity Center Guide](https://docs.aws.amazon.com/singlesignon/)
   - [Amazon Q Documentation](https://docs.aws.amazon.com/amazonq/)

2. **Support Channels**
   - [AWS re:Post] (https://repost.aws/)

