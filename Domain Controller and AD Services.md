# Build a Directory Service Server with Active Directory
  This guide walks you through setting up an Active Directory (AD) server on Windows Server 2025, including configuration for Domain Controller, DNS, DHCP, and user accounts.

## Active Directory Overview
  What is Active Directory?
  
  - Active Directory (AD) is a directory service developed by Microsoft to manage and organize resources in a network. It serves as a centralized database to authenticate and authorize users and devices, acting as the backbone of most Windows-based enterprise environments.

## Key Components
  - Authentication: Verifies user identity using credentials like username and password.
  - Authorization: Grants or denies access to network resources based on permissions.
  - Management: Centralizes control over users, computers, and other resources.

## Why is Active Directory Used?
  Active Directory is widely used in enterprise environments to streamline and secure network management. Its key benefits include:
  
  - Centralized Resource Management: Enables administrators to manage users, devices, and permissions from a single location, reducing complexity.
  - Scalability: Handles environments from small businesses to multinational corporations with millions of objects.
  - Authentication and Authorization: Provides a robust framework for verifying users and granting access using protocols like Kerberos and LDAP.
  - Group Policy Management: Allows enforcement of security settings, software deployment, and updates via Group Policy Objects (GPOs).
  - Integration with Other Services: Seamlessly integrates with Microsoft Exchange, Microsoft Entra ID (formerly Azure AD), and other enterprise applications.

## Active Directory Core Concepts
  Domains  
  - A logical grouping of objects (users, devices, etc.) sharing the same database and security policies.
      Example: corp.local or, for this project, corp.hermitt-Sec-dc.com.
  
  Domain Controllers (DCs)  
  - Servers hosting the AD database, handling authentication, authorization, and replication.
  
  Organizational Units (OUs)  
  - Containers within a domain to organize objects logically (e.g., separate OUs for HR, IT, and Finance).
  
  Objects  
  - Entities in AD, such as users, computers, printers, and groups.
  
  Groups  
  - Security Groups: Manage permissions to resources.
  - Distribution Groups: Used for email distribution.
  
  Forest and Trees  
  - A forest is the highest-level container, encompassing multiple domains with a common schema.
  - A tree is a hierarchy of domains within a forest.
  
  Global Catalog (GC)
  - A distributed data repository providing information about all objects in the forest for faster lookups.
  
  Trust Relationships
  - Enable users in one domain to access resources in another domain.
  
  Security Implications
  - Active Directory is a prime target for attackers due to its central role in network resource management. Misconfigurations or vulnerabilities can lead to significant risks.
  
  Common Security Threats
  - Credential Theft: Techniques like Pass-the-Hash or Kerberoasting allow attackers to escalate privileges.
  - Privilege Escalation: Exploiting misconfigured permissions to gain higher access levels.
  - Lateral Movement: Attackers use AD to identify and move to valuable targets within the network.

*Note: Many organizations are transitioning to hybrid environments with Microsoft Entra ID for combined on-premises and cloud-based identity management. This guide focuses on an on-premises setup for full control and to avoid cloud costs.*

## Setup Windows Server 2025
  
  Step 1: Install Windows Server 2025
  - In the installation wizard, select Next → Install Windows Server 2025 → Check the box → Next.
   ![page6_img2](https://github.com/user-attachments/assets/42346f33-6cd5-4e3f-bea0-c52d789e7f6f)
  ![page7_img2](https://github.com/user-attachments/assets/9ffdea3b-e40a-47ef-920a-b4331c7ea532)


  - Choose Desktop Experience.
  - ![page7_img3](https://github.com/user-attachments/assets/a28b7476-ce14-42e7-89d3-4b037207a25d)

  - Accept Microsoft’s End User License Agreement (EULA) → Next.
  - Select Disk 0 Unallocated Space → Create Partition.
  - ![page8_img2](https://github.com/user-attachments/assets/ab2fdbc9-3d4a-4387-958e-9981522a58c9)

  - Use the default Size in MB setting → Apply. Wait for three partitions to appear.
  - ![page8_img3](https://github.com/user-attachments/assets/68bada70-0c8f-4a38-9ad2-f88432013178)

  - Select Disk 0 Partition 3 (with the largest free space) → Install.
  - ![page9_img2](https://github.com/user-attachments/assets/5c99f856-5139-4da6-9c62-d6ea2eb63da3)

  - Wait for Windows Server 2025 to install. The VM will restart.

  Step 2: Initial Configuration
  - Set a password for the default Administrator account.
  - On the VirtualBox login screen, navigate to Input → Keyboard → Insert Ctrl-Alt-Del to open the login prompt.
  - Choose Required only for sending diagnostic data to Microsoft.
  - After signing in, the Server Manager window appears. Close the Azure Arc dialog box if prompted.
  - ![page13_img2](https://github.com/user-attachments/assets/c4d0e1b9-b770-4a50-8945-f6e356b39556)

  Disable Default Logoff
  - To prevent automatic logoff after 5 minutes:
  - Search for Settings in the search bar → System → Power.
  - ![page13_img3](https://github.com/user-attachments/assets/ae010b6b-2156-437e-a9ec-cfce6397695f)

  - Under Screen timeout, select Never.
  
  Disable CTRL + ALT + DEL
  - To bypass the VirtualBox CTRL + ALT + DEL requirement:
  - Search for Local Security Policy.
  - Navigate to Interactive logon… → Toggle from Disabled to Enabled → Apply → OK.
  - ![page14_img2](https://github.com/user-attachments/assets/aca67956-d61a-4ff6-a5f4-f16d678704a7)

  
  Assign Static IP Address
  - Open Control Panel (Shortcut: Windows+X) → Network and Sharing Center → Change adapter settings.
  - Right-click the Ethernet icon → Properties.
  - Select Internet Protocol Version 4 (TCP/IPv4) → Properties.
  - ![page16_img3](https://github.com/user-attachments/assets/2f60dcac-9c58-49a4-bf0b-c3bfc42e2e71)

  
  Set Desired static IP configuration:
  - IP address: 10.0.0.05
  - Subnet mask: 255.255.255.0
  - Default gateway: 10.0.0.1
  - Select OK.
  - ![page17_img2](https://github.com/user-attachments/assets/e79ce614-a145-4d0e-b188-0812772671e5)

    
## Promote Active Directory to a Domain Controller
  Step 1: Install AD Roles
  - In Server Manager, select Add roles and features.
  - ![page18_img2](https://github.com/user-attachments/assets/2b158211-cc6b-4ff2-8c56-f4054c841d35)

  - Click Next for the first three screens.
  - ![page18_img3](https://github.com/user-attachments/assets/d8acb56c-c352-45db-9fca-5b489e2a1c39)
  - ![page19_img2](https://github.com/user-attachments/assets/09408923-dce8-4473-b10e-a5cd08474120)
  - ![page19_img3](https://github.com/user-attachments/assets/cb1c3d1a-1c32-442d-973e-bb00985a69b0)

  
  Select the following roles:
  - Active Directory Domain Services
  - DHCP Server
  - DNS Server
  - File and Storage Services
  - Web Server (IIS)
  - ![page20_img2](https://github.com/user-attachments/assets/24faccf2-ffe8-41bc-901e-b2a90bd20599)

    
    Keep defaults and click Next until the Confirmation tab.
    Select Install. Close the dialog box during installation.
    Once installed, a notification appears in Server Manager.

  Step 2: Promote to Domain Controller
  - In Server Manager, click the notification → More → Promote this server to a domain.
  - ![page22_img3](https://github.com/user-attachments/assets/eb6b35fe-02b0-471b-a983-eb784fd57b0a)

  - Select Add a new forest and enter the root domain name: corp.hermitt-Sec-dc.com.
  - Use the Administrator password (@dmin123) for the Directory Services Restore Mode (DSRM).
  - Leave Create DNS delegation blank → Next.
  - Keep the NetBIOS name as Desired Name and proceed with defaults until the check screen.
  - Allow the wizard to complete checks, then select Install. The server will restart.
  - Log in using the CORP\Administrator domain.

## Verify domain membership in PowerShell:
  Get-ADDomainController
 - ![Screenshot 2025-05-22 112407](https://github.com/user-attachments/assets/354ef610-8226-4e8c-90e3-de5c36c6cfcb)


## Setup DNS for Internet Access
  Step 1: Configure DNS Forwarders
  - In Server Manager, navigate to DNS → Right-click the server → DNS Manager.
  - ![page28_img2](https://github.com/user-attachments/assets/adcfba52-80b4-4444-a118-74a155e81ca4)

  - Right-click the domain → Properties → Forwarders tab → Edit.
  - ![page30_img2](https://github.com/user-attachments/assets/08d77699-51ba-4929-ab60-7a7c7ee43ad2)

  - Add 8.8.8.8 → OK. This enables internet access from Windows Server 2025.
  
  Verify connectivity in PowerShell:
  - ping google.com
  - nslookup corp.hermitt-Sec-dc.com

##  Setup DHCP
  Step 1: Configure DHCP Scope
  - In Server Manager, navigate to DHCP → DHCP Manager.
  - ![page32_img3](https://github.com/user-attachments/assets/9ef4a596-3465-4f4a-900f-f178484c02ba)

  - Go to IPv4 → New Scope → Name it Hermitt-sec-scope.
  
  Set the following:
  - Start IP address: 10.0.0.100
  - End IP address: 10.0.0.200
  - Subnet mask: 255.255.255.0
  - Proceed with defaults (no IP exclusions or lease expiration).
  - Add 10.0.0.1 as the Router IP.
  - Complete the wizard with default settings.
  - ![page36_img2](https://github.com/user-attachments/assets/aea51da0-15b9-438a-8e7e-8549aed613b2)

  - ![page35_img2](https://github.com/user-attachments/assets/043adbbe-6c73-45c9-9868-8558bf37fc53)


## Add User Accounts in Active Directory

  Step 1: Create Users (Powershell script)
  
    # ----- Edit these Variables for your own Use Case ----- #
    $PASSWORD_FOR_USERS   = "@Password!"
    $USER_FIRST_LAST_LIST = Get-Content .\names.txt
    # ------------------------------------------------------ #
    $password = ConvertTo-SecureString $PASSWORD_FOR_USERS -AsPlainText -Force
    New-ADOrganizationalUnit -Name _USERS -ProtectedFromAccidentalDeletion $false
    
    foreach ($n in $USER_FIRST_LAST_LIST) {
        $first = $n.Split(" ")[0].ToLower()
        $last = $n.Split(" ")[1].ToLower()
        $username = "$($first.Substring(0,1))$($last)".ToLower()
        Write-Host "Creating user: $($username)" -BackgroundColor Black -ForegroundColor Cyan
        
        New-AdUser -AccountPassword $password `
                   -GivenName $first `
                   -Surname $last `
                   -DisplayName $username `
                   -Name $username `
                   -EmployeeID $username `
                   -PasswordNeverExpires $true `
                   -Path "ou=_USERS,$(([ADSI]`"").distinguishedName)" `
                   -Enabled $true
      }

  Step 1: Create Users (GUI interface)
  - In Server Manager, go to Tools → Active Directory Users and Computers.
  - ![page38_img3](https://github.com/user-attachments/assets/a31e6bd1-a7b6-4d57-8b44-8fe75d2b9215)

  - Navigate to Users → New → User.
  - ![page39_img3](https://github.com/user-attachments/assets/9a96546f-97f1-4b7b-9d60-b75c00f79a43)

  - Enter user information.
  - Select User cannot change password → Proceed with default settings.
  - Verify new users appear in the list.
  - ![page41_img3](https://github.com/user-attachments/assets/b19a892d-0eab-41e0-a048-3dd9b4565dd5)


## Final Steps
  Success! Your Active Directory server is now set up.
  Take a Snapshot of the VM to preserve the current state.
 - ![page41_img4](https://github.com/user-attachments/assets/b32eccea-93c3-42f3-8b52-b7cbc2b4f80d)

