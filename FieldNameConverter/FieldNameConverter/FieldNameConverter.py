import os
import re

#To Do:
#- Fix rules which don't reference a keyword

fieldMap = {
    #Runtime Sensitive Field Remaps
    "name:": "file.path:",
    "name like~": "file.path like~",
    
    #Generic Fields
    "EventID": "event.code",
    "EventType": "event.type",

    "action:": "event.action:",
    "action like~": "event.action like~",

    "blocked": "event.outcome",
    "Provider_Name": "event.provider",
    "ErrorCode": "error.code",

    #User Context
    "User:": "user.name:",
    "User like~": "user.name like~",
    "SubjectUserName": "user.name",

    #Process
    "ParentImage:": "process.parent.executable",
    "Parentprocess.executable": "process.parent.executable",
    "ImagePath": "process.executable",

    "Image:": "process.executable:",
    "Image like~": "process.executable like~",

    "ModifyingApplication": "process.executable",
    "processPath": "process.executable",
    "ApplicationPath": "process.executable",
    "process.executablefile.path": "process.executable",

    "LocalName": "process.name",
    "ProcessName": "process.name",

    #Need to Verify Functionality
    #"Type:": "process.env_vars:",
    #"Type like~": "process.env_vars like~",

    "OriginalFileName": "process.pe.original_file_name",
    "Description": "process.pe.description",

    #winlog.event_data
    "Channel": "winlog.channel",

    "QueryName": "winlog.event_data.QueryName",
    "ImageName": "winlog.event_data.ImageName",
    "DeviceName": "winlog.event_data.DeviceName",

    "FileNameBuffer": "winlog.event_data.Buffer",
    "ProcessNameBuffer": "winlog.event_data.Buffer",

    "AttributeLDAPDisplayName:": "winlog.event_data.AttributeLDAPDisplayName",
    "AttributeValue": "winlog.event_data.AttributeValue",

    "ObjectType": "winlog.event_data.ObjectType",
    "ObjectName": "winlog.event_data.ObjectName",

    "Product": "winlog.event_data.Product",
    "LogonType": "winlog.event_data.LogonType",

    "ServicePrincipalNames": "winlog.event_data.ServicePrincipalNames",
    "DestinationHostName": "Winlog.event_data.DNSHostName",

    "SubjectLogonId": "winlog.event_data.SubjectLogonId",
    "SubcategoryGuid": "winlog.event_data.SubcategoryGuid",
    "AuditPolicyChanges": "winlog.event_data.AuditPolicyChanges",
    "AccessMask": "winlog.event_data.AccessMask",

    #File
    "Path:": "file.path:",
    "Path like~": "file.path like~",
    "ImageLoaded": "file.path",
    
    "CurrentDirectory": "file.directory",

    #Registry
    "TargetObject": "registry.path",
    "Details": "registry.data.strings",

    #Network Connection
    "RemoteName": "destination.domain",
    "Dst_port": "destination.port",
    "ServiceName": "service.name",
    "IpAddress": "source.ip",

    #Scripting/Command Line
    "CommandLine": "process.command_line",

    #PowerShell
    "ScriptBlockText": "powershell.file.script_block_text",

    "Data:": "powershell.file.script_block_text:",
    "Data like~": "powershell.file.script_block_text like~",

    #x509 Fields
    "subjectName": "x509.subject.distinguished_name",
    "certificate.serial": "x509.serial_number",
    
    #RDS
    "address:": "client.address:",
    "address like~": "client.address like~",
    #"query": "dns.question.name", - conflicting with object

    #Other
    "PackageFullName": "package.name",

    #Configuration, OldValue, NewValue (in context of EC 29)
    #DistinguishedName, SearchFilter, objectclass (EC "30")
    #TargetUserSid, SidList
    #Data (EC 6)
    #WorkstationName (EC 8004)
    #TargetName (EC 8001)
    #process, payload (EC 4)
}

directory = r"E:\all projects ever... mostly\2026\Work\Elastic_Sigma_Rules"

def FieldRemap():
    for filename in os.listdir(directory):
        if filename.endswith(".ndjson"):
            path = os.path.join(directory, filename)

            with open(path, "r") as file:
                content = file.read()

            for oldField, newField in fieldMap.items():
                content = content.replace(oldField, newField)
                print(newField + " Field Remapped...\n")

            with open(path, "w") as file:
                file.write(content)
                print("File's Fields Remapped...\n")

def HashValueReplacement(content):
    #Check if hash is md5, sha1, or sha256 and sub Hashes for File.hash.[type]
    #Hash and Hashes - need to check imphash data fieldname in Elastic

    content = re.sub(r'\\\"\*.{1,10}=([a-fA-F0-9]{32,64})\*\\\"', r'"\1"', content) #Cleans Hash data

    content = re.sub(r'(Hashes\: )(\".{32}\")', r'File.hash.imphash\: \2', content)
    content = re.sub(r'(Hashes\: )(\".{40}\")', r'File.hash.sha1\: \2', content)
    content = re.sub(r'(Hashes\: )(\".{64}\")', r'File.hash.sha256\: \2', content)

    content = re.sub(r'Hashes like~ \(((\".{32}\", ){1,50}(\".{32}\"\)))', r'File.hash.imphash like~ \(\1', content)
    content = re.sub(r'Hashes like~ \(((\".{40}\", ){1,50}(\".{40}\"\)))', r'File.hash.sha1 like~ \(\1', content)
    content = re.sub(r'Hashes like~ \(((\".{64}\", ){1,50}(\".{64}\"\)))', r'File.hash.sha256 like~ \(\1', content)

    return content

def ListCorrection(match):
    return re.sub(r"(\d+)", r'\"\1\"', match.group(0))

def SyntaxCorrection():
    for filename in os.listdir(directory):
        if filename.endswith(".ndjson"):
            path = os.path.join(directory, filename)

            with open(path, "r") as file:
                content = file.read()
            
                #Fix feedname, index patterns, hashes, and tags (Raven/Sigma)
                content = content.replace("\"query\": \"any where", "\"query\": \"any where feedname: \\\"raven\\\" and")
                content = re.sub(r'(\"index\": )(\[.*\], "query")', r'\1["logs-*-raven*"], "query"', content)
                content = re.sub(r'(\"tags\": )(\[.*\], "to")', r'\1["Raven", "Sigma"], "to"', content)
                content = HashValueReplacement(content)

                #put event.codes in ""
                content = re.sub(r'(event\.code:)([0-9]{1,5})', r'\1\"\2\"', content)

                content = re.sub(r'(event\.code like~ \()(([0-9]{1,5}, ){1,50}[0-9]{1,5}\))', ListCorrection, content)
            with open(path, "w") as file:
                file.write(content)
                print("Syntax Corrected...\n")

#Runtime
FieldRemap()
SyntaxCorrection()
print("Migration Successful")