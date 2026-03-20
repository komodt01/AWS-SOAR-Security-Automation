# Threat Model (STRIDE)

## Spoofing
Risk: Unauthorized identity generating logs  
Mitigation: IAM + CloudTrail validation  

## Tampering
Risk: Logs altered/deleted  
Mitigation: S3 Versioning  

## Repudiation
Risk: Actions denied by actors  
Mitigation: CloudTrail audit logs  

## Information Disclosure
Risk: Exposure of sensitive logs  
Mitigation: Encryption + access controls  

## Denial of Service (Cost/Storage)
Risk: Log explosion causing cost/performance issues  
Mitigation: Lifecycle policies + monitoring  

## Elevation of Privilege
Risk: Unauthorized access to logs  
Mitigation: Least privilege IAM policies  
