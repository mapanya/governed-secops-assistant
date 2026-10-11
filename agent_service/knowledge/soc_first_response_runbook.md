# Security Operations First-Response Runbook

Classification: internal. Owner: security operations manager. Review cycle: every six months.

## How to use this runbook

This runbook tells a security operations analyst what to do in the first hour of the most common incident types. Each section lists the first-response steps in order. Steps marked "approval required" change a live system, so the analyst prepares the change and a named approver confirms it before it is carried out. Every incident is logged in the case management system with a case number before any step is taken and every action is recorded against that case.

## Severity levels and response times

Severity 1 (critical): business-wide outage, active ransomware, or confirmed theft of personal or customer data. Response starts within 15 minutes, around the clock. The incident manager and the chief information security officer are informed immediately.
Severity 2 (high): a confirmed compromise limited to one system or one account. Response starts within 1 hour.
Severity 3 (medium): suspicious activity that is not yet confirmed. Response starts within 4 hours.
Severity 4 (low): policy breaches and informational alerts. Response starts within 1 business day.
When in doubt, choose the higher severity and lower it later with a recorded reason.

## Phishing email reported

1. Thank the reporter and ask them not to forward, reply to or delete the message.
2. Collect the original message with full headers as evidence and record the sender address, subject, links and attachment names in the case.
3. Check the mail logs to find every recipient of the same message.
4. Check whether any recipient clicked a link, opened an attachment or entered credentials.
5. If credentials were entered, follow the compromised account steps for that user.
6. Approval required: remove the message from all mailboxes and block the sender domain and the linked web addresses at the mail and web gateways.
7. Send a short awareness note to affected staff and close the case with the lessons learned.

## Ransomware or mass file encryption

1. Treat as severity 1 and inform the incident manager immediately.
2. Identify the affected devices from alerts, file share activity and user reports.
3. Approval required: isolate affected devices from the network using the endpoint protection console. Do not switch devices off, because memory evidence would be lost.
4. Approval required: disable accounts that show signs of misuse and suspend scheduled tasks that copy or synchronise files.
5. Preserve evidence: ransom notes, sample encrypted files, endpoint alerts and relevant logs, recorded with a chain of custody.
6. Confirm that backups are intact and disconnected before any restore is planned.
7. Do not contact the attackers or pay a ransom. Any contact is decided by the crisis management team with legal advice.

## Compromised user account

Typical signs are sign-ins from impossible locations, repeated multi-factor prompts the user did not start, new mailbox forwarding rules and unusual access to sensitive files.
1. Confirm the activity with the user by phone, not by email.
2. Approval required: reset the password, revoke active sessions and tokens and re-register multi-factor authentication.
3. Remove any forwarding rules, mailbox delegations or application consents that the user did not create.
4. Review what the account accessed during the suspicious period and record any data that may have been exposed.
5. If personal or customer data was accessed, raise the case to severity 1 and inform the privacy officer.

## Malware detected on an endpoint

1. Check the alert details: file name, fingerprint (hash), detection name and the action the endpoint protection tool already took.
2. Search for the same fingerprint on other devices.
3. Approval required: isolate the device if the malware is active or spreading.
4. Collect the endpoint timeline and the malicious file sample through the approved evidence tool only.
5. Remove the malware or rebuild the device from a clean image, then monitor it for seven days.

## Suspected data exfiltration

1. Treat as severity 1 until the volume and type of data are understood.
2. Identify the source system, the account, the destination and the amount of data from proxy, firewall and cloud logs.
3. Approval required: block the destination at the perimeter and suspend the account involved.
4. Preserve logs that cover the full period of the transfer.
5. The privacy officer decides with legal advice whether regulators and affected people must be notified. Where personal data is involved, many regulations require notification within 72 hours of becoming aware of the breach.

## Lost or stolen device

1. Record when and where the device was last seen and whether it was encrypted.
2. Approval required: lock or wipe the device remotely through device management and revoke its certificates and sessions.
3. Reset the passwords of accounts used on the device.
4. If the device held sensitive data and was not encrypted, raise the case to severity 1.

## Escalation contacts

Contacts are listed by role and the on-call rota in the case management system shows who holds each role today.
- Security operations shift lead: first escalation for every case.
- Incident manager: leads severity 1 and severity 2 incidents and runs the incident bridge.
- Chief information security officer: informed of every severity 1 incident within 15 minutes.
- Privacy officer: decides on notifications when personal data is involved.
- Legal counsel and communications: join severity 1 incidents that may need external statements.

## Evidence handling

Collect evidence with approved tools only and record who collected it, when, from where and how it was stored. Calculate a fingerprint (hash) of every file at collection time and again whenever it is handed over. Store evidence in the restricted evidence share, never on personal devices or in email.

## Actions that always need a second person

The following actions change live systems and always need approval from the shift lead or the incident manager before they are carried out: isolating a device, disabling or resetting an account, blocking an address or domain at the perimeter, deleting messages from mailboxes, wiping a device and restoring data from backup. The approval and the approver's name are recorded in the case.
