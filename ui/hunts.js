window.hunts = [
  {
    name: "Successful logon",
    tactic: "Credential Access",
    technique: "T1078 Valid Accounts",
    sql: "SELECT record_id, time_created, computer,\n  json_extract_string(event_data, '$.TargetUserName') AS user,\n  json_extract_string(event_data, '$.LogonType') AS logon_type,\n  json_extract_string(event_data, '$.IpAddress') AS ip\nFROM events\nWHERE event_id = 4624\nORDER BY time_created"
  },
  {
    name: "Network logon",
    tactic: "Lateral Movement",
    technique: "T1021 Remote Services",
    sql: "SELECT record_id, time_created, computer,\n  json_extract_string(event_data, '$.TargetUserName') AS user,\n  json_extract_string(event_data, '$.IpAddress') AS ip,\n  json_extract_string(event_data, '$.WorkstationName') AS workstation\nFROM events\nWHERE event_id = 4624\n  AND json_extract_string(event_data, '$.LogonType') = '3'\nORDER BY time_created"
  },
  {
    name: "Failed logon",
    tactic: "Credential Access",
    technique: "T1110 Brute Force",
    sql: "SELECT record_id, time_created, computer,\n  json_extract_string(event_data, '$.TargetUserName') AS user,\n  json_extract_string(event_data, '$.IpAddress') AS ip\nFROM events\nWHERE event_id = 4625\nORDER BY time_created"
  },
  {
    name: "Explicit credentials",
    tactic: "Credential Access",
    technique: "T1078 Valid Accounts",
    sql: "SELECT record_id, time_created, computer,\n  json_extract_string(event_data, '$.SubjectUserName') AS caller,\n  json_extract_string(event_data, '$.TargetUserName') AS target,\n  json_extract_string(event_data, '$.IpAddress') AS ip\nFROM events\nWHERE event_id = 4648\nORDER BY time_created"
  },
  {
    name: "Account created",
    tactic: "Persistence",
    technique: "T1136 Create Account",
    sql: "SELECT record_id, time_created, computer,\n  json_extract_string(event_data, '$.TargetUserName') AS user,\n  json_extract_string(event_data, '$.TargetSid') AS sid\nFROM events\nWHERE event_id = 4720\nORDER BY time_created"
  },
  {
    name: "Account changed",
    tactic: "Persistence",
    technique: "T1098 Account Manipulation",
    sql: "SELECT record_id, event_id, time_created, computer,\n  json_extract_string(event_data, '$.TargetUserName') AS user\nFROM events\nWHERE event_id IN (4722, 4724, 4726, 4738)\nORDER BY time_created"
  },
  {
    name: "Special privileges",
    tactic: "Privilege Escalation",
    technique: "T1078 Valid Accounts",
    sql: "SELECT record_id, time_created, computer,\n  json_extract_string(event_data, '$.SubjectUserName') AS user,\n  json_extract_string(event_data, '$.PrivilegeList') AS privileges\nFROM events\nWHERE event_id = 4672\nORDER BY time_created"
  },
  {
    name: "One account",
    tactic: "Discovery",
    technique: "T1087 Account Discovery",
    sql: "SELECT record_id, event_id, time_created, computer\nFROM events\nWHERE json_extract_string(event_data, '$.TargetUserName') = 'USER'\n   OR json_extract_string(event_data, '$.SubjectUserName') = 'USER'\nORDER BY time_created"
  }
];
