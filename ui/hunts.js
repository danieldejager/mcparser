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
  },
  {
    name: "Process ran",
    tactic: "Execution",
    technique: "T1059 Command and Scripting Interpreter",
    sql: "SELECT host_id, executable, run_count, last_run, path\nFROM prefetch\nORDER BY last_run DESC"
  },
  {
    name: "Recently executed",
    tactic: "Execution",
    technique: "T1059 Command and Scripting Interpreter",
    sql: "SELECT host_id, name, run_count, last_run\nFROM userassist\nORDER BY last_run DESC"
  },
  {
    name: "Program inventory",
    tactic: "Discovery",
    technique: "T1518 Software Discovery",
    sql: "SELECT host_id, kind, name, path, publisher, version\nFROM amcache\nORDER BY modified DESC"
  },
  {
    name: "Service binary",
    tactic: "Persistence",
    technique: "T1543 Create or Modify System Process",
    sql: "SELECT host_id, name, display_name, state, start_mode, path, user_id\nFROM services\nORDER BY name"
  },
  {
    name: "Scheduled task",
    tactic: "Persistence",
    technique: "T1053 Scheduled Task/Job",
    sql: "SELECT host_id, path, command, arguments, user_id, enabled\nFROM tasks\nORDER BY path"
  },
  {
    name: "Shim cache entry",
    tactic: "Defense Evasion",
    technique: "T1036 Masquerading",
    sql: "SELECT host_id, path, last_modified\nFROM shimcache\nORDER BY last_modified DESC"
  },
  {
    name: "Network use",
    tactic: "Command and Control",
    technique: "T1071 Application Layer Protocol",
    sql: "SELECT host_id, app, bytes_sent, bytes_received, user_id\nFROM srum\nORDER BY bytes_sent DESC"
  },
  {
    name: "New service",
    tactic: "Persistence",
    technique: "T1543 Create or Modify System Process",
    sql: "SELECT record_id, time_created, computer,\n  json_extract_string(event_data, '$.ServiceName') AS service,\n  json_extract_string(event_data, '$.ImagePath') AS path\nFROM events\nWHERE event_id = 7045\nORDER BY time_created"
  },
  {
    name: "Task registered",
    tactic: "Persistence",
    technique: "T1053 Scheduled Task/Job",
    sql: "SELECT record_id, time_created, computer,\n  json_extract_string(event_data, '$.TaskName') AS task,\n  json_extract_string(event_data, '$.TaskContent') AS content\nFROM events\nWHERE event_id = 4698\nORDER BY time_created"
  },
  {
    name: "Process created",
    tactic: "Execution",
    technique: "T1059 Command and Scripting Interpreter",
    sql: "SELECT record_id, time_created, computer,\n  json_extract_string(event_data, '$.NewProcessName') AS process,\n  json_extract_string(event_data, '$.CommandLine') AS command,\n  json_extract_string(event_data, '$.SubjectUserName') AS user\nFROM events\nWHERE event_id = 4688\nORDER BY time_created"
  },
  {
    name: "Audit cleared",
    tactic: "Defense Evasion",
    technique: "T1070 Indicator Removal",
    sql: "SELECT record_id, time_created, computer,\n  json_extract_string(event_data, '$.SubjectUserName') AS user\nFROM events\nWHERE event_id = 1102\nORDER BY time_created"
  },
  {
    name: "Time changed",
    tactic: "Defense Evasion",
    technique: "T1070.006 Timestomp",
    sql: "SELECT record_id, time_created, computer,\n  json_extract_string(event_data, '$.SubjectUserName') AS user,\n  json_extract_string(event_data, '$.PreviousTime') AS previous,\n  json_extract_string(event_data, '$.NewTime') AS new_time\nFROM events\nWHERE event_id = 4616\nORDER BY time_created"
  },
  {
    name: "Firewall changed",
    tactic: "Defense Evasion",
    technique: "T1562 Impair Defenses",
    sql: "SELECT record_id, time_created, computer,\n  json_extract_string(event_data, '$.RuleName') AS rule,\n  json_extract_string(event_data, '$.ModifyingApplication') AS app\nFROM events\nWHERE event_id IN (4946, 4947)\nORDER BY time_created"
  },
  {
    name: "Application crash",
    tactic: "Impact",
    technique: "T1499 Endpoint Denial of Service",
    sql: "SELECT record_id, time_created, computer, provider,\n  json_extract_string(event_data, '$.param1') AS app\nFROM events\nWHERE channel = 'Application' AND event_id = 1000\nORDER BY time_created"
  }

];
