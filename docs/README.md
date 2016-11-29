# ThreadFix API Documentation

**Before you start**, its important to understand that all responses to api calls (even when errors occur) are wrapped in a response object. This object mimics the behavior of the ThreadFix API and allows you to simply check if the API call was successful and get the response message. Here is a simple example demonstrating this functionality.

```python
from threadfix_api import threadfix

tf = threadfix.ThreadFixAPI(host, api_key)

teams = tf.list_teams()

if teams.success:  # Was the request a success?
  # Everything worked fine, lets view the response data
  print(teams.data)

  # If we want to print valid json
  print(teams.data_json())

  # Fancy indented json
  print(teams.data_json(pretty=True))
else:
  # Print the reason why the request was not a success
  print(teams.message)
```

If you are using a **self-signed certificate**, you can disable certificate verification when you instantiate the API wrapper. If disabled, API requests could be intercepted by third-parties -- use with caution. Option verify_ssl only applies to host certs.

```python
tf = threadfix.ThreadFixAPI(host, api_key, verify_ssl=False)
```

You can also specify a local cert to use as client side certificate, as a single file (containing the private key and the certificate) or as a tuple of both file’s path:

```python
cert=('/path/server.crt', '/path/key')
tf = threadfix.ThreadFixAPI(host, api_key, cert=cert)
```

## Table of Contents

[Teams](#teams)

- [List Teams: `list_teams`](#list-teams-list_teams)
- [Get Team: `get_team`](##get-team-get_team)
- [Get Team By Name: `get_team_by_name`](#get-team-by-name-get_team_by_name)

[Applications](#applications)

- [Create Application: `create_application`](#create-application-create_application)
- [Get Application: `get_application`](#get-application-get_application)
- [Get Application By Name: `get_application_by_name`](#get-application-by-name-get_application_by_name)
- [Set Application Parameters: `set_application_parameters`](#set-application-parameters-set_application_parameters)
- [Set Application URL: `set_application_url`](#set-application-url-set_application_url)
- [Set Application WAF: `set_application_waf`](#set-application-waf-set_application_waf)

[Findings](#findings)

- [Create Manual Finding: `create_manual_finding`](#create-manual-finding-create_manual_finding)
- [Create Static Finding: `create_static_finding`](#create-static-finding-create_static_finding)
- [Upload Scan: `upload_scan`](#upload-scan-upload_scan)

[WAFs](#wafs)

- [List WAFs: `list_wafs`](#list-wafs-list_wafs)
- [Create WAF: `create_waf`](#create-waf-create_waf)
- [Get WAF: `get_waf`](#get-waf-get_waf)
- [Get WAF By Name: `get_waf_by_name`](#get-waf-by-name-get_waf_by_name)
- [Get WAF Rules: `get_waf_rules`](#get-waf-rules-get_waf_rules)
- [Get WAF Rules By Application: `get_waf_rules_by_application`](#get-waf-rules-by-application-get_waf_rules_by_application)
- [Upload WAF Log: `upload_waf_log`](#upload-waf-log-upload_waf_log)

[Vulnerabilities](#vulnerabilities)

- [Get Vulnerabilities: `get_vulnerabilities`](#get-vulnerabilities-get_vulnerabilities)

## Teams

### List Teams: `list_teams`

Retrieves all the teams.

#### Parameters

_None_

#### Example

```python
tf = threadfix.ThreadFixAPI(host, api_key)
response = tf.list_teams()
```

### Create Team: `create_team`

Creates a team with the given name.

#### Parameters

| Parameter  | Required | Default | Description | Values |
| ---------- | -------- | ------- | ----------- | ------ |
| name | **Yes** |  | The name of the new team that is being created. |  |

#### Example

```python
tf = threadfix.ThreadFixAPI(host, api_key)
response = tf.create_team('Example Team')
```

### Get Team: `get_team`

Retrieves a team using the given team id.

#### Parameters

| Parameter  | Required | Default | Description | Values |
| ---------- | -------- | ------- | ----------- | ------ |
| team_id | **Yes** |  | Team identifier. |  |

#### Example

```python
tf = threadfix.ThreadFixAPI(host, api_key)
response = tf.get_team(4)
```

### Get Team By Name: `get_team_by_name`

Retrieves a team using the given name.

#### Parameters

| Parameter  | Required | Default | Description | Values |
| ---------- | -------- | ------- | ----------- | ------ |
| name | **Yes** |  | The name of the team to be retrieved. |  |

#### Example

```python
tf = threadfix.ThreadFixAPI(host, api_key)
response = tf.get_team_by_name('Home Team')
```

## Applications

### Create Application: `create_application`

Creates an application under a given team.

#### Parameters

| Parameter  | Required | Default | Description | Values |
| ---------- | -------- | ------- | ----------- | ------ |
| team_id    | **Yes**  |  | Team identifier. |  |
| name       | **Yes**  |  | The name of the new team being created. |  |
| url        | No       |  | The url of where application is located. |  |

#### Example

```python
tf = threadfix.ThreadFixAPI(host, api_key)
response = tf.create_application(
  team_id=1,
  name='Example Application',
  url='http://www.example.com/'
)
```

### Get Application: `get_application`

Retrieves an application using the given application id.

#### Parameters

| Parameter  | Required | Default | Description | Values |
| ---------- | -------- | ------- | ----------- | ------ |
| application_id | **Yes** |  | Application identifier. |  |

#### Example

```python
tf = threadfix.ThreadFixAPI(host, api_key)
response = tf.get_application(1)
```

### Get Application By Name: `get_application_by_name`

Retrieves an application using the given team name and application name.

#### Parameters

| Parameter  | Required | Default | Description | Values |
| ---------- | -------- | ------- | ----------- | ------ |
| team_id | **Yes** |  | Team identifier. |  |
| application_id | **Yes** |  | Application identifier. |  |

#### Example

```python
tf = threadfix.ThreadFixAPI(host, api_key)
response = tf.get_application_by_name('Home Team', 'Alfa Application')
```

### Set Application Parameters: `set_application_parameters`

Sets parameters for the Hybrid Analysis Mapping ThreadFix functionality.

#### Parameters

| Parameter  | Required | Default | Description | Values |
| ---------- | -------- | ------- | ----------- | ------ |
| application_id | **Yes** |  | Application identifier. |  |
| framework_type | **Yes** |  | The web framework the app was built on. | `'None'`, `'DETECT'`, `'JSP'`, `'SPRING_MVC'` |
| repository_url | **Yes** |  | The git repository where the source code for the application can be found. |  |

#### Example

```python
tf = threadfix.ThreadFixAPI(host, api_key)
response = tf.set_application_parameters(
  application_id=1,
  framework_type='DETECT',
  repository_url='http://repository.example.com/'
)
```

### Set Application URL: `set_application_url`

Sets the application's URL.

#### Parameters

| Parameter  | Required | Default | Description | Values |
| ---------- | -------- | ------- | ----------- | ------ |
| application_id | **Yes** |  | Application identifier. |  |
| url | **Yes** |  | The url you want to assign to the application. |  |

#### Example

```python
tf = threadfix.ThreadFixAPI(host, api_key)
response = tf.set_application_url(
  application_id=1,
  url='http://www.example.com/'
)
```

### Set Application WAF: `set_application_waf`

Sets the application's WAF to the WAF with the specified id.

#### Parameters

| Parameter  | Required | Default | Description | Values |
| ---------- | -------- | ------- | ----------- | ------ |
| application_id | **Yes** |  | Application identifier. |  |
| waf_id | **Yes** |  | WAF identifier. |  |

#### Example

```python
tf = threadfix.ThreadFixAPI(host, api_key)
response = tf.set_application_waf(
  application_id=4,
  waf_id=3
)
```

## Findings

### Create Manual Finding: `create_manual_finding`

Creates a manual finding with given properties.

#### Parameters

| Parameter  | Required | Default | Description | Values |
| ---------- | -------- | ------- | ----------- | ------ |
| application_id | **Yes** |  | Application identifier. |  |
| vulnerability_type | **Yes** |  | Name of CWE vulnerability. |  |
| description | **Yes** |  | General description of the issue. |  |
| severity | **Yes** |  | Severity level. | 0 - 8 |
| full_url | No |  | Absolute URL to the page with the vulnerability. |  |
| native_id | No |  | Specific identifier for vulnerability. |  |
| path | No |  | Relative path to vulnerability page. |  |

#### Example

```python
tf = threadfix.ThreadFixAPI(host, api_key)
response = tf.create_manual_finding(
  application_id=4,
  vulnerability_type='Location',
  description='This should be addressed',
  severity=3,
  full_url='http://www.samplewebsite.com',
  native_id=24,
  path='/store/3'
)
```

### Create Static Finding: `create_static_finding`

Creates a static finding with given properties.

#### Parameters

| Parameter  | Required | Default | Description | Values |
| ---------- | -------- | ------- | ----------- | ------ |
| application_id | **Yes** |  | Application identifier. |  |
| vulnerability_type | **Yes** |  | Name of CWE vulnerability. |  |
| description | **Yes** |  | General description of the issue. |  |
| severity | **Yes** |  | Severity level. | 0 - 8 |
| parameter | _See Note_ |  | Request parameter for vulnerability. |  |
| file_path | _See Note_ |  | Location of source file. |  |
| native_id | No |  | Specific identifier for vulnerability. |  |
| column | No |  | Column number for finding vulnerability source. |  |
| line_text | No |  | Specific line text to finding vulnerability. |  |
| line_number | No |  | Specific source line number to finding vulnerability. |  |

**Note:** Either `parameter` or `file_path` must be specified. If not, a ValueError will be raised.

#### Example

```python
tf = threadfix.ThreadFixAPI(host, api_key)
response = tf.create_static_finding(
  application_id=4,
  vulnerability_type='Location',
  description='This should be addressed',
  severity=3,
  parameter='store',
  native_id=24,
  column=2,
  line_text='findStore()',
  line_number='234'
)
```

### Upload Scan: `upload_scan`

Uploads and processes a scan file.

#### Parameters

| Parameter  | Required | Default | Description | Values |
| ---------- | -------- | ------- | ----------- | ------ |
| application_id | **Yes** |  | Application identifier. |  |
| file_path | **Yes** |  | Path to the scan file to be uploaded. |  |

#### Example

```python
tf = threadfix.ThreadFixAPI(host, api_key)
response = tf.upload_scan(
  application_id=4,
  file_path='/home/threadfix/zap_scan.xml'
)
```

## WAFs

### List WAFs: `list_wafs`

Retrieves all WAFs in system.

#### Parameters

_None_

#### Example

```python
tf = threadfix.ThreadFixAPI(host, api_key)
response = tf.list_wafs()
```

### Create WAF: `create_waf`

Creates a WAF with the given type.

#### Parameters

| Parameter  | Required | Default | Description | Values |
| ---------- | -------- | ------- | ----------- | ------ |
| name | **Yes** |  | Name of the WAF. |  |
| waf_type | **Yes** |  | WAF type. | `'mod_security'`, `'Snort'`, `'Imperva SecureSphere'`, `'F5 BigIP ASM'`, `'DenyAll rWeb'` |

#### Example

```python
tf = threadfix.ThreadFixAPI(host, api_key)
response = tf.create_waf(
  name='My Application WAF',
  waf_type='mod_security'
)
```

### Get WAF: `get_waf`

Retrieves WAF using the given WAF id.

#### Parameters

| Parameter  | Required | Default | Description | Values |
| ---------- | -------- | ------- | ----------- | ------ |
| waf_id | **Yes** |  | WAF identifier. |  |

#### Example

```python
tf = threadfix.ThreadFixAPI(host, api_key)
response = tf.get_waf(4)
```

### Get WAF By Name: `get_waf_by_name`

Retrieves waf using the given name.

#### Parameters

| Parameter  | Required | Default | Description | Values |
| ---------- | -------- | ------- | ----------- | ------ |
| name | **Yes** |  | Name of the WAF. |  |

#### Example

```python
tf = threadfix.ThreadFixAPI(host, api_key)
response = tf.get_waf_by_name('My Application WAF')
```

### Get WAF Rules: `get_waf_rules`

Retrieves all the rules for WAF with the given WAF id.

#### Parameters

| Parameter  | Required | Default | Description | Values |
| ---------- | -------- | ------- | ----------- | ------ |
| waf_id | **Yes** |  | WAF identifier. |  |

#### Example

```python
tf = threadfix.ThreadFixAPI(host, api_key)
response = tf.get_waf_rules(4)
```

### Get WAF Rules By Application: `get_waf_rules_by_application`

Returns the WAF rule text for one or all of the applications in a WAF. If the application id is -1, it will get rules for all apps. If the application is a valid application id, rules will be generated for that application.

#### Parameters

| Parameter  | Required | Default | Description | Values |
| ---------- | -------- | ------- | ----------- | ------ |
| waf_id | **Yes** |  | WAF identifier. |  |
| application_id | **Yes** |  | Application identifier. |  |

#### Example

```python
tf = threadfix.ThreadFixAPI(host, api_key)
response = tf.get_waf_rules_by_application(4, 1)
```

### Upload WAF Log: `upload_waf_log`

Uploads and processes a WAF log file.

#### Parameters

| Parameter  | Required | Default | Description | Values |
| ---------- | -------- | ------- | ----------- | ------ |
| waf_id | **Yes** |  | WAF identifier. |  |
| file_path | **Yes** |  | Path to the WAF log file to be uploaded. |  |

#### Example

```python
tf = threadfix.ThreadFixAPI(host, api_key)
response = tf.upload_waf_log(
  waf_id=4,
  file_path='/home/threadfix/mod_secuity.log'
)
```

## Vulnerabilities

### Get Vulnerabilities: `get_vulnerabilities`

Returns filtered list of vulnerabilities.

#### Parameters

| Parameter  | Required | Default | Description | Values |
| ---------- | -------- | ------- | ----------- | ------ |
| teams | No |  | List of team ids. |  |
| applications | No |  | List of application ids. |  |
| channel_types | No |  | List of scanner names. |  |
| start_date | No |  | Lower bound on scan dates. |  |
| end_date | No |  | Upper bound on scan dates. |  |
| generic_severities | No |  | List of generic severity values. |  |
| generic_vulnerabilities | No |  | List of generic vulnerability ids. |  |
| number_merged | No |  | Number of vulnerabilities merged from different scans. |  |
| number_vulnerabilities | No |  | Number of vulnerabilities to return. |  |
| parameter | No |  | Application input that the vulnerability affects. |  |
| path | No |  | Path to the web page where the vulnerability was found. |  |
| show_open | No |  | Flag to show all open vulnerabilities. |  |
| show_closed | No |  | Flag to show all closed vulnerabilities. |  |
| show_defect_open | No |  | Flag to show any vulnerabilities with open defects. |  |
| show_defect_closed | No |  | Flag to show any vulnerabilities with closed defects. |  |
| show_defect_present | No |  | Flag to show any vulnerabilities with a defect. |  |
| show_defect_not_present | No |  | Flag to show any vulnerabilities without a defect. |  |
| show_false_positive | No |  | Flag to show any false positives from vulnerabilities. |  |
| show_hidden | No |  | Flag to show all hidden vulnerabilities. |  |

#### Example

```python
tf = threadfix.ThreadFixAPI(host, api_key)
# Get all vulnerabilities
response = tf.get_vulnerabilities()
```

```python
tf = threadfix.ThreadFixAPI(host, api_key)
# Get open vulnerabilities
response = tf.get_vulnerabilities(show_open=True)
```

```python
tf = threadfix.ThreadFixAPI(host, api_key)
# Get vulnerabilities for specific applications
response = tf.get_vulnerabilities(applications=[4, 8, 15, 16, 23, 42])
```
