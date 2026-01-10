# Import Veracode Static Analysis Flaws to GitHub Issues or Azure DevOps Work Items - GitHub Action

This action can be used in a workflow after a Veracode Static Analysis (either Pipeline Scan or Policy/Sandbox scan) to take the results of the scan and import them into GitHub as Issues or Azure DevOps as Work Items.

**New Feature**: For Policy scans, the action now supports an advanced annotation-based workflow that allows security teams to automatically manage issue lifecycle through Veracode annotations, including automatic issue closing for approved mitigations and reopening for rejected ones.

## Supported Defect Tracking Systems

This action supports two defect tracking systems:
- **GitHub Issues** (default) - Creates issues in GitHub repositories
- **Azure DevOps Work Items** - Creates work items in Azure DevOps projects

The system is selected using the `dts_type` parameter, which defaults to `GITHUB` if not specified.

## Important Note on Issue/Work Item Management

This action will **open, reopen, and close** issues/work items based on the current scan results:

- **New findings**: Creates new work items
- **Existing findings**: Reopens closed work items or skips if already open
- **Resolved findings**: Closes work items that are no longer present in the scan results (when `autoCloseFindings` is enabled)

This ensures that security findings remain tracked and visible until properly addressed, and that resolved issues are automatically closed when they no longer appear in scans.

### Auto-Close Behavior

By default, the action will **not** automatically close issues/work items that are no longer present in scan results. To enable this behavior, set the `autoCloseFindings` parameter to `true`.

**When `autoCloseFindings: true`:**
- Issues/work items that are no longer present in the current scan results will be automatically closed
- This helps keep your issue tracker clean by removing resolved security findings

**When `autoCloseFindings: false` or not set (default):**
- No issues/work items will be closed automatically
- Only new issues/work items will be created and existing ones will be reopened if needed

## Importing Pipeline Scan flaws
For a Pipeline Scan, this is typically done with the filtered results of the Pipeline Scan, see [Pipeline Scan commands](https://help.veracode.com/r/r_pipeline_scan_commands).  

Note that when Issues are added, a tag is inserted into the Issue title.  The tag is of the form `[VID:<cwe>:<file>:<line>]`.  There is some very simple matching of same file, same CWE, +/- 10 lines that will get resolved as the same issue.

## Importing Policy/Sandbox Scan flaws

For a Policy or Sandbox scan, you can either:

1. **Use API-based fetching (Recommended)**: Provide `profile-name` (and optionally `sandbox-name`) along with `veracode-api-id` and `veracode-api-key`. The action will automatically fetch findings directly from the Veracode API with annotations included (`include_annot=TRUE`), but only policy-relevant findings (`violates_policy=True`) will be loaded.

2. **Use file-based approach**: Download findings manually using the Findings REST API call (see [Findings REST API](https://help.veracode.com/r/c_findings_v2_intro)) and provide the file path via `scan-results-json`.

**Important**: To enable the annotation-based workflow, ensure your API call includes the `include_annot=TRUE` parameter to fetch annotations along with the findings data. When using API-based fetching, this is automatically included.

**Note**: When sandbox findings are loaded (using `sandbox-name`), issues and work items will be automatically tagged with `sandbox-{SANDBOX_NAME}`.

Note that when Issues are added, a tag is inserted into the Issue title.  The tag is of the form `[VID:<flaw_number>]`.  This tag is used to prevent duplicate issues from getting created.

## Importing SCA (Software Composition Analysis) Findings

The action supports importing SCA findings in addition to static scan findings. SCA findings identify vulnerable third-party components and dependencies in your application.

**Important**: SCA findings can only be imported when using API-based fetching (with `profile-name` and `veracode-api-id`/`veracode-api-key`). File-based SCA import is not currently supported.

### How SCA Findings Work

When `include-sca: true` is set along with API-based fetching:

1. **API Calls**: The action fetches SCA findings using `scan_type=SCA` (no `include_annot` or `violates_policy` parameters needed)
2. **Filtering**: Only findings where `finding_status.status === "OPEN"` AND `violates_policy === true` are processed
3. **Issue/Work Item Creation**: Each SCA finding creates a separate issue or work item

### SCA Finding Format

**Title**: `Veracode SCA - {CVE-NAME} - {COMPONENT-FILENAME}`

**Body includes**:
- Component filename and CVE name
- Vulnerability description
- CVSS score and severity
- EPSS percentile and score (if available)
- CVE link (if available)
- License information (if available)

**Labels/Tags**:
- `Veracode-SCA` (always added)
- `CVE-{CVE-NAME}` (CVE identifier)
- Severity label (based on CVE severity: Very High, High, Medium, Low, etc.)
- `sandbox-{SANDBOX_NAME}` (if findings come from a sandbox)

### SCA Finding Lifecycle

- **New findings**: Creates new issues/work items
- **Existing findings**: Reopens closed issues/work items if they reappear
- **Resolved findings**: Closes issues/work items when `finding_status.status === "CLOSED"` or when findings are no longer present in scan results (if `autoCloseFindings: true`)

### Annotation-Based Workflow (Policy Scans Only)

For Policy scans, the action supports an advanced annotation-based workflow that allows security teams to manage issue lifecycle through Veracode annotations. This feature is only available for Policy scans and requires:

1. **API Parameter**: The Veracode API call must include `include_annot=TRUE` to fetch annotations
2. **Data Structure**: The scan results must include an `annotations` array for each finding

#### How It Works

When a Policy scan includes annotations, the action will:

1. **Process each finding's annotations** to determine the appropriate action
2. **Make decisions based on the most recent annotation** (by creation date)
3. **Automatically manage issue state** based on annotation actions

#### Supported Annotation Actions

- **`APPROVED`** - Closes the GitHub issue (indicates the finding has been properly mitigated)
- **`REJECTED`** - Reopens closed issues or keeps open issues open (indicates the mitigation was rejected)
- **Other actions** (e.g., `OSENV`, `FALSE_POSITIVE`, etc.) - Updates the issue with annotation comments (indicates proposed mitigations)

#### Annotation Comments

Each annotation generates a structured comment on the GitHub issue with the following format:

```markdown
## Veracode Mitigation

**Action:** [APPROVED/REJECTED/OSENV/etc.]
**Comment:** [annotation comment]
**Date:** [formatted date]
**User:** [user name]

> **Note:** This is a proposed mitigation, please talk to your security team for approval.
```

*Note: The "proposed mitigation" message only appears for actions that are neither APPROVED nor REJECTED.*

#### Workflow Examples

**Scenario 1: Approved Mitigation**
- Finding has annotation: `{ "action": "APPROVED", "comment": "Fixed in latest commit", ... }`
- Result: GitHub issue is closed with the annotation comment

**Scenario 2: Rejected Mitigation**
- Finding has annotation: `{ "action": "REJECTED", "comment": "This approach has security concerns", ... }`
- Result: GitHub issue is reopened (if closed) or kept open, with the annotation comment

**Scenario 3: Proposed Mitigation**
- Finding has annotation: `{ "action": "OSENV", "comment": "Should use environment variables", ... }`
- Result: GitHub issue is updated with the annotation comment (including the proposed mitigation note)

#### Fallback Behavior

If a Policy scan does not include annotations, the action falls back to the standard workflow:
- Creates new issues for new findings
- Links existing issues to pull requests when running on PRs
- Closes issues for findings no longer present (when `autoCloseFindings` is enabled)  
  
## Pull request decoration (GitHub only)
This action supports pull request decoration when using GitHub Issues. Once an issue is generated and the job runs on a PR, the issue will automatically be linked to the PR. This is done for easy review and an easy approval process.  
  
## Fail the build upon findings  
As this job needs to run after a Veracode pipeline/sandbox/policy scan, the scan job cannot fail the pipeline upon findings as otherwiese the following job, this flaws-to-issues job, won't be started. In order to still fail the pipeline this action now includes and option to fail the pipeline upon findings. Make sure you pass the correct pipelins-scan results or download the correct sandbox/policy scan results (most probably all unmitigated, policy relevant findings) to fail the pipeline.  
  
---

## Inputs

### `dts_type`

**Optional** Type of defect tracking system to use. Valid values are `GITHUB` or `ADO`.
| Default value | `"GITHUB"` |
--- | ---

### `scan-results-json`

**Required** (when not using API-based fetching) The path to the scan results file in JSON format.  The scan type, Pipeline or Policy/Sandbox, is auto-detected based on the input file and imported issues are labeled appropriately.

**Note:** This parameter is optional when using API-based fetching with `profile-name` or `sandbox-name`. If `profile-name` or `sandbox-name` is provided, the action will fetch findings directly from the Veracode API instead of using this file.
|Default value |  `"filtered_results.json"`|
--- | ---

### `wait-time`

**Optional** GitHub (at least the free/public version) has a rate limiter to prevent a user from adding Issues too quickly.  This value is used to insert a small delay between each new issue created so as to not trip the rate limiter.  This value sets the number of seconds between each issue.  See [here](https://docs.github.com/en/rest/guides/best-practices-for-integrators#dealing-with-rate-limits) for additional information.
| Default value | `"2"` |
--- | ---
  
### `source_base_path_1`, `source_base_path_2`, `source_base_path_3`
   
**Optional** In some compilations, the path representation is not the same as the repository root folder. In order to add the ability to navigate back from the scanning issue to the file in the repository, a base path to the source is required. The input format is regex base (`"[search pattern]:[replace with pattern]"`).
| Default value | `""` |
--- | ---  

Example:  
```yml
source-base-path-1: "^com/veracode:src/main/java/com/veracode"
source-base-path-2: "^WEB-INF:src/main/webapp/WEB-INF"
```  
  
### `fail_build`
   
**Optional** If a previous task run and was set to `fail_build: false` as you need to run this `flaws-to-issues` action after the scan is finished but you still need to fail the pipeline based on findings from a Veracode scan, this option is require to be set to `true`.
| Default value | `""` |
--- | ---   

### `autoCloseFindings`

**Optional** Controls whether issues/work items that are no longer present in scan results should be automatically closed. When set to `true`, the action will close issues/work items that were previously created but are no longer found in the current scan results. This helps keep your issue tracker clean by removing resolved security findings.

**Valid values:** `"true"` or `"false"` (as strings) or `true` or `false` (as booleans)
| Default value | `"false"` |
|--- | ---

### Veracode API inputs (for API-based fetching)

### `profile-name`

**Optional** Veracode application profile name. When provided along with `veracode-api-id` and `veracode-api-key`, the action will fetch findings directly from the Veracode API instead of using a file.

**Note:** This parameter is required when using API-based fetching. It is not needed when using `scan-results-json` with a file.
| Default value | `""` |
|--- | ---

### `sandbox-name`

**Optional** Veracode sandbox name. When provided along with `profile-name`, the action will fetch findings from the specified sandbox instead of the policy scan.

**Note:** This parameter requires `profile-name` to be specified. When sandbox findings are loaded, issues and work items will be automatically tagged with `sandbox-{SANDBOX_NAME}`.
| Default value | `""` |
|--- | ---

### `veracode-api-id`

**Required** (when using `profile-name` or `sandbox-name`) Your Veracode API ID for authenticating API requests. This should be stored as a GitHub secret for security.

**Note:** This parameter is required when using API-based fetching. It is not needed when using `scan-results-json` with a file.
| Default value | `""` |
|--- | ---

### `veracode-api-key`

**Required** (when using `profile-name` or `sandbox-name`) Your Veracode API Key (secret) for authenticating API requests. This should be stored as a GitHub secret for security.

**Note:** This parameter is required when using API-based fetching. It is not needed when using `scan-results-json` with a file.
| Default value | `""` |
|--- | ---

### `include-sca`

**Optional** Include SCA (Software Composition Analysis) findings in addition to static scan findings. When set to `true`, the action will fetch and process SCA findings that identify vulnerable third-party components and dependencies.

**Important:** 
- SCA findings can only be imported when using API-based fetching (with `profile-name` and API credentials)
- File-based SCA import is not currently supported
- Only SCA findings where `finding_status.status === "OPEN"` AND `violates_policy === true` will be processed

**Valid values:** `"true"` or `"false"` (as strings) or `true` or `false` (as booleans)
| Default value | `"false"` |
|--- | ---

### GitHub-specific inputs (when `dts_type` is `GITHUB` or not specified)

### `github-token`

**Required for GitHub** GitHub token to access the repo.
| Default value | `${{ github.token }}` |
--- | ---

### `repo_owner`

**Optional** Repository owner. If not specified, uses the context from the GitHub workflow.
| Default value | `""` |
--- | ---

### `repo_name`

**Optional** Repository name. If not specified, uses the context from the GitHub workflow.
| Default value | `""` |
--- | ---

### `commitHash`

**Optional** Commit hash to use for file links. If not specified, uses `GITHUB_SHA`.
| Default value | `""` |
--- | ---

### `debug`

**Optional** Enable debug logging.
| Default value | `""` |
--- | ---

### Azure DevOps-specific inputs (when `dts_type` is `ADO`)

### `ADO_PAT`

**Required for ADO** Azure DevOps Personal Access Token with appropriate permissions to create work items.
| Default value | `""` |
--- | ---

### `ADO_ORG`

**Required for ADO** Azure DevOps Organization name.
| Default value | `""` |
--- | ---

### `ADO_PROJECT`

**Required for ADO** Azure DevOps Project name.
| Default value | `""` |
--- | ---

### `ADO_WORK_ITEM_TYPE`

**Optional for ADO** Azure DevOps Work Item Type to create. Currently supported and tested by this action: `Issue` and `Bug`.
| Default value | `"Issue"` |
--- | ---

When `ADO_WORK_ITEM_TYPE` is set to `Bug`, the action uses ADO Bug-specific fields and state names:
- The finding description is written to the Bug `Repro Steps` field (instead of `Description`)
- Mitigation details are appended to the Bug `Discussion` (System.History)
- Bug state names differ from Issue and can be configured via the state inputs below

### `ADO_OPEN_STATE`

**Optional for ADO** State to use when creating or reopening a work item.
- For `Issue` work items the default is `"To Do"`
- For `Bug` work items we recommend `"New"`

| Default value | `"To Do"` |
--- | ---

### `ADO_CLOSE_STATE`

**Optional for ADO** State to use when closing a work item.
- For `Issue` work items the default is `"Done"`
- For `Bug` work items we recommend `"Closed"`

| Default value | `"Done"` |
--- | ---

### `ADO_REOPEN_STATE`

**Optional for ADO** State to use when reopening a work item.
- For `Issue` work items the default is `"To Do"`
- For `Bug` work items we recommend `"New"`

| Default value | `"To Do"` |
--- | ---

> Note: When `ADO_WORK_ITEM_TYPE` is set to `Bug`, the three state inputs `ADO_OPEN_STATE`, `ADO_CLOSE_STATE`, and `ADO_REOPEN_STATE` are effectively required to match your ADO process configuration. If they are not provided, the action will attempt sensible defaults but your process may require specific state names.

---

## Permissions

### GitHub Permissions

If you get an error like:

```
Failure at Error: Error 404 creating VeracodeFlaw label "VeracodeFlaw: Very High": Not Found
```
Or:
```
Failure at Error: Error 403 creating VeracodeFlaw label "VeracodeFlaw: Very High": Resource not accessible by integration
```

It is likely that something is wrong with the permissions for the token provided to the action (GitHub API responds with 403 or 404 if there are permission issues).

#### GITHUB_TOKEN

This action requires `issues: write` of all (new) Personal Access Tokens, including the automatically generated `GITHUB_TOKEN`.

If you do not add anything to the YAML, by default the `GITHUB_TOKEN` will be used and it will not be given "write" rights to "issues".

You can [change the default permissions](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-your-repository#setting-the-permissions-of-the-github_token-for-your-repository), but this would apply to all workflows in your repository and we generally don't recommend this

To follow the Principle of Least Privilege we recommend only granting the permission to the job in the job configuration by including [job.<job_id>.permissions](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idpermissions):

```
    permissions:
      issues: write
```


#### Your own token

You can specify your own token with the `github-token` argument:
```
        with:
          github-token: ${{ secrets.MY_TOKEN }}
```

If this is a Classic token this token must have the `repo` scope.
[You can check this with curl](https://stackoverflow.com/a/70588035).

If this is a new 'fine-grained, repository-scoped token' you will need to ensure that for the given repository it says "Read and Write access to issues".
[You can check that here](https://github.com/settings/tokens?type=beta)

### Azure DevOps Permissions

For Azure DevOps integration, the Personal Access Token (PAT) must have the following permissions:
- **Work Items**: Read & Write
- **Code**: Read (for repository access)

The PAT should be scoped to the specific project where work items will be created.

## Example usage

### GitHub Issues (Default)

#### Pipeline Scan

```yaml
  . . . 
# This first step is assumed to exist already in your Workflow
  pipeline_scan:
      needs: build
      runs-on: ubuntu-latest
      name: pipeline scan
      steps:
        - name: checkout repo
          uses: actions/checkout@v3

        - name: get archive
          uses: actions/download-artifact@v3
          with:
            name: verademo.war
        - name: pipeline-scan action step
          id: pipeline-scan
          uses: veracode/Veracode-pipeline-scan-action@pipeline-scan-beta-v0.0.4
          with:
            vid: ${{ secrets.VID }}
            vkey: ${{ secrets.VKEY }}
            file: "verademo.war" 
            fail_build: false

# This step will import the flaws from the step above
  import-issues:
    needs: scan
    runs-on: ubuntu-latest
    permissions:
      issues: write
    steps:
      - name: get scan results
        uses: actions/download-artifact@v3
        with:
          name: filtered-results

      - name: import flaws as issues
        uses: veracode/veracode-flaws-to-issues@v2.1.19
        with:
          dts_type: 'GITHUB'  # Optional, this is the default
          scan-results-json: 'filtered_results.json'
          autoCloseFindings: 'true'  # Optional, closes issues no longer present in scan
```

#### Policy/Sandbox scan (using API-based fetching - Recommended)

```yaml
  . . .
# This step will fetch findings directly from Veracode API and import them as issues
  import-policy-flaws:
    runs-on: ubuntu-latest
    permissions:
      issues: write
    steps:
      - name: import flaws as issues
        uses: veracode/veracode-flaws-to-issues@v2.1.19
        with:
          dts_type: 'GITHUB'  # Optional, this is the default
          profile-name: 'NodeGoat'  # Your Veracode application profile name
          veracode-api-id: ${{ secrets.VERACODE_API_ID }}
          veracode-api-key: ${{ secrets.VERACODE_API_KEY }}
          autoCloseFindings: 'true'  # Optional, closes issues no longer present in scan
```

#### Policy/Sandbox scan with SCA findings (using API-based fetching)

```yaml
  . . .
# This step will fetch both static and SCA findings directly from Veracode API and import them as issues
  import-policy-and-sca-flaws:
    runs-on: ubuntu-latest
    permissions:
      issues: write
    steps:
      - name: import flaws as issues
        uses: veracode/veracode-flaws-to-issues@v2.1.19
        with:
          dts_type: 'GITHUB'  # Optional, this is the default
          profile-name: 'NodeGoat'  # Your Veracode application profile name
          veracode-api-id: ${{ secrets.VERACODE_API_ID }}
          veracode-api-key: ${{ secrets.VERACODE_API_KEY }}
          include-sca: 'true'  # Include SCA findings
          autoCloseFindings: 'true'  # Optional, closes issues no longer present in scan
```

#### Policy/Sandbox scan with Sandbox (using API-based fetching)

```yaml
  . . .
# This step will fetch sandbox findings directly from Veracode API and import them as issues
  import-sandbox-flaws:
    runs-on: ubuntu-latest
    permissions:
      issues: write
    steps:
      - name: import sandbox flaws as issues
        uses: veracode/veracode-flaws-to-issues@v2.1.19
        with:
          dts_type: 'GITHUB'  # Optional, this is the default
          profile-name: 'NodeGoat'  # Your Veracode application profile name
          sandbox-name: 'Feature123'  # Your Veracode sandbox name
          veracode-api-id: ${{ secrets.VERACODE_API_ID }}
          veracode-api-key: ${{ secrets.VERACODE_API_KEY }}
          autoCloseFindings: 'true'  # Optional, closes issues no longer present in scan
```

#### Policy/Sandbox scan with Sandbox and SCA findings (using API-based fetching)

```yaml
  . . .
# This step will fetch both static and SCA findings from a sandbox and import them as issues
  import-sandbox-and-sca-flaws:
    runs-on: ubuntu-latest
    permissions:
      issues: write
    steps:
      - name: import sandbox and SCA flaws as issues
        uses: veracode/veracode-flaws-to-issues@v2.1.19
        with:
          dts_type: 'GITHUB'  # Optional, this is the default
          profile-name: 'NodeGoat'  # Your Veracode application profile name
          sandbox-name: 'Feature123'  # Your Veracode sandbox name
          veracode-api-id: ${{ secrets.VERACODE_API_ID }}
          veracode-api-key: ${{ secrets.VERACODE_API_KEY }}
          include-sca: 'true'  # Include SCA findings
          autoCloseFindings: 'true'  # Optional, closes issues no longer present in scan
```

#### Policy/Sandbox scan (using file-based approach - Legacy)

```yaml
  . . .
# this first step will get existing flaws for an Application Profile (in this case, NodeGoat).  
# 	(obviously) Change the name=<app_name> in the first http call to be 
#	the name of your Application on the Veracode platform
  get-policy-flaws:
    runs-on: ubuntu-latest
    container: 
      image: veracode/api-signing:latest
    steps:
      # Note: this will only work up to about 500 flaws
      #		due to Veracode results limiting
      # See the get_flaws.sh script in the helpers directory
      #		for a more elaborate method
      # Note: include_annot=TRUE is required for annotation-based workflow
      - name: get policy flaws
        run: |
          cd /tmp
          export VERACODE_API_KEY_ID=${{ secrets.VERACODE_API_ID }}
          export VERACODE_API_KEY_SECRET=${{ secrets.VERACODE_API_KEY }}
          guid=$(http --auth-type veracode_hmac GET "https://api.veracode.com/appsec/v1/applications?name=NodeGoat" | jq -r '._embedded.applications[0].guid') 
          echo GUID: ${guid}
          total_flaws=$(http --auth-type veracode_hmac GET "https://api.veracode.com/appsec/v2/applications/${guid}/findings?scan_type=STATIC&violates_policy=True&include_annot=TRUE" | jq -r '.page.total_elements')
          echo TOTAL_FLAWS: ${total_flaws}
          http --auth-type veracode_hmac GET "https://api.veracode.com/appsec/v2/applications/${guid}/findings?scan_type=STATIC&violates_policy=True&include_annot=TRUE&size=${total_flaws}" > policy_flaws.json

      - name: save results file
        uses: actions/upload-artifact@v3
        with:
          name: policy-flaws
          path: /tmp/policy_flaws.json

# This step will import flaws from the step above
  import-policy-flaws:
    needs: get-policy-flaws
    runs-on: ubuntu-latest
    permissions:
      issues: write
    steps:
      - name: get flaw file
        uses: actions/download-artifact@v3
        with:
          name: policy-flaws
          path: /tmp

      - name: import flaws as issues
        uses: veracode/veracode-flaws-to-issues@v2.1.19
        with:
          dts_type: 'GITHUB'  # Optional, this is the default
          scan-results-json: '/tmp/policy_flaws.json'
          autoCloseFindings: 'true'  # Optional, closes issues no longer present in scan
```

### Azure DevOps Work Items

#### Pipeline Scan with ADO

```yaml
  . . . 
# This first step is assumed to exist already in your Workflow
  pipeline_scan:
      needs: build
      runs-on: ubuntu-latest
      name: pipeline scan
      steps:
        - name: checkout repo
          uses: actions/checkout@v3

        - name: get archive
          uses: actions/download-artifact@v3
          with:
            name: verademo.war
        - name: pipeline-scan action step
          id: pipeline-scan
          uses: veracode/Veracode-pipeline-scan-action@pipeline-scan-beta-v0.0.4
          with:
            vid: ${{ secrets.VID }}
            vkey: ${{ secrets.VKEY }}
            file: "verademo.war" 
            fail_build: false

# This step will import the flaws from the step above as ADO work items
  import-ado-workitems:
    needs: scan
    runs-on: ubuntu-latest
    steps:
      - name: get scan results
        uses: actions/download-artifact@v3
        with:
          name: filtered-results

      - name: import flaws as ADO work items
        uses: veracode/veracode-flaws-to-issues@v2.1.19
        with:
          dts_type: 'ADO'
          scan-results-json: 'filtered_results.json'
          ADO_PAT: ${{ secrets.ADO_PAT }}
          ADO_ORG: 'your-organization'
          ADO_PROJECT: 'your-project'
          ADO_WORK_ITEM_TYPE: 'Bug'  # Optional, defaults to 'Issue'
          autoCloseFindings: 'true'  # Optional, closes work items no longer present in scan
```

#### Policy/Sandbox scan with ADO (using API-based fetching - Recommended)

```yaml
  . . .
# This step will fetch findings directly from Veracode API and import them as ADO work items
  import-policy-flaws-ado:
    runs-on: ubuntu-latest
    steps:
      - name: import flaws as ADO work items
        uses: veracode/veracode-flaws-to-issues@v2.1.19
        with:
          dts_type: 'ADO'
          profile-name: 'NodeGoat'  # Your Veracode application profile name
          veracode-api-id: ${{ secrets.VERACODE_API_ID }}
          veracode-api-key: ${{ secrets.VERACODE_API_KEY }}
          ADO_PAT: ${{ secrets.ADO_PAT }}
          ADO_ORG: 'your-organization'
          ADO_PROJECT: 'your-project'
          ADO_WORK_ITEM_TYPE: 'Bug'
          autoCloseFindings: 'true'  # Optional, closes work items no longer present in scan
```

#### Policy/Sandbox scan with ADO and SCA findings (using API-based fetching)

```yaml
  . . .
# This step will fetch both static and SCA findings directly from Veracode API and import them as ADO work items
  import-policy-and-sca-flaws-ado:
    runs-on: ubuntu-latest
    steps:
      - name: import flaws as ADO work items
        uses: veracode/veracode-flaws-to-issues@v2.1.19
        with:
          dts_type: 'ADO'
          profile-name: 'NodeGoat'  # Your Veracode application profile name
          veracode-api-id: ${{ secrets.VERACODE_API_ID }}
          veracode-api-key: ${{ secrets.VERACODE_API_KEY }}
          include-sca: 'true'  # Include SCA findings
          ADO_PAT: ${{ secrets.ADO_PAT }}
          ADO_ORG: 'your-organization'
          ADO_PROJECT: 'your-project'
          ADO_WORK_ITEM_TYPE: 'Bug'
          autoCloseFindings: 'true'  # Optional, closes work items no longer present in scan
```

#### Policy/Sandbox scan with ADO and Sandbox (using API-based fetching)

```yaml
  . . .
# This step will fetch sandbox findings directly from Veracode API and import them as ADO work items
  import-sandbox-flaws-ado:
    runs-on: ubuntu-latest
    steps:
      - name: import sandbox flaws as ADO work items
        uses: veracode/veracode-flaws-to-issues@v2.1.19
        with:
          dts_type: 'ADO'
          profile-name: 'NodeGoat'  # Your Veracode application profile name
          sandbox-name: 'Feature123'  # Your Veracode sandbox name
          veracode-api-id: ${{ secrets.VERACODE_API_ID }}
          veracode-api-key: ${{ secrets.VERACODE_API_KEY }}
          ADO_PAT: ${{ secrets.ADO_PAT }}
          ADO_ORG: 'your-organization'
          ADO_PROJECT: 'your-project'
          ADO_WORK_ITEM_TYPE: 'Bug'
          autoCloseFindings: 'true'  # Optional, closes work items no longer present in scan
```

#### Policy/Sandbox scan with ADO, Sandbox, and SCA findings (using API-based fetching)

```yaml
  . . .
# This step will fetch both static and SCA findings from a sandbox and import them as ADO work items
  import-sandbox-and-sca-flaws-ado:
    runs-on: ubuntu-latest
    steps:
      - name: import sandbox and SCA flaws as ADO work items
        uses: veracode/veracode-flaws-to-issues@v2.1.19
        with:
          dts_type: 'ADO'
          profile-name: 'NodeGoat'  # Your Veracode application profile name
          sandbox-name: 'Feature123'  # Your Veracode sandbox name
          veracode-api-id: ${{ secrets.VERACODE_API_ID }}
          veracode-api-key: ${{ secrets.VERACODE_API_KEY }}
          include-sca: 'true'  # Include SCA findings
          ADO_PAT: ${{ secrets.ADO_PAT }}
          ADO_ORG: 'your-organization'
          ADO_PROJECT: 'your-project'
          ADO_WORK_ITEM_TYPE: 'Bug'
          autoCloseFindings: 'true'  # Optional, closes work items no longer present in scan
```

#### Policy/Sandbox scan with ADO (using file-based approach - Legacy)

```yaml
  . . .
# this first step will get existing flaws for an Application Profile
  get-policy-flaws:
    runs-on: ubuntu-latest
    container: 
      image: veracode/api-signing:latest
    steps:
      - name: get policy flaws
        run: |
          cd /tmp
          export VERACODE_API_KEY_ID=${{ secrets.VERACODE_API_ID }}
          export VERACODE_API_KEY_SECRET=${{ secrets.VERACODE_API_KEY }}
          guid=$(http --auth-type veracode_hmac GET "https://api.veracode.com/appsec/v1/applications?name=NodeGoat" | jq -r '._embedded.applications[0].guid') 
          echo GUID: ${guid}
          total_flaws=$(http --auth-type veracode_hmac GET "https://api.veracode.com/appsec/v2/applications/${guid}/findings?scan_type=STATIC&violates_policy=True&include_annot=TRUE" | jq -r '.page.total_elements')
          echo TOTAL_FLAWS: ${total_flaws}
          http --auth-type veracode_hmac GET "https://api.veracode.com/appsec/v2/applications/${guid}/findings?scan_type=STATIC&violates_policy=True&include_annot=TRUE&size=${total_flaws}" > policy_flaws.json

      - name: save results file
        uses: actions/upload-artifact@v3
        with:
          name: policy-flaws
          path: /tmp/policy_flaws.json

# This step will import flaws from the step above as ADO work items
  import-policy-flaws-ado:
    needs: get-policy-flaws
    runs-on: ubuntu-latest
    steps:
      - name: get flaw file
        uses: actions/download-artifact@v3
        with:
          name: policy-flaws
          path: /tmp

      - name: import flaws as ADO work items
        uses: veracode/veracode-flaws-to-issues@v2.1.19
        with:
          dts_type: 'ADO'
          scan-results-json: '/tmp/policy_flaws.json'
          ADO_PAT: ${{ secrets.ADO_PAT }}
          ADO_ORG: 'your-organization'
          ADO_PROJECT: 'your-project'
          ADO_WORK_ITEM_TYPE: 'Bug'
          autoCloseFindings: 'true'  # Optional, closes work items no longer present in scan