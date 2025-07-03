# Import Veracode Static Analysis Flaws to GitHub Issues or Azure DevOps Work Items - GitHub Action

This action can be used in a workflow after a Veracode Static Analysis (either Pipeline Scan or Policy/Sandbox scan) to take the results of the scan and import them into GitHub as Issues or Azure DevOps as Work Items.

## Supported Defect Tracking Systems

This action supports two defect tracking systems:
- **GitHub Issues** (default) - Creates issues in GitHub repositories
- **Azure DevOps Work Items** - Creates work items in Azure DevOps projects

The system is selected using the `dts_type` parameter, which defaults to `GITHUB` if not specified.

## Important Note on Issue/Work Item Management

This action will **open, reopen, and close** issues/work items based on the current scan results:

- **New findings**: Creates new work items
- **Existing findings**: Reopens closed work items or skips if already open
- **Resolved findings**: Closes work items that are no longer present in the scan results

This ensures that security findings remain tracked and visible until properly addressed, and that resolved issues are automatically closed when they no longer appear in scans.

## Importing Pipeline Scan flaws
For a Pipeline Scan, this is typically done with the filtered results of the Pipeline Scan, see [Pipeline Scan commands](https://help.veracode.com/r/r_pipeline_scan_commands).  

Note that when Issues are added, a tag is inserted into the Issue title.  The tag is of the form `[VID:<cwe>:<file>:<line>]`.  There is some very simple matching of same file, same CWE, +/- 10 lines that will get resolved as the same issue.

## Importing Policy/Sandbox Scan flaws
For a Policy or Sandbox scan, this is done with the Findings REST API call, see [Findings REST API](https://help.veracode.com/r/c_findings_v2_intro).

Note that when Issues are added, a tag is inserted into the Issue title.  The tag is of the form `[VID:<flaw_number>]`.  This tag is used to prevent duplicate issues from getting created.  
  
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

**Required** The path to the scan results file in JSON format.  The scan type, Pipeline or Policy/Sandbox, is auto-detected based on the input file and imported issues are labeled appropriately.
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

**Optional for ADO** Azure DevOps Work Item Type to create. Valid values are: Bug, Issue, Task, Epic, Feature, Test Case, User Story.
| Default value | `"Issue"` |
--- | ---

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
```

#### Policy/Sandbox scan

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
      - name: get policy flaws
        run: |
          cd /tmp
          export VERACODE_API_KEY_ID=${{ secrets.VERACODE_API_ID }}
          export VERACODE_API_KEY_SECRET=${{ secrets.VERACODE_API_KEY }}
          guid=$(http --auth-type veracode_hmac GET "https://api.veracode.com/appsec/v1/applications?name=NodeGoat" | jq -r '._embedded.applications[0].guid') 
          echo GUID: ${guid}
          total_flaws=$(http --auth-type veracode_hmac GET "https://api.veracode.com/appsec/v2/applications/${guid}/findings?scan_type=STATIC&violates_policy=True" | jq -r '.page.total_elements')
          echo TOTAL_FLAWS: ${total_flaws}
          http --auth-type veracode_hmac GET "https://api.veracode.com/appsec/v2/applications/${guid}/findings?scan_type=STATIC&violates_policy=True&size=${total_flaws}" > policy_flaws.json

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
```

#### Policy/Sandbox scan with ADO

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
          total_flaws=$(http --auth-type veracode_hmac GET "https://api.veracode.com/appsec/v2/applications/${guid}/findings?scan_type=STATIC&violates_policy=True" | jq -r '.page.total_elements')
          echo TOTAL_FLAWS: ${total_flaws}
          http --auth-type veracode_hmac GET "https://api.veracode.com/appsec/v2/applications/${guid}/findings?scan_type=STATIC&violates_policy=True&size=${total_flaws}" > policy_flaws.json

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