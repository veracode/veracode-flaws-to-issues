# Import Veracode Static Analysis Flaws to GitHub Issues - GitHub Action

This action can be used in a workflow after a Veracode Static Analysis (either Pipeline Scan or Policy/Sandbox scan) to take the results of the scan and import them into GitHub as Issues.

## Importing Pipeline Scan flaws
For a Pipeline Scan, this is typically done with the filtered results of the Pipeline Scan, see [Pipeline Scan commands](https://help.veracode.com/r/r_pipeline_scan_commands).  

Note that when Issues are added, a tag is inserted into the Issue title.  The tag is of the form `[VID:<cwe>:<file>:<line>]`.  There is some very simple matching of same file, same CWE, +/- 10 lines that will get resolved as the same issue.

## Importing Policy/Sandbox Scan flaws
For a Policy or Sandbox scan, this is done with the Findings REST API call, see [Findings REST API](https://help.veracode.com/r/c_findings_v2_intro).

Note that when Issues are added, a tag is inserted into the Issue title.  The tag is of the form `[VID:<flaw_number>]`.  This tag is used to prevent duplicate issues from getting created.  
  
## Pull request decoration  
This action now supports pull request decoration. Once an issue is generated and the job runs on a PR, the issue will automatically be linked to the PR. This is done for easy review and an easy approval process.  
  
## Fail the build upon findings  
As this job needs to run after a Veracode pipeline/sandbox/policy scan, the scan job cannot fail the pipeline upon findings as otherwiese the following job, this flaws-to-issues job, won't be started. In order to still fail the pipeline this action now includes and option to fail the pipeline upon findings. Make sure you pass the correct pipelins-scan results or download the correct sandbox/policy scan results (most probably all unmitigated, policy relevant findings) to fail the pipeline.  
  
---

## Inputs

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
  
  
## Example usage

### Pipeline Scan

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
    steps:
      - name: get scan results
        uses: actions/download-artifact@v3
        with:
          name: filtered-results

      - name: import flaws as issues
        uses: veracode/veracode-flaws-to-issues@v2.1.19
        with:
          scan-results-json: 'filtered_results.json'
```

### Policy/Sandbox scan

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
    steps:
      - name: get flaw file
        uses: actions/download-artifact@v3
        with:
          name: policy-flaws
          path: /tmp

      - name: import flaws as issues
        uses: veracode/veracode-flaws-to-issues@v2.1.19
        with:
          scan-results-json: '/tmp/policy_flaws.json'
```
