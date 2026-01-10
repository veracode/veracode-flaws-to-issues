//
// entry point when called from a Workflow Action
//

const core = require('@actions/core');
const github = require('@actions/github');
const fs = require('fs');
const path = require('path');

const importFlaws = require('./importer').importFlaws;
const importFlawsToADO = require('./ado-importer').importFlawsToADO;
const { findApplicationProfile, findSandbox, getAllFindings } = require('./veracode-api');

async function fetchFindingsFromAPI(debug = false) {
    const profileName = core.getInput('profile-name');
    const sandboxName = core.getInput('sandbox-name');
    const apiKeyId = core.getInput('veracode-api-id');
    const apiKeySecret = core.getInput('veracode-api-key');
    
    // Validate inputs
    if (!profileName && !sandboxName) {
        return null; // No API fetching needed
    }
    
    if (!apiKeyId || !apiKeySecret) {
        throw new Error('veracode-api-id and veracode-api-key are required when profile-name or sandbox-name is provided');
    }
    
    // Validate: cannot use both, and sandbox requires profile
    if (profileName && sandboxName) {
        // Actually, when sandbox is specified, we need the profile to find which application it belongs to
        // So both can be provided together - profile-name identifies the app, sandbox-name identifies the sandbox
        // This is allowed and is the intended usage for sandbox scans
    } else if (sandboxName && !profileName) {
        throw new Error('profile-name is required when sandbox-name is specified. The profile name identifies which application the sandbox belongs to.');
    } else if (!profileName && !sandboxName) {
        throw new Error('Either profile-name (for policy scans) or both profile-name and sandbox-name (for sandbox scans) must be provided');
    }
    
    console.log('=== Fetching Veracode Findings via API ===');
    console.log(`Input profile name: ${profileName || 'N/A'}`);
    console.log(`Input sandbox name: ${sandboxName || 'N/A'}`);
    
    // Step 1: Find application profile (required for both policy and sandbox scans)
    console.log(`\nFinding application profile: ${profileName}`);
    const profileInfo = await findApplicationProfile(apiKeyId, apiKeySecret, profileName, debug);
    console.log(`✓ Found profile: ${profileInfo.name} (GUID: ${profileInfo.guid})`);
    
    // Step 2: Find sandbox if specified
    let sandboxInfo = null;
    if (sandboxName) {
        console.log(`\nFinding sandbox: ${sandboxName}`);
        sandboxInfo = await findSandbox(apiKeyId, apiKeySecret, profileInfo.guid, sandboxName, debug);
        console.log(`✓ Found sandbox: ${sandboxInfo.name} (GUID: ${sandboxInfo.guid})`);
    }
    
    // Step 3: Fetch findings
    console.log(`\nFetching findings...`);
    const findings = await getAllFindings(apiKeyId, apiKeySecret, profileInfo.guid, sandboxInfo?.guid, debug);
    const findingsCount = findings._embedded?.findings?.length || 0;
    console.log(`✓ Fetched ${findingsCount} findings`);
    
    // Display summary
    console.log('\n=== Summary ===');
    console.log(`Input profile name: ${profileName}`);
    if (sandboxName) {
        console.log(`Input sandbox name: ${sandboxName}`);
    }
    console.log(`Found profile name: ${profileInfo.name}`);
    console.log(`Found profile GUID: ${profileInfo.guid}`);
    if (sandboxInfo) {
        console.log(`Found sandbox name: ${sandboxInfo.name}`);
        console.log(`Found sandbox GUID: ${sandboxInfo.guid}`);
    }
    console.log(`Number of findings: ${findingsCount}`);
    console.log('================\n');
    
    // Write findings to a temporary file
    const tempFile = path.join(process.env.RUNNER_TEMP || '/tmp', `veracode-findings-${Date.now()}.json`);
    fs.writeFileSync(tempFile, JSON.stringify(findings, null, 2));
    console.log(`Findings written to: ${tempFile}`);
    
    // Return both file path and sandbox name (if applicable)
    return {
        file: tempFile,
        sandboxName: sandboxInfo?.name || null
    };
}

(async () => {
try {
    // get input params
    const dts_type = core.getInput('dts_type') || 'GITHUB';
    
    // Check if we need to fetch from API or use file
    let resultsFile;
    const profileName = core.getInput('profile-name');
    const sandboxName = core.getInput('sandbox-name');
    
    // Prioritize API-based fetching if profile-name or sandbox-name is provided
    // (even if scan-results-json has a default value)
    const useApi = profileName && profileName.trim() !== '' || sandboxName && sandboxName.trim() !== '';
    
    let sandboxNameForTag = null;
    if (useApi) {
        // Fetch from API - this takes precedence over file input
        console.log('Using API-based fetching (profile-name/sandbox-name provided)');
        const debug = core.getInput('debug');
        const apiResult = await fetchFindingsFromAPI(debug);
        if (!apiResult || !apiResult.file) {
            throw new Error('Failed to fetch findings from API');
        }
        resultsFile = apiResult.file;
        sandboxNameForTag = apiResult.sandboxName; // Will be null if not a sandbox scan
    } else {
        // Use file input (may use default value from action.yml)
        console.log('Using file-based input (scan-results-json)');
        resultsFile = core.getInput('scan-results-json');
        if (!resultsFile || resultsFile.trim() === '') {
            throw new Error('Either profile-name/sandbox-name (for API fetching) or scan-results-json (for file input) must be provided');
        }
    }
    const waitTime = core.getInput('wait-time');                // default set in Action.yml
    const source_base_path_1 = core.getInput('source_base_path_1'); 
    const source_base_path_2 = core.getInput('source_base_path_2'); 
    const source_base_path_3 = core.getInput('source_base_path_3');
    const fail_build = core.getInput('fail_build');
    const autoCloseFindings = core.getInput('autoCloseFindings');
    const debug = core.getInput('debug')
    let commit_hash = core.getInput('commitHash');
    if ( commit_hash == "" ){
        commit_hash = process.env.GITHUB_SHA;
    }
    console.log('dts_type: '+dts_type+'\nresultsFile: '+resultsFile+'\nwaitTime: '+waitTime+'\nsource_base_path_1: '+source_base_path_1+'\nsource_base_path_2: '+source_base_path_2+'\nsource_base_path_3: '+source_base_path_3+'\ncommit_hash: '+commit_hash+'\nautoCloseFindings: '+autoCloseFindings+'\ndebug: '+debug)

    if (dts_type === 'ADO') {
        // Validate ADO specific required parameters
        const ado_pat = core.getInput('ADO_PAT', {required: true});
        const ado_org = core.getInput('ADO_ORG', {required: true});
        const ado_project = core.getInput('ADO_PROJECT', {required: true});
        const ado_work_item_type = core.getInput('ADO_WORK_ITEM_TYPE') || 'Issue';
        const ado_open_state = core.getInput('ADO_OPEN_STATE') || 'To Do';
        const ado_close_state = core.getInput('ADO_CLOSE_STATE') || 'Done';
        const ado_reopen_state = core.getInput('ADO_REOPEN_STATE') || 'To Do';

        // Validate work item type
        const validWorkItemTypes = ['Bug', 'Issue'];
        if (!validWorkItemTypes.includes(ado_work_item_type)) {
            throw new Error(`Invalid ADO_WORK_ITEM_TYPE. Must be one of: ${validWorkItemTypes.join(', ')}`);
        }

        // Validate state parameters for Bug type
        if (ado_work_item_type === 'Bug') {
            if (!ado_open_state || !ado_close_state || !ado_reopen_state) {
                throw new Error('For Bug work item type, ADO_OPEN_STATE, ADO_CLOSE_STATE, and ADO_REOPEN_STATE parameters are required');
            }
        }

        // Import flaws to Azure DevOps
        importFlawsToADO({
            resultsFile: resultsFile,
            adoPat: ado_pat,
            adoOrg: ado_org,
            adoProject: ado_project,
            adoWorkItemType: ado_work_item_type,
            adoOpenState: ado_open_state,
            adoCloseState: ado_close_state,
            adoReopenState: ado_reopen_state,
            waitTime: waitTime,
            source_base_path_1: source_base_path_1,
            source_base_path_2: source_base_path_2,
            source_base_path_3: source_base_path_3,
            commit_hash: commit_hash,
            fail_build: fail_build,
            autoCloseFindings: autoCloseFindings,
            debug: debug,
            sandboxName: sandboxNameForTag
        })
        .catch(error => {console.error(`Failure at ${error.stack}`)});
    } else {
        // Original GitHub functionality
        const token = core.getInput('github-token', {required: true} );
        let isPR
        let owner
        let repo

        // other params
        if ( core.getInput('repo_owner') && core.getInput('repo_name') ){
            owner = core.getInput('repo_owner');
            console.log('Owner: '+core.getInput('repo_owner'))
            repo = core.getInput('repo_name');
            console.log('Repo: '+core.getInput('repo_name'))
        }
        else {
            owner = github.context.repo.owner;
            repo = github.context.repo.repo;
        }

        console.log('owner = '+owner);
        console.log('repo = '+repo);

        if ( core.getInput('repo_owner') && core.getInput('repo_name') ){
            isPR = 0
        }
        else {
            core.info('check if we run on a pull request')
            let pullRequest = process.env.GITHUB_REF

            if ( debug == "true" ){
                core.info('#### DEBUG START ####')
                core.info('index.js')
                core.info(pullRequest)
                core.info(JSON.stringify(process.env))
                core.info('#### DEBUG END ####')
            }
            const isPR = pullRequest.indexOf("pull")

            var pr_context
            var pr_commentID
        }

        if ( isPR >= 1 ){
            core.info("This run is part of a PR, should add some PR links")
            pr_context = github.context
            pr_commentID = pr_context.payload.pull_request.number
        }
        else {
            if ( debug == "true" ){
                core.info('#### DEBUG START ####')
                core.info('index.js')
                core.info("isPR?: "+ isPR)
                core.info('#### DEBUG END ####')
            }
            core.info("We don't run on a PR")
        }

        // do the thing
        importFlaws(
            {resultsFile: resultsFile,
             githubOwner: owner,
             githubRepo: repo,
             githubToken: token,
             waitTime: waitTime,
             source_base_path_1: source_base_path_1,
             source_base_path_2: source_base_path_2,
             source_base_path_3: source_base_path_3,
             commit_hash: commit_hash,
             isPR: isPR,
             pr_commentID: pr_commentID,
             fail_build: fail_build,
             autoCloseFindings: autoCloseFindings,
             debug: debug,
             sandboxName: sandboxNameForTag
            }
        )
        .catch(error => {console.error(`Failure at ${error.stack}`)});
    }
} catch (error) {
    core.setFailed(error.stack);
}
})();
