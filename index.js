//
// entry point when called from a Workflow Action
//

const core = require('@actions/core');
const github = require('@actions/github');

const importFlaws = require('./importer').importFlaws;
const importFlawsToADO = require('./ado-importer').importFlawsToADO;

try {
    // get input params
    const dts_type = core.getInput('dts_type') || 'GITHUB';
    const resultsFile = core.getInput('scan-results-json', {required: true} );
    const waitTime = core.getInput('wait-time');                // default set in Action.yml
    const source_base_path_1 = core.getInput('source_base_path_1'); 
    const source_base_path_2 = core.getInput('source_base_path_2'); 
    const source_base_path_3 = core.getInput('source_base_path_3');
    const fail_build = core.getInput('fail_build');
    const debug = core.getInput('debug')
    let commit_hash = core.getInput('commitHash');
    if ( commit_hash == "" ){
        commit_hash = process.env.GITHUB_SHA;
    }
    console.log('dts_type: '+dts_type+'\nresultsFile: '+resultsFile+'\nwaitTime: '+waitTime+'\nsource_base_path_1: '+source_base_path_1+'\nsource_base_path_2: '+source_base_path_2+'\nsource_base_path_3: '+source_base_path_3+'\ncommit_hash: '+commit_hash+'\ndebug: '+debug)

    if (dts_type === 'ADO') {
        // Validate ADO specific required parameters
        const ado_pat = core.getInput('ADO_PAT', {required: true});
        const ado_org = core.getInput('ADO_ORG', {required: true});
        const ado_project = core.getInput('ADO_PROJECT', {required: true});
        const ado_work_item_type = core.getInput('ADO_WORK_ITEM_TYPE') || 'Issue';

        // Validate work item type
        const validWorkItemTypes = ['Bug', 'Issue', 'Task', 'Epic', 'Feature', 'Test Case', 'User Story'];
        if (!validWorkItemTypes.includes(ado_work_item_type)) {
            throw new Error(`Invalid ADO_WORK_ITEM_TYPE. Must be one of: ${validWorkItemTypes.join(', ')}`);
        }

        // Import flaws to Azure DevOps
        importFlawsToADO({
            resultsFile: resultsFile,
            adoPat: ado_pat,
            adoOrg: ado_org,
            adoProject: ado_project,
            adoWorkItemType: ado_work_item_type,
            waitTime: waitTime,
            source_base_path_1: source_base_path_1,
            source_base_path_2: source_base_path_2,
            source_base_path_3: source_base_path_3,
            commit_hash: commit_hash,
            fail_build: fail_build,
            debug: debug
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
             debug: debug
            }
        )
        .catch(error => {console.error(`Failure at ${error.stack}`)});
    }
} catch (error) {
    core.setFailed(error.stack);
}
