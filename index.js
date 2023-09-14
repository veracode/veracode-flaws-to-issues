//
// entry point when called from a Workflow Action
//

const core = require('@actions/core');
const github = require('@actions/github');

const importFlaws = require('./importer').importFlaws;

try {
    // get input params
    const resultsFile = core.getInput('scan-results-json', {required: true} );
    const token = core.getInput('github-token', {required: true} );
    const waitTime = core.getInput('wait-time');                // default set in Action.yml
    const source_base_path_1 = core.getInput('source_base_path_1'); 
    const source_base_path_2 = core.getInput('source_base_path_2'); 
    const source_base_path_3 = core.getInput('source_base_path_3');
    const fail_build = core.getInput('fail_build');
    const debug = core.getInput('debug')
    const commit_hash = process.env.GITHUB_SHA;
    console.log('resultsFile: '+resultsFile+'\nwaitTime: '+waitTime+'\nsource_base_path_1: '+source_base_path_1+'\nsource_base_path_2: '+source_base_path_2+'\nsource_base_path_3: '+source_base_path_3+'\ncommit_hash: '+commit_hash+'\ndebug: '+debug)

    // other params
    const owner = github.context.repo.owner;
    const repo = github.context.repo.repo;

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
} catch (error) {
    core.setFailed(error.stack);
}
