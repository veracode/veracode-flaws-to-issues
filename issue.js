//
// GitHub issue importer
//

const { request } = require('@octokit/request');

// add the flaw to GitHub as an Issue
async function addVeracodeIssue(options, issue) {

    const label = require('./label');
    const ApiError = require('./util').ApiError;

    const githubOwner = options.githubOwner;
    const githubRepo = options.githubRepo;
    const githubToken = options.githubToken;

    console.debug(`Adding Issue for ${issue.title}`);

    var authToken = 'token ' + githubToken;


    await request('POST /repos/{owner}/{repo}/issues', {
        headers: {
            authorization: authToken
        },
        owner: githubOwner,
        repo: githubRepo,
        data: {
            "title": issue.title,
            "labels": [label.severityToLabel(issue.severity), issue.label],
            "body": issue.body
        }
    })
    .then( async result => {
        console.log(`Issue successfully created, result: ${result.status}`);
        var issue_number = result.data.number
        if ( (issue.pr_link != "" ) && !(issue.pr_link === undefined)) {
            console.log('Running on a PR, adding PR to the issue.')
            //console.log('pr_link: '+issue.pr_link+'\nissue_number: '+issue_number)
        
            await request('POST /repos/{owner}/{repo}/issues/{issue_number}/comments', {
                headers: {
                    authorization: authToken
                },
                owner: githubOwner,
                repo: githubRepo,
                issue_number: issue_number,
                data: {
                    "body": issue.pr_link
                }
            })
        }
        return issue_number
    })
    .catch( error => {
        // 403 possible rate-limit error
        if((error.status == 403) && (error.message.indexOf('abuse detection') > 0) ) {

            console.warn(`GitHub rate limiter tripped, ${error.message}`);

            throw new ApiError('Rate Limiter tripped');
        } else {
            throw new Error (`Error ${error.status} creating Issue for \"${issue.title}\": ${error.message}`);
        }           
    });
}

module.exports = { addVeracodeIssue };