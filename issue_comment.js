//
// GitHub issue importer
//

const { request } = require('@octokit/request');

// add the comment to a GitHub Issue
async function addVeracodeIssueComment(options, issueComment) {

    const ApiError = require('./util').ApiError;

    const githubOwner = options.githubOwner;
    const githubRepo = options.githubRepo;
    const githubToken = options.githubToken;

    var authToken = 'token ' + githubToken;

    console.log('Adding PR to the issue now.')
    //console.log('pr_link: '+issueComment.pr_link+' - issue_number: '+issueComment.issue_number)
    const baseUrl = process.env.GITHUB_API_URL || 'https://api.github.com';
    const customRequest = request.defaults({
        baseUrl
    });

    await customRequest('POST /repos/{owner}/{repo}/issues/{issue_number}/comments', {
        headers: {
            authorization: authToken
        },
        owner: githubOwner,
        repo: githubRepo,
        issue_number: issueComment.issue_number,
        data: {
            "body": issueComment.pr_link
        }
    })
    .catch( error => {
        // 403 possible rate-limit error
        if((error.status == 403) && (error.message.indexOf('abuse detection') > 0) ) {

            console.warn(`GitHub rate limiter tripped, ${error.message}`);

            throw new ApiError('Rate Limiter tripped');
        } else {
            throw new Error (`Error ${error.status} creating Issue for \"${issueComment.issue_number}\": ${error.message}`);
        }           
    });
}

module.exports = { addVeracodeIssueComment };