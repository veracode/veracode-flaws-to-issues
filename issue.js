//
// GitHub issue importer
//

const { request } = require('@octokit/request');
const core = require('@actions/core');

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
            "body": issue.body+`/nDon't know how to fix this? Don't know why this was reported?<br><a href="http://www.veracode.com">Get Assistance from Veracode</a>`
        }
    })
    .then( async result => {
        console.log(`Issue successfully created, result: ${result.status}`);
        var issue_number = result.data.number
        if ( options.debug == "true" ){
            core.info('#### DEBUG START ####')
            core.info('issues.js')
            console.log("isPr?: "+options.isPR)
            core.info('#### DEBUG END ####')
        }
//        const mailToLink = buildMailToLink(
//            `https://github.com/${githubOwner}/${githubRepo}/issues/${issue_number}`,
//            issue.flaw
//        );
//        await request('POST /repos/{owner}/{repo}/issues/{issue_number}/comments', {
//            headers: {
//                authorization: authToken
//            },
//            owner: githubOwner,
//            repo: githubRepo,
//            issue_number: issue_number,
//            data: {
//                "body": `Don't know how to fix this? Don't know why this was reported?<br>
//                <a href="${mailToLink}">Get Assistance from Veracode</a>`
//            }
//        });
        if ( issue.pr_link != "" && options.isPR >=1 ){
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

function buildMailToLink(issueUrl, flaw) {
    return 'mailto:support@veracode.com?subject=' +
        encodeURIComponent('[veracode/veracode-flaws-to-issues] Get Assistance') +
        '&body=' +
        encodeURIComponent(`Hi,

Could you please help me with: ${issueUrl}.
A CWE-${flaw.cwe.id}: ${flaw.cwe.name} flaw reported on line ${flaw.lineNumber} of ${flaw.file} .

I'd like help with:
[ ] Understanding why this flaw was reported
[ ] Fixing this flaw
[ ] Other, namely: [[ please describe here ]]

Thank you.`);
}

module.exports = { addVeracodeIssue };