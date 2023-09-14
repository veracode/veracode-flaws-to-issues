//
// handle policy & sandbox scan flaws
//

const { request } = require('@octokit/request');
const label = require('./label');
const addVeracodeIssue = require('./issue').addVeracodeIssue;
const addVeracodeIssueComment = require('./issue_comment').addVeracodeIssueComment;
const core = require('@actions/core');

// sparse array, element = true if the flaw exists, undefined otherwise
var existingFlaws = [];
var existingFlawNumber = [];
var existingIssueState = [];
var pr_link



function createVeracodeFlawID(flaw) {
    // [VID:FlawID]
    return('[VID:' + flaw.issue_id + ']')
}

// given an Issue title, extract the FlawID string (for existing issues)
function getVeracodeFlawID(title) {
    let start = title.indexOf('[VID');
    if(start == -1) {
        return null;
    }
    let end = title.indexOf(']', start);

    return title.substring(start, end+1);
}

function parseVeracodeFlawID(vid) {
    let parts = vid.split(':');

    return ({
        "prefix": parts[0],
        "flawNum": parts[1].substring(0, parts[1].length - 1)
      })
}

// get existing Veracode-entered issues, to avoid dups
async function getAllVeracodeIssues(options) {
    const githubOwner = options.githubOwner;
    const githubRepo = options.githubRepo;
    const githubToken = options.githubToken;

    var authToken = 'token ' + githubToken;

    // when searching for issues, the label list is AND-ed (all requested labels must exist for the issue),
    // so we need to loop through each severity level manually
    for(const element of label.flawLabels) {

        // get list of all flaws with the VeracodeFlaw label
        console.log(`Getting list of existing \"${element.name}\" issues`);

        let done = false;
        let pageNum = 1;

        let uriSeverity = encodeURIComponent(element.name);
        let uriType = encodeURIComponent(label.otherLabels.find( val => val.id === 'policy').name);
        let reqStr = `GET /repos/{owner}/{repo}/issues?labels=${uriSeverity},${uriType}&state=open&page={page}`
        //let reqStr = `GET /repos/{owner}/{repo}/issues?labels=${uriName},${uriType}&state=open&page={page}&per_page={pageMax}`

        while(!done) {
            await request(reqStr, {
                headers: {
                    authorization: authToken
                },
                owner: githubOwner,
                repo: githubRepo,
                page: pageNum,
                //pageMax: 3
            })
            .then( result => {
                console.log(`${result.data.length} flaw(s) found, (result code: ${result.status})`);

                // walk findings and populate VeracodeFlaws map
                result.data.forEach(element => {
                    let flawID = getVeracodeFlawID(element.title);
                    let issue_number = element.number
                    let issueState = element.state

                    // Map using VeracodeFlawID as index, for easy searching.  Line # for simple flaw matching
                    if(flawID === null){
                        console.log(`Flaw \"${element.title}\" has no Veracode Flaw ID, ignored.`)
                    } else {
                        flawNum = parseVeracodeFlawID(flawID).flawNum;
                        existingFlaws[parseInt(flawNum)] = true;
                        existingFlawNumber[parseInt(flawNum)] = issue_number;
                        existingIssueState[parseInt(flawNum)] = issueState;
                    }
                })

                // check if we need to loop
                // (if there is a link field in the headers, we have more than will fit into 1 query, so 
                //  need to loop.  On the last query we'll still have the link, but the data will be empty)
                if( (result.headers.link !== undefined) && (result.data.length > 0)) {
                        pageNum += 1;
                }
                else 
                    done = true;
            })
            .catch( error => {
                throw new Error (`Error ${error.status} getting VeracodeFlaw issues: ${error.message}`);
            });
        }
    }
}

function issueExists(vid) {
    if(existingFlaws[parseInt(parseVeracodeFlawID(vid).flawNum)] === true)
        return true;
    else
        return false;
}

function getIssueNumber(vid) {
    return existingFlawNumber[parseInt(parseVeracodeFlawID(vid).flawNum)]
}

function getIssueState(vid) {
    return existingIssueState[parseInt(parseVeracodeFlawID(vid).flawNum)]
}



async function processPolicyFlaws(options, flawData) {

    const util = require('./util');

    const waitTime = parseInt(options.waitTime);

    // get a list of all open VeracodeSecurity issues in the repo
    await getAllVeracodeIssues(options)

    // walk through the list of flaws in the input file
    console.log(`Processing input file: \"${options.resultsFile}\" with ${flawData._embedded.findings.length} flaws to process.`)
    var index;
    for( index=0; index < flawData._embedded.findings.length; index++) {
        let flaw = flawData._embedded.findings[index];
        let vid = createVeracodeFlawID(flaw);
        let issue_number = getIssueNumber(vid)
        let issueState = getIssueState(vid)
        console.debug(`processing flaw ${flaw.issue_id}, VeracodeID: ${vid}`);

        // check for mitigation
        if(flaw.finding_status.resolution_status == 'APPROVED') {
            console.log('Flaw mitigated, skipping import');
            continue;
        }

        // check for duplicate
        if(issueExists(vid)) {
            console.log('Issue already exists, skipping import');
            if ( options.debug == "true" ){
                core.info('#### DEBUG START ####')
                core.info('policy.js')
                console.log("isPr?: "+options.isPR)
                core.info('#### DEBUG END ####')
            }
            if ( options.isPR >= 1 && issueState == "open" ){
                console.log('We are on a PR, need to link this issue to this PR')
                pr_link = `Veracode issue link to PR: https://github.com/`+options.githubOwner+`/`+options.githubRepo+`/pull/`+options.pr_commentID

                let issueComment = {
                    'issue_number': issue_number,
                    'pr_link': pr_link
                }; 
    
    
                await addVeracodeIssueComment(options, issueComment)
                .catch( error => {
                    if(error instanceof util.ApiError) {
                        throw error;
                    } else {
                        //console.error(error.message);
                        throw error; 
                    }
                })
            }
            else{
                console.log('GitHub issue is closed no need to update.')
            }


    
            continue;
        }

        //rewrite path
        function replacePath (rewrite, path){
            replaceValues = rewrite.split(":")
            //console.log('Value 1:'+replaceValues[0]+' Value 2: '+replaceValues[1]+' old path: '+path)
            newPath = path.replace(replaceValues[0],replaceValues[1])
            //console.log('new Path:'+newPath)
            return newPath
        }

        filename = flaw.finding_details.file_path

        var filepath = filename

        if (options.source_base_path_1 || options.source_base_path_2 || options.source_base_path_3){
            orgPath1 = options.source_base_path_1.split(":")
            orgPath2 = options.source_base_path_2.split(":")
            orgPath3 = options.source_base_path_3.split(":")
            //console.log('path1: '+orgPath1[0]+' path2: '+orgPath2[0]+' path3: '+orgPath3[0])

            if( filename.includes(orgPath1[0])) {
                //console.log('file path1: '+filename)
                let filepath = replacePath(options.source_base_path_1, filename)
            }
            else if (filename.includes(orgPath2[0])){
                //console.log('file path2: '+filename)
                let filepath = replacePath(options.source_base_path_2, filename)
            }
            else if (filename.includes(orgPath3[0])){
                //console.log('file path3: '+filename)
                let filepath = replacePath(options.source_base_path_3, filename)
            }
            console.log('Filepath:'+filepath);
        }

        linestart = eval(flaw.finding_details.file_line_number-5)
        linened = eval(flaw.finding_details.file_line_number+5)

        let commit_path = "https://github.com/"+options.githubOwner+"/"+options.githubRepo+"/blob/"+options.commit_hash+"/"+filepath+"#L"+linestart+"-L"+linened

        //console.log('Full Path:'+commit_path)

        // add to repo's Issues
        // (in theory, we could do this w/o await-ing, but GitHub has rate throttling, so single-threading this helps)
        let title = `${flaw.finding_details.cwe.name} ('${flaw.finding_details.finding_category.name}') ` + createVeracodeFlawID(flaw);
        let lableBase = label.otherLabels.find( val => val.id === 'policy').name;
        let severity = flaw.finding_details.severity;

        if ( options.debug == "true" ){
            core.info('#### DEBUG START ####')
            core.info("policy.js")
            console.log('isPr?: '+options.isPR)
            core.info('#### DEBUG END ####')
        }


        if ( options.isPR >= 1 ){
            pr_link = `Veracode issue link to PR: https://github.com/`+options.githubOwner+`/`+options.githubRepo+`/pull/`+options.pr_commentID
        }

        let bodyText = `${commit_path}`;
        bodyText += `\n\n**Filename:** ${flaw.finding_details.file_name}`;
        bodyText += `\n\n**Line:** ${flaw.finding_details.file_line_number}`;
        bodyText += `\n\n**CWE:** ${flaw.finding_details.cwe.id} (${flaw.finding_details.cwe.name} ('${flaw.finding_details.finding_category.name}'))`;
        bodyText += '\n\n' + decodeURI(flaw.description);

        //console.log('bodyText: '+bodyText)

        let issue = {
            'title': title,
            'label': lableBase,
            'severity': severity,
            'body': bodyText,
            'pr_link': pr_link
        };

        console.log('Issue: '+JSON.stringify(issue))
        
        await addVeracodeIssue(options, issue)
        .catch( error => {
            if(error instanceof util.ApiError) {

                // TODO: fall back, retry this same issue, continue process

                // for now, only 1 case - rate limit tripped
                //console.warn('Rate limiter tripped.  30 second delay and time between issues increased by 2 seconds.');
                // await sleep(30000);
                // waitTime += 2;

                // // retry this same issue again, bail out if this fails
                // await addVeracodeIssue(options, flaw)
                // .catch( error => {
                //     throw new Error(`Issue retry failed ${error.message}`);
                // })

                throw error;
            } else {
                //console.error(error.message);
                throw error; 
            }
        })

        console.log('My Issue Nmbuer: '+addVeracodeIssue.issue_numnber)

        // progress counter for large flaw counts
        if( (index > 0) && (index % 25 == 0) )
            console.log(`Processed ${index} flaws`)

        // rate limiter, per GitHub: https://docs.github.com/en/rest/guides/best-practices-for-integrators
        if(waitTime > 0)
            await util.sleep(waitTime * 1000);
    }

    return index;
}

module.exports = { processPolicyFlaws }

