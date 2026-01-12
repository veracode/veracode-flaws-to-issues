//
// handle SCA (Software Composition Analysis) scan findings for GitHub
//

const { request } = require('@octokit/request');
const label = require('./label');
const addVeracodeIssue = require('./issue').addVeracodeIssue;
const core = require('@actions/core');
const util = require('./util');

// Sparse array, element = true if the finding exists, undefined otherwise
var existingFindings = [];
var existingFindingNumber = [];
var existingIssueState = [];

/**
 * Create a unique Veracode SCA finding ID
 * Format: [VID-SCA:CVE-NAME:COMPONENT-FILENAME]
 */
function createSCAFindingID(finding) {
    const cveName = finding.finding_details?.cve?.name || 'Unknown';
    const componentFilename = finding.finding_details?.component_filename || 'Unknown';
    return `[VID-SCA:${cveName}:${componentFilename}]`;
}

/**
 * Extract Veracode SCA finding ID from issue title
 */
function getSCAFindingID(title) {
    let start = title.indexOf('[VID-SCA');
    if (start == -1) {
        return null;
    }
    let end = title.indexOf(']', start);
    return title.substring(start, end + 1);
}

/**
 * Parse Veracode SCA finding ID
 */
function parseSCAFindingID(vid) {
    // Format: [VID-SCA:CVE-NAME:COMPONENT-FILENAME]
    const parts = vid.replace('[VID-SCA:', '').replace(']', '').split(':');
    return {
        prefix: 'VID-SCA',
        cveName: parts[0] || 'Unknown',
        componentFilename: parts.slice(1).join(':') || 'Unknown'
    };
}

/**
 * Check if a finding exists
 */
function findingExists(vid) {
    return existingFindings[vid] !== undefined;
}

/**
 * Get issue number for a finding ID
 */
function getIssueNumber(vid) {
    return existingFindingNumber[vid];
}

/**
 * Get issue state for a finding ID
 */
function getIssueState(vid) {
    return existingIssueState[vid];
}

/**
 * Get all existing Veracode SCA issues
 */
async function getAllVeracodeSCAIssues(options) {
    const githubOwner = options.githubOwner;
    const githubRepo = options.githubRepo;
    const githubToken = options.githubToken;
    const authToken = 'token ' + githubToken;

    let done = false;
    let page = 1;
    let allIssues = [];

    while (!done) {
        try {
            const result = await request('GET /repos/{owner}/{repo}/issues', {
                headers: { authorization: authToken },
                owner: githubOwner,
                repo: githubRepo,
                state: 'all',
                labels: 'Veracode-SCA',
                per_page: 100,
                page: page
            });

            if (result.data.length === 0) {
                done = true;
            } else {
                allIssues = allIssues.concat(result.data);
                page++;
            }
        } catch (error) {
            console.error(`Error fetching issues: ${error.message}`);
            done = true;
        }
    }

    console.log(`Found ${allIssues.length} existing Veracode SCA issues`);

    // Populate the sparse arrays
    for (const issue of allIssues) {
        const vid = getSCAFindingID(issue.title);
        if (vid) {
            existingFindings[vid] = true;
            existingFindingNumber[vid] = issue.number;
            existingIssueState[vid] = issue.state;
        }
    }
}

/**
 * Format SCA finding body text
 */
function formatSCAFindingBody(finding) {
    const componentFilename = finding.finding_details?.component_filename || 'Unknown';
    const cveName = finding.finding_details?.cve?.name || 'Unknown';
    const description = finding.description || 'No description available';
    const cvss = finding.finding_details?.cve?.cvss || 'N/A';
    const severity = finding.finding_details?.cve?.severity || 'Unknown';
    const cveHref = finding.finding_details?.cve?.href;
    const exploitability = finding.finding_details?.cve?.exploitability;
    const licenses = finding.finding_details?.licenses || [];

    let body = `**${componentFilename} - ${cveName}**\n\n`;
    body += `${description}\n\n`;
    body += `**CVSS Score:** ${cvss} - ${severity}\n\n`;

    // Add EPSS information if available
    if (exploitability?.epss_percentile !== undefined && exploitability?.epss_score !== undefined) {
        body += `**EPSS Percentile:** ${exploitability.epss_percentile}\n`;
        body += `**EPSS Score:** ${exploitability.epss_score}\n\n`;
    }

    // Add CVE link if available
    if (cveHref) {
        body += `**CVE Link:** ${cveHref}\n\n`;
    }

    // Add license information if available
    if (licenses.length > 0) {
        const licenseIds = licenses.map(l => l.license_id).filter(Boolean);
        if (licenseIds.length > 0) {
            body += `**License:** ${licenseIds.join(', ')}\n\n`;
        }
    }

    return body;
}

/**
 * Map CVE severity to GitHub label severity
 */
function mapSeverity(cveSeverity) {
    const severityMap = {
        'Very High': 5,
        'High': 4,
        'Medium': 3,
        'Low': 2,
        'Very Low': 1,
        'Informational': 0
    };
    return severityMap[cveSeverity] || 3;
}

/**
 * Process SCA findings and create/update GitHub issues
 */
async function processSCAFindings(options, scaData, autoCloseFindings) {
    const waitTime = parseInt(options.waitTime);

    // Create Veracode-SCA label if it doesn't exist
    await label.createLabels(options);

    // Get all existing Veracode SCA issues
    await getAllVeracodeSCAIssues(options);

    if (!scaData._embedded || !scaData._embedded.findings) {
        console.log('No SCA findings found in input data');
        return 0;
    }

    const findings = scaData._embedded.findings;
    console.log(`Processing ${findings.length} SCA findings`);

    let processedCount = 0;

    // Process each finding
    for (let index = 0; index < findings.length; index++) {
        const finding = findings[index];
        
        const vid = createSCAFindingID(finding);
        const findingStatus = finding.finding_status?.status || 'UNKNOWN';
        const violatesPolicy = finding.violates_policy === true;

        console.debug(`Processing SCA finding ${vid} (Status: ${findingStatus}, Violates Policy: ${violatesPolicy})`);

        // Check if issue already exists
        if (findingExists(vid)) {
            const issueNumber = getIssueNumber(vid);
            const issueState = getIssueState(vid);
            console.log(`Issue already exists for ${vid} (Issue #${issueNumber}, State: ${issueState}, Finding Status: ${findingStatus})`);
            
            // Synchronize issue state with finding status
            if (findingStatus === 'CLOSED' && issueState === 'open') {
                // Finding is closed on Veracode platform, but issue is open on GitHub - close it
                console.log(`Closing open issue #${issueNumber} for ${vid} - finding is CLOSED on Veracode platform`);
                await request('PATCH /repos/{owner}/{repo}/issues/{issue_number}', {
                    headers: { authorization: 'token ' + options.githubToken },
                    owner: options.githubOwner,
                    repo: options.githubRepo,
                    issue_number: issueNumber,
                    state: 'closed',
                    state_reason: 'completed'
                });
                
                // Add comment explaining the closure
                await request('POST /repos/{owner}/{repo}/issues/{issue_number}/comments', {
                    headers: { authorization: 'token ' + options.githubToken },
                    owner: options.githubOwner,
                    repo: options.githubRepo,
                    issue_number: issueNumber,
                    body: 'Issue closed through Veracode Platform mitigation'
                });
                
                // Rate limiting
                if (waitTime > 0) {
                    await util.sleep(waitTime * 1000);
                }
            } else if (findingStatus === 'OPEN' && violatesPolicy && issueState === 'closed') {
                // Finding is open on Veracode platform, but issue is closed on GitHub - reopen it
                console.log(`Reopening closed issue #${issueNumber} for ${vid} - finding is OPEN on Veracode platform`);
                await request('PATCH /repos/{owner}/{repo}/issues/{issue_number}', {
                    headers: { authorization: 'token ' + options.githubToken },
                    owner: options.githubOwner,
                    repo: options.githubRepo,
                    issue_number: issueNumber,
                    state: 'open'
                });
                
                // Add comment explaining the reopening
                const commitHash = options.commit_hash || process.env.GITHUB_SHA || 'N/A';
                await request('POST /repos/{owner}/{repo}/issues/{issue_number}/comments', {
                    headers: { authorization: 'token ' + options.githubToken },
                    owner: options.githubOwner,
                    repo: options.githubRepo,
                    issue_number: issueNumber,
                    body: `The finding is still open on the Veracode platform for scan ${commitHash}`
                });
                
                // Rate limiting
                if (waitTime > 0) {
                    await util.sleep(waitTime * 1000);
                }

                // Add sandbox label if needed
                if (options.sandboxName) {
                    const currentIssue = await request('GET /repos/{owner}/{repo}/issues/{issue_number}', {
                        headers: { authorization: 'token ' + options.githubToken },
                        owner: options.githubOwner,
                        repo: options.githubRepo,
                        issue_number: issueNumber
                    });
                    
                    const currentLabels = currentIssue.data.labels.map(l => l.name);
                    const sandboxLabel = `sandbox-${options.sandboxName}`;
                    
                    if (!currentLabels.includes(sandboxLabel)) {
                        currentLabels.push(sandboxLabel);
                        await request('PATCH /repos/{owner}/{repo}/issues/{issue_number}', {
                            headers: { authorization: 'token ' + options.githubToken },
                            owner: options.githubOwner,
                            repo: options.githubRepo,
                            issue_number: issueNumber,
                            labels: currentLabels
                        });
                    }
                }
            } else if (findingStatus === 'OPEN' && violatesPolicy && issueState === 'open') {
                // Finding is open and issue is open - ensure sandbox label is present if needed
                if (options.sandboxName) {
                    const currentIssue = await request('GET /repos/{owner}/{repo}/issues/{issue_number}', {
                        headers: { authorization: 'token ' + options.githubToken },
                        owner: options.githubOwner,
                        repo: options.githubRepo,
                        issue_number: issueNumber
                    });
                    
                    const currentLabels = currentIssue.data.labels.map(l => l.name);
                    const sandboxLabel = `sandbox-${options.sandboxName}`;
                    
                    if (!currentLabels.includes(sandboxLabel)) {
                        currentLabels.push(sandboxLabel);
                        await request('PATCH /repos/{owner}/{repo}/issues/{issue_number}', {
                            headers: { authorization: 'token ' + options.githubToken },
                            owner: options.githubOwner,
                            repo: options.githubRepo,
                            issue_number: issueNumber,
                            labels: currentLabels
                        });
                    }
                }
            }
            continue;
        }

        // Only create new issues for findings that are OPEN and violate policy
        if (findingStatus !== 'OPEN' || !violatesPolicy) {
            if (findingStatus !== 'OPEN') {
                console.log(`Skipping finding - status is ${findingStatus}, not OPEN`);
            } else {
                console.log(`Skipping finding - violates_policy is ${violatesPolicy}, not true`);
            }
            continue;
        }

        // Create new issue
        const componentFilename = finding.finding_details?.component_filename || 'Unknown';
        const cveName = finding.finding_details?.cve?.name || 'Unknown';
        const title = `Veracode SCA - ${cveName} - ${componentFilename} ${vid}`;
        const body = formatSCAFindingBody(finding);
        const cveSeverity = finding.finding_details?.cve?.severity || 'Medium';
        const severity = mapSeverity(cveSeverity);

        const issue = {
            title: title,
            label: 'Veracode-SCA',
            severity: severity,
            body: body,
            pr_link: ''
        };

        console.log(`Creating new issue for ${vid}`);
        const issueResult = await addVeracodeIssue(options, issue)
            .catch(error => {
                if (error instanceof util.ApiError) {
                    throw error;
                } else {
                    throw error;
                }
            });

        // Add CVE label to the issue (in addition to Veracode-SCA and severity labels)
        // Check if cveName already starts with "CVE-" to avoid duplication
        const cveLabel = cveName.startsWith('CVE-') ? cveName : `CVE-${cveName}`;
        try {
            // Get current labels and add CVE label
            const currentIssue = await request('GET /repos/{owner}/{repo}/issues/{issue_number}', {
                headers: { authorization: 'token ' + options.githubToken },
                owner: options.githubOwner,
                repo: options.githubRepo,
                issue_number: issueResult
            });
            
            const currentLabels = currentIssue.data.labels.map(l => l.name);
            if (!currentLabels.includes(cveLabel)) {
                currentLabels.push(cveLabel);
                await request('PATCH /repos/{owner}/{repo}/issues/{issue_number}', {
                    headers: { authorization: 'token ' + options.githubToken },
                    owner: options.githubOwner,
                    repo: options.githubRepo,
                    issue_number: issueResult,
                    labels: currentLabels
                });
            }
        } catch (labelError) {
            console.warn(`Failed to add CVE label ${cveLabel}: ${labelError.message}`);
        }

        processedCount++;

        // Progress counter
        if ((index > 0) && (index % 25 == 0)) {
            console.log(`Processed ${index} SCA findings`);
        }

        // Rate limiting
        if (waitTime > 0) {
            await util.sleep(waitTime * 1000);
        }
    }

    // Close issues that are no longer present in the scan results
    if (autoCloseFindings) {
        console.log(`\nChecking for SCA GitHub issues to close (findings not found in current scan)...`);
        
        // Track all findings that exist in the scan (regardless of status)
        const processedFindingIds = new Set();
        findings.forEach(finding => {
            const vid = createSCAFindingID(finding);
            processedFindingIds.add(vid);
        });

        const authToken = 'token ' + options.githubToken;
        let done = false;
        let page = 1;
        let closedCount = 0;

        while (!done) {
            try {
                const result = await request('GET /repos/{owner}/{repo}/issues', {
                    headers: { authorization: authToken },
                    owner: options.githubOwner,
                    repo: options.githubRepo,
                    state: 'open',
                    labels: 'Veracode-SCA',
                    per_page: 100,
                    page: page
                });

                if (result.data.length === 0) {
                    done = true;
                } else {
                    for (const issue of result.data) {
                        const vid = getSCAFindingID(issue.title);
                        if (vid && !processedFindingIds.has(vid)) {
                            console.log(`Closing GitHub issue ${issue.number} - finding no longer found in scan: "${issue.title}"`);
                            
                            await request('PATCH /repos/{owner}/{repo}/issues/{issue_number}', {
                                headers: { authorization: authToken },
                                owner: options.githubOwner,
                                repo: options.githubRepo,
                                issue_number: issue.number,
                                state: 'closed',
                                state_reason: 'completed'
                            });
                            
                            await request('POST /repos/{owner}/{repo}/issues/{issue_number}/comments', {
                                headers: { authorization: authToken },
                                owner: options.githubOwner,
                                repo: options.githubRepo,
                                issue_number: issue.number,
                                body: 'This issue has been automatically closed by Veracode automation because the SCA finding is no longer present in the latest scan results.'
                            });
                            
                            closedCount++;
                            
                            if (waitTime > 0) {
                                await util.sleep(waitTime * 1000);
                            }
                        }
                    }
                    page++;
                }
            } catch (error) {
                console.error(`Error checking for issues to close: ${error.message}`);
                done = true;
            }
        }

        if (closedCount > 0) {
            console.log(`Closed ${closedCount} SCA issues that are no longer present in scan results`);
        }
    }

    return processedCount;
}

module.exports = {
    processSCAFindings
};

