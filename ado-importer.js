const core = require('@actions/core');
const axios = require('axios');
const fs = require('fs');

async function importFlawsToADO(params) {
    const {
        resultsFile,
        adoPat,
        adoOrg,
        adoProject,
        adoWorkItemType,
        waitTime,
        source_base_path_1,
        source_base_path_2,
        source_base_path_3,
        commit_hash,
        fail_build,
        debug
    } = params;

    // Read and parse the results file
    const flawData = JSON.parse(fs.readFileSync(resultsFile, 'utf8'));
    
    // Initialize ADO API client
    const baseUrl = `https://dev.azure.com`;
    if (debug === 'true') {
        console.log(`Initializing ADO client with base URL: ${baseUrl}`);
        console.log(`Organization: ${adoOrg}`);
        console.log(`Project: ${adoProject}`);
        console.log(`Work Item Type: ${adoWorkItemType}`);
    }

    const adoClient = axios.create({
        baseURL: baseUrl,
        auth: {
            username: 'Basic',
            password: adoPat
        },
        headers: {
            'Content-Type': 'application/json-patch+json'
        }
    });

    // Determine scan type and get flaws
    let scanType = '';
    let flaws = [];
    
    if ('pipeline_scan' in flawData) {
        scanType = 'pipeline';
        console.log('This is a pipeline scan');
        flaws = flawData;
    } else {
        scanType = 'policy';
        console.log('This is a policy scan');
        if ('_embedded' in flawData) {
            console.log('Flaws found to import!');
            flaws = flawData._embedded.findings || [];
        } else {
            console.log('No flaws found to import!');
            return;
        }
    }

    if (flaws.length === 0) {
        console.log('No flaws found to import!');
        return;
    }

    console.log(`Importing ${scanType} flaws into Azure DevOps. ${waitTime} seconds between imports (to handle rate limiting)`);

    // Process each flaw
    for (const flaw of flaws) {
        try {
            // Create work item
            const workItem = await createWorkItem(adoClient, adoOrg, adoProject, adoWorkItemType, flaw, {
                source_base_path_1,
                source_base_path_2,
                source_base_path_3,
                commit_hash,
                debug
            });

            if (debug === 'true') {
                core.info(`Created work item ${workItem.id} for flaw ${flaw.issue_id}`);
            }

            // Wait between API calls to avoid rate limiting
            await new Promise(resolve => setTimeout(resolve, waitTime * 1000));
        } catch (error) {
            if (debug === 'true') {
                console.error('Detailed error information:');
                console.error('Error message:', error.message);
                if (error.response) {
                    console.error('Response status:', error.response.status);
                    console.error('Response data:', error.response.data);
                    console.error('Response headers:', error.response.headers);
                }
                if (error.request) {
                    console.error('Request details:', {
                        method: error.request.method,
                        path: error.request.path,
                        headers: error.request.headers
                    });
                }
            }
            core.error(`Failed to create work item for flaw ${flaw.issue_id}: ${error.message}`);
            if (fail_build === 'true') {
                throw error;
            }
        }
    }
}

async function createWorkItem(adoClient, adoOrg, project, workItemType, flaw, params) {
    const { source_base_path_1, source_base_path_2, source_base_path_3, commit_hash, debug } = params;

    // Format the description with markdown
    const description = formatDescription(flaw, {
        source_base_path_1,
        source_base_path_2,
        source_base_path_3,
        commit_hash
    });

    const url = `/${adoOrg}/${project}/_apis/wit/workitems/${workItemType}?api-version=6.0`;
    const payload = [
        {
            op: 'add',
            path: '/fields/System.Title',
            value: `[Veracode] ${flaw.issue_id}: ${flaw.finding_details?.cwe?.name || 'Security Finding'}`
        },
        {
            op: 'add',
            path: '/fields/System.Description',
            value: description
        },
        {
            op: 'add',
            path: '/fields/System.Tags',
            value: 'Veracode;Security'
        },
        {
            op: 'add',
            path: '/fields/Microsoft.VSTS.Common.Severity',
            value: mapSeverity(flaw.finding_details?.severity)
        }
    ];

    if (debug === 'true') {
        console.log('Creating work item with:');
        console.log('URL:', url);
        console.log('Payload:', JSON.stringify(payload, null, 2));
    }

    // Create the work item
    const response = await adoClient.post(url, payload);

    if (debug === 'true') {
        console.log('Response:', JSON.stringify(response.data, null, 2));
    }

    return response.data;
}

function formatDescription(flaw, params) {
    const { source_base_path_1, source_base_path_2, source_base_path_3, commit_hash } = params;
    
    let description = `# Veracode Security Finding\n\n`;
    description += `## Details\n\n`;
    description += `- **Issue ID**: ${flaw.issue_id}\n`;
    description += `- **Severity**: ${flaw.finding_details?.severity || 'Unknown'}\n`;
    description += `- **CWE ID**: ${flaw.finding_details?.cwe?.id || 'Unknown'}\n`;
    description += `- **Category**: ${flaw.finding_details?.finding_category?.name || 'Unknown'}\n\n`;
    
    description += `## Description\n\n${flaw.description}\n\n`;
    
    if (flaw.finding_details?.procedure) {
        description += `## Procedure\n\n${flaw.finding_details.procedure}\n\n`;
    }

    // Add file information if available
    if (flaw.finding_details?.file_path) {
        let filePath = flaw.finding_details.file_path;
        if (source_base_path_1) filePath = filePath.replace(source_base_path_1, '');
        if (source_base_path_2) filePath = filePath.replace(source_base_path_2, '');
        if (source_base_path_3) filePath = filePath.replace(source_base_path_3, '');
        
        description += `## Location\n\n`;
        description += `- **File**: ${filePath}\n`;
        if (flaw.finding_details.file_line_number) {
            description += `- **Line**: ${flaw.finding_details.file_line_number}\n`;
        }
        if (commit_hash) {
            description += `- **Commit**: ${commit_hash}\n`;
        }
    }

    return description;
}

function mapSeverity(veracodeSeverity) {
    const severityMap = {
        5: '1 - Critical',
        4: '2 - High',
        3: '3 - Medium',
        2: '4 - Low',
        1: '5 - Low'
    };
    return severityMap[veracodeSeverity] || '3 - Medium';
}

module.exports = {
    importFlawsToADO
}; 