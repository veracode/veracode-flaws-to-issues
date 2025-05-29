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
    const results = JSON.parse(fs.readFileSync(resultsFile, 'utf8'));
    
    // Initialize ADO API client
    const adoClient = axios.create({
        baseURL: `https://dev.azure.com/${adoOrg}`,
        auth: {
            username: 'Basic',
            password: adoPat
        },
        headers: {
            'Content-Type': 'application/json-patch+json'
        }
    });

    // Process each flaw
    for (const flaw of results) {
        try {
            // Create work item
            const workItem = await createWorkItem(adoClient, adoProject, adoWorkItemType, flaw, {
                source_base_path_1,
                source_base_path_2,
                source_base_path_3,
                commit_hash
            });

            if (debug === 'true') {
                core.info(`Created work item ${workItem.id} for flaw ${flaw.issue_id}`);
            }

            // Wait between API calls to avoid rate limiting
            await new Promise(resolve => setTimeout(resolve, waitTime * 1000));
        } catch (error) {
            core.error(`Failed to create work item for flaw ${flaw.issue_id}: ${error.message}`);
            if (fail_build === 'true') {
                throw error;
            }
        }
    }
}

async function createWorkItem(adoClient, project, workItemType, flaw, params) {
    const { source_base_path_1, source_base_path_2, source_base_path_3, commit_hash } = params;

    // Format the description with markdown
    const description = formatDescription(flaw, {
        source_base_path_1,
        source_base_path_2,
        source_base_path_3,
        commit_hash
    });

    // Create the work item
    const response = await adoClient.post(
        `/${project}/_apis/wit/workitems/${workItemType}?api-version=6.0`,
        [
            {
                op: 'add',
                path: '/fields/System.Title',
                value: `[Veracode] ${flaw.issue_id}: ${flaw.title}`
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
                value: mapSeverity(flaw.severity)
            }
        ]
    );

    return response.data;
}

function formatDescription(flaw, params) {
    const { source_base_path_1, source_base_path_2, source_base_path_3, commit_hash } = params;
    
    let description = `# Veracode Security Finding\n\n`;
    description += `## Details\n\n`;
    description += `- **Issue ID**: ${flaw.issue_id}\n`;
    description += `- **Severity**: ${flaw.severity}\n`;
    description += `- **CWE ID**: ${flaw.cwe_id}\n`;
    description += `- **Category**: ${flaw.category}\n\n`;
    
    description += `## Description\n\n${flaw.description}\n\n`;
    
    if (flaw.recommendation) {
        description += `## Recommendation\n\n${flaw.recommendation}\n\n`;
    }

    // Add file information if available
    if (flaw.file) {
        let filePath = flaw.file;
        if (source_base_path_1) filePath = filePath.replace(source_base_path_1, '');
        if (source_base_path_2) filePath = filePath.replace(source_base_path_2, '');
        if (source_base_path_3) filePath = filePath.replace(source_base_path_3, '');
        
        description += `## Location\n\n`;
        description += `- **File**: ${filePath}\n`;
        if (flaw.line) {
            description += `- **Line**: ${flaw.line}\n`;
        }
        if (commit_hash) {
            description += `- **Commit**: ${commit_hash}\n`;
        }
    }

    return description;
}

function mapSeverity(veracodeSeverity) {
    const severityMap = {
        'Very High': '1 - Critical',
        'High': '2 - High',
        'Medium': '3 - Medium',
        'Low': '4 - Low',
        'Very Low': '5 - Low'
    };
    return severityMap[veracodeSeverity] || '3 - Medium';
}

module.exports = {
    importFlawsToADO
}; 