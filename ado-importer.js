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
        headers: {
            'Content-Type': 'application/json-patch+json',
            'Authorization': `Bearer ${adoPat}`
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

    // Extract fields for title and tags
    const flawId = flaw.issue_id || 'Unknown';
    const cweName = flaw.finding_details?.cwe?.name || 'Unknown';
    const cweId = flaw.finding_details?.cwe?.id || 'Unknown';
    const cweTag = cweId !== 'Unknown' ? `CWE_${cweId}` : '';

    // Format the description as HTML
    const description = formatDescriptionHTML(flaw, {
        source_base_path_1,
        source_base_path_2,
        source_base_path_3,
        commit_hash
    });

    // Now create the work item
    const url = `/${adoOrg}/${project}/_apis/wit/workitems/$${workItemType}?api-version=7.2-preview.3`;
    const tags = cweTag ? `Veracode;Security;${cweTag}` : 'Veracode;Security';
    const payload = [
        {
            op: 'add',
            path: '/fields/System.Title',
            value: `Veracode Flaw (Static): ${cweName}, Flaw ${flawId}`
        },
        {
            op: 'add',
            path: '/fields/System.Description',
            value: description
        },
        {
            op: 'add',
            path: '/fields/System.Tags',
            value: tags
        },
        {
            op: 'add',
            path: '/fields/Microsoft.VSTS.Common.Severity',
            value: mapSeverity(flaw.finding_details?.severity)
        }
    ];

    if (debug === 'true') {
        console.log('Creating work item with:');
        console.log('Base URL:', adoClient.defaults.baseURL);
        console.log('Organization:', adoOrg);
        console.log('Project:', project);
        console.log('URL:', url);
        console.log('Full URL:', `${adoClient.defaults.baseURL}${url}`);
        console.log('Payload:', JSON.stringify(payload, null, 2));
    }

    try {
        const response = await adoClient.post(url, payload);
        if (debug === 'true') {
            console.log('Response:', JSON.stringify(response.data, null, 2));
        }
        return response.data;
    } catch (error) {
        if (debug === 'true') {
            console.error('Error creating work item:');
            console.error('Status:', error.response?.status);
            console.error('Data:', error.response?.data);
            console.error('Headers:', error.response?.headers);
            console.error('Request URL:', error.config?.url);
            console.error('Request Method:', error.config?.method);
            console.error('Request Headers:', error.config?.headers);
        }
        throw error;
    }
}

function formatDescriptionHTML(flaw, params) {
    const { source_base_path_1, source_base_path_2, source_base_path_3, commit_hash } = params;
    const issueId = flaw.issue_id || 'Unknown';
    const severity = flaw.finding_details?.severity || 'Unknown';
    const cweId = flaw.finding_details?.cwe?.id || 'Unknown';
    const cweName = flaw.finding_details?.cwe?.name || 'Unknown';
    const cweUrl = flaw.finding_details?.cwe?.url || (cweId !== 'Unknown' ? `https://cwe.mitre.org/data/definitions/${cweId}.html` : '');
    const category = flaw.finding_details?.finding_category?.name || 'Unknown';
    const moduleName = flaw.finding_details?.module_name || 'Unknown';
    let filePath = flaw.finding_details?.file_path || 'Unknown';
    if (source_base_path_1) filePath = filePath.replace(source_base_path_1, '');
    if (source_base_path_2) filePath = filePath.replace(source_base_path_2, '');
    if (source_base_path_3) filePath = filePath.replace(source_base_path_3, '');
    const lineNumber = flaw.finding_details?.file_line_number || 'Unknown';
    const attackVector = flaw.finding_details?.attack_vector || 'Unknown';
    const descriptionText = flaw.description || '';
    const procedure = flaw.finding_details?.procedure || '';
    const references = flaw.finding_details?.references || [];
    const veracodeLink = flaw.finding_details?.veracode_link || '';
    const buildId = flaw.finding_details?.build_id || '';
    const policyLink = flaw.finding_details?.policy_link || '';

    let desc = '';
    desc += `<b>Veracode Links:</b> `;
    if (policyLink) {
        desc += `<a href='${policyLink}'>Application Policy Flaw</a>`;
    } else if (veracodeLink) {
        desc += `<a href='${veracodeLink}'>Flaw Link</a>`;
    } else {
        desc += 'N/A';
    }
    desc += `<br>`;
    desc += `<b>CWE:</b> <a href='${cweUrl}'>[${cweId} ${cweName}]</a><br>`;
    desc += `<b>Module:</b> ${moduleName}<br>`;
    desc += `<b>Source:</b> ${filePath}<br>`;
    desc += `<b>Line Number:</b> ${lineNumber}<br>`;
    desc += `<b>Attack Vector:</b> ${attackVector}<br>`;
    desc += `<b>Description:</b> ${descriptionText}<br>`;
    if (procedure) {
        desc += `<b>Procedure:</b> ${procedure}<br>`;
    }
    if (commit_hash) {
        desc += `<b>Commit:</b> ${commit_hash}<br>`;
    }
    if (references && Array.isArray(references) && references.length > 0) {
        desc += `<b>References:</b><ul>`;
        for (const ref of references) {
            if (ref.url) {
                desc += `<li><a href='${ref.url}'>${ref.title || ref.url}</a></li>`;
            } else {
                desc += `<li>${ref.title || ref}</li>`;
            }
        }
        desc += `</ul>`;
    }
    return desc;
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