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

    // Get existing work items to check for duplicates
    const existingWorkItems = await getExistingWorkItems(adoClient, adoOrg, adoProject, debug);
    console.log(`Found ${existingWorkItems.length} existing work items to check against`);

    // Track which work items are still active (not closed)
    const activeWorkItems = existingWorkItems.filter(wi => {
        const state = wi.fields['System.State'] || 'Unknown';
        return state !== 'Closed' && state !== 'Resolved' && state !== 'Removed';
    });
    console.log(`Found ${activeWorkItems.length} active work items to check for closure`);

    // Track which flaws we've processed to identify work items that should be closed
    const processedFlawIds = new Set();

    // Process each flaw
    let createdCount = 0;
    let reopenedCount = 0;
    let skippedCount = 0;

    for (const flaw of flaws) {
        try {
            const flawId = flaw.issue_id || 'Unknown';
            const cweId = flaw.finding_details?.cwe?.id || 'Unknown';
            const cweName = flaw.finding_details?.cwe?.name || 'Unknown';
            
            // Create a unique identifier for the flaw (similar to GitHub implementation)
            const veracodeFlawId = createVeracodeFlawId(flaw, scanType);
            
            // Track this flaw as processed
            processedFlawIds.add(veracodeFlawId);
            
            if (debug === 'true') {
                console.log(`Processing flaw ${flawId} with Veracode ID: ${veracodeFlawId}`);
            }
            
            // Check if work item already exists with enhanced duplicate detection
            const existingWorkItem = validateNoDuplicates(existingWorkItems, veracodeFlawId, debug);
            
            if (existingWorkItem) {
                const workItemState = existingWorkItem.fields['System.State'] || 'Unknown';
                console.log(`Work item already exists for flaw ${flawId} (ID: ${existingWorkItem.id}, State: ${workItemState})`);
                
                if (workItemState === 'Closed' || workItemState === 'Resolved') {
                    console.log(`Reopening closed work item ${existingWorkItem.id} for flaw ${flawId}`);
                    await reopenWorkItem(adoClient, adoOrg, adoProject, existingWorkItem.id, {
                        source_base_path_1,
                        source_base_path_2,
                        source_base_path_3,
                        commit_hash,
                        debug
                    });
                    reopenedCount++;
                } else {
                    console.log(`Work item ${existingWorkItem.id} is already open (State: ${workItemState}), skipping creation`);
                    skippedCount++;
                }
            } else {
                // Create new work item
                console.log(`Creating new work item for flaw ${flawId} (Veracode ID: ${veracodeFlawId})`);
                const workItem = await createWorkItem(adoClient, adoOrg, adoProject, adoWorkItemType, flaw, {
                    source_base_path_1,
                    source_base_path_2,
                    source_base_path_3,
                    commit_hash,
                    debug
                });

                console.log(`Successfully created work item ${workItem.id} for flaw ${flawId}`);
                createdCount++;
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
            core.error(`Failed to process work item for flaw ${flaw.issue_id}: ${error.message}`);
            if (fail_build === 'true') {
                throw error;
            }
        }
    }

    // Close work items that are no longer present in the scan results
    let closedCount = 0;
    console.log(`\nChecking for work items to close (flaws not found in current scan)...`);
    
    for (const workItem of activeWorkItems) {
        try {
            const title = workItem.fields['System.Title'] || '';
            const workItemId = workItem.id;
            
            // Check if this work item corresponds to a flaw that's still present
            const isStillPresent = Array.from(processedFlawIds).some(flawId => {
                return title.includes(flawId) || isWorkItemMatchingFlaw(workItem, flawId);
            });
            
            if (!isStillPresent) {
                console.log(`Closing work item ${workItemId} - flaw no longer found in scan: "${title}"`);
                await closeWorkItem(adoClient, adoOrg, adoProject, workItemId, commit_hash, debug);
                closedCount++;
                
                // Wait between API calls to avoid rate limiting
                await new Promise(resolve => setTimeout(resolve, waitTime * 1000));
            } else {
                if (debug === 'true') {
                    console.log(`Keeping work item ${workItemId} open - flaw still present: "${title}"`);
                }
            }
        } catch (error) {
            console.error(`Failed to close work item ${workItem.id}: ${error.message}`);
            if (fail_build === 'true') {
                throw error;
            }
        }
    }

    // Summary of work item operations
    console.log(`\n=== Work Item Processing Summary ===`);
    console.log(`Total flaws processed: ${flaws.length}`);
    console.log(`New work items created: ${createdCount}`);
    console.log(`Existing work items reopened: ${reopenedCount}`);
    console.log(`Existing work items skipped (already open): ${skippedCount}`);
    console.log(`Work items closed (flaw not found): ${closedCount}`);
    console.log(`Total work items affected: ${createdCount + reopenedCount + closedCount}`);
    
    if (createdCount + reopenedCount + skippedCount !== flaws.length) {
        console.warn(`WARNING: Processed ${createdCount + reopenedCount + skippedCount} work items but had ${flaws.length} flaws. Some flaws may not have been processed.`);
    }
}

async function getExistingWorkItems(adoClient, adoOrg, adoProject, debug) {
    try {
        // Query for existing work items with Veracode tags
        const url = `/${adoOrg}/${adoProject}/_apis/wit/wiql?api-version=7.2-preview.3`;
        const query = {
            query: "SELECT [System.Id], [System.Title], [System.State], [System.Tags], [System.ChangedDate] FROM WorkItems WHERE [System.Tags] CONTAINS 'Veracode' ORDER BY [System.ChangedDate] DESC"
        };

        if (debug === 'true') {
            console.log('Querying existing work items with query:', JSON.stringify(query, null, 2));
        }

        const response = await adoClient.post(url, query);
        const workItemIds = response.data.workItems.map(wi => wi.id);

        if (workItemIds.length === 0) {
            console.log('No existing work items with Veracode tags found');
            return [];
        }

        console.log(`Found ${workItemIds.length} existing work items with Veracode tags`);

        // Get full details for each work item
        const detailsUrl = `/${adoOrg}/${adoProject}/_apis/wit/workitems?ids=${workItemIds.join(',')}&$expand=all&api-version=7.2-preview.3`;
        const detailsResponse = await adoClient.get(detailsUrl);
        
        const workItems = detailsResponse.data.value || [];
        
        // Check for potential duplicates in the results
        const duplicateCheck = checkForDuplicateWorkItems(workItems, debug);
        if (duplicateCheck.duplicates.length > 0) {
            console.warn(`Found ${duplicateCheck.duplicates.length} potential duplicate work items in existing data:`);
            duplicateCheck.duplicates.forEach(dup => {
                console.warn(`  - Similar titles: "${dup.title1}" and "${dup.title2}"`);
            });
        }
        
        return workItems;
    } catch (error) {
        console.error('Error fetching existing work items:', error.message);
        if (debug === 'true' && error.response) {
            console.error('Response status:', error.response.status);
            console.error('Response data:', error.response.data);
        }
        return [];
    }
}

function checkForDuplicateWorkItems(workItems, debug) {
    const duplicates = [];
    const processedTitles = new Set();
    
    for (let i = 0; i < workItems.length; i++) {
        const title1 = workItems[i].fields['System.Title'] || '';
        const normalizedTitle1 = normalizeTitle(title1);
        
        if (processedTitles.has(normalizedTitle1)) {
            continue;
        }
        
        for (let j = i + 1; j < workItems.length; j++) {
            const title2 = workItems[j].fields['System.Title'] || '';
            const normalizedTitle2 = normalizeTitle(title2);
            
            if (normalizedTitle1 === normalizedTitle2 && title1 !== title2) {
                duplicates.push({
                    title1: title1,
                    title2: title2,
                    workItem1: workItems[i].id,
                    workItem2: workItems[j].id
                });
            }
        }
        
        processedTitles.add(normalizedTitle1);
    }
    
    return { duplicates };
}

function normalizeTitle(title) {
    // Normalize title for comparison by removing extra spaces and converting to lowercase
    return title.toLowerCase().replace(/\s+/g, ' ').trim();
}

function createVeracodeFlawId(flaw, scanType) {
    if (scanType === 'pipeline') {
        // For pipeline scans, use CWE:file:line format
        const cweId = flaw.cwe_id || 'Unknown';
        const fileName = flaw.files?.source_file?.file || 'Unknown';
        const lineNumber = flaw.files?.source_file?.line || 'Unknown';
        return `[VID:${cweId}:${fileName}:${lineNumber}]`;
    } else {
        // For policy scans, use flaw number format
        const flawNumber = flaw.issue_id || 'Unknown';
        return `[VID:${flawNumber}]`;
    }
}

function findExistingWorkItem(existingWorkItems, veracodeFlawId) {
    // First, try exact match
    let match = existingWorkItems.find(workItem => {
        const title = workItem.fields['System.Title'] || '';
        return title === veracodeFlawId || title.includes(veracodeFlawId);
    });

    if (match) {
        return match;
    }

    // If no exact match, try more flexible matching
    // Extract the core parts of the flaw ID for comparison
    const coreParts = extractCoreFlawParts(veracodeFlawId);
    
    return existingWorkItems.find(workItem => {
        const title = workItem.fields['System.Title'] || '';
        const tags = workItem.fields['System.Tags'] || '';
        
        // Check if title contains Veracode and matches core parts
        if (title.toLowerCase().includes('veracode') && title.toLowerCase().includes('flaw')) {
            return coreParts.every(part => 
                title.toLowerCase().includes(part.toLowerCase())
            );
        }
        
        return false;
    });
}

function extractCoreFlawParts(veracodeFlawId) {
    // Extract the key identifying parts from the flaw ID
    // Remove the [VID:] wrapper and split by colons
    const cleanId = veracodeFlawId.replace(/^\[VID:/, '').replace(/\]$/, '');
    return cleanId.split(':').filter(part => part && part !== 'Unknown');
}

function validateNoDuplicates(existingWorkItems, veracodeFlawId, debug) {
    const matches = existingWorkItems.filter(workItem => {
        const title = workItem.fields['System.Title'] || '';
        return title.includes(veracodeFlawId);
    });

    if (matches.length > 1) {
        console.warn(`WARNING: Found ${matches.length} existing work items for flaw ID: ${veracodeFlawId}`);
        if (debug === 'true') {
            matches.forEach((match, index) => {
                console.warn(`  Duplicate ${index + 1}: ID=${match.id}, Title="${match.fields['System.Title']}", State=${match.fields['System.State']}`);
            });
        }
        // Return the most recently updated one (assuming it's the most relevant)
        return matches.sort((a, b) => {
            const dateA = new Date(a.fields['System.ChangedDate'] || 0);
            const dateB = new Date(b.fields['System.ChangedDate'] || 0);
            return dateB - dateA;
        })[0];
    }

    return matches[0] || null;
}

async function reopenWorkItem(adoClient, adoOrg, adoProject, workItemId, params) {
    const { source_base_path_1, source_base_path_2, source_base_path_3, commit_hash, debug } = params;
    
    const url = `/${adoOrg}/${adoProject}/_apis/wit/workitems/${workItemId}?api-version=7.2-preview.3`;
    const payload = [
        {
            op: 'replace',
            path: '/fields/System.State',
            value: 'Active'
        },
        {
            op: 'add',
            path: '/fields/System.History',
            value: `Reopened by Veracode scan - Commit: ${commit_hash || 'Unknown'}`
        }
    ];

    if (debug === 'true') {
        console.log('Reopening work item with payload:', JSON.stringify(payload, null, 2));
    }

    try {
        const response = await adoClient.patch(url, payload);
        if (debug === 'true') {
            console.log('Work item reopened successfully:', response.data.id);
        }
        return response.data;
    } catch (error) {
        console.error(`Failed to reopen work item ${workItemId}:`, error.message);
        throw error;
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

async function closeWorkItem(adoClient, adoOrg, adoProject, workItemId, commit_hash, debug) {
    const url = `/${adoOrg}/${adoProject}/_apis/wit/workitems/${workItemId}?api-version=7.2-preview.3`;
    const payload = [
        {
            op: 'replace',
            path: '/fields/System.State',
            value: 'Closed'
        },
        {
            op: 'add',
            path: '/fields/System.History',
            value: `Closed by Veracode scan - Flaw no longer found in scan from commit ${commit_hash || 'Unknown'} on GitHub`
        }
    ];

    if (debug === 'true') {
        console.log('Closing work item with payload:', JSON.stringify(payload, null, 2));
    }

    try {
        const response = await adoClient.patch(url, payload);
        if (debug === 'true') {
            console.log('Work item closed successfully:', response.data.id);
        }
        return response.data;
    } catch (error) {
        console.error(`Failed to close work item ${workItemId}:`, error.message);
        throw error;
    }
}

function isWorkItemMatchingFlaw(workItem, flawId) {
    const title = workItem.fields['System.Title'] || '';
    const tags = workItem.fields['System.Tags'] || '';
    
    // Check if the work item title contains the flaw ID
    if (title.includes(flawId)) {
        return true;
    }
    
    // For more flexible matching, extract core parts and compare
    const coreParts = extractCoreFlawParts(flawId);
    if (coreParts.length > 0) {
        return coreParts.every(part => 
            title.toLowerCase().includes(part.toLowerCase())
        );
    }
    
    return false;
}

module.exports = {
    importFlawsToADO
}; 