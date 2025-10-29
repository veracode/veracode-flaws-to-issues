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
        adoOpenState,
        adoCloseState,
        adoReopenState,
        waitTime,
        source_base_path_1,
        source_base_path_2,
        source_base_path_3,
        commit_hash,
        fail_build,
        debug,
        autoCloseFindings
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

    // Create base ADO client with common headers
    const adoClient = axios.create({
        baseURL: baseUrl,
        headers: {
            'Authorization': `Bearer ${adoPat}`
        }
    });
    
    // Create specialized clients for different operations
    const adoQueryClient = axios.create({
        baseURL: baseUrl,
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${adoPat}`
        }
    });
    
    const adoPatchClient = axios.create({
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
        flaws = flawData.findings || [];
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
    const existingWorkItems = await getExistingWorkItems(adoQueryClient, adoClient, adoOrg, adoProject, debug);
    console.log(`Found ${existingWorkItems.length} existing work items to check against`);

    // Track which work items are still active (not closed)
    console.log(`\n=== Work Item State Analysis ===`);
    const stateCounts = {};
    existingWorkItems.forEach(wi => {
        const state = wi.fields['System.State'] || 'Unknown';
        stateCounts[state] = (stateCounts[state] || 0) + 1;
        if (debug === 'true') {
            console.log(`Work Item ${wi.id}: State="${state}", Title="${wi.fields['System.Title']?.substring(0, 50)}..."`);
        }
    });
    
    console.log(`Work item state distribution:`);
    Object.entries(stateCounts).forEach(([state, count]) => {
        console.log(`  ${state}: ${count} work items`);
    });
    
    const activeWorkItems = existingWorkItems.filter(wi => {
        const state = wi.fields['System.State'] || 'Unknown';
        return state !== 'Done' && state !== 'Resolved' && state !== 'Removed';
    });
    console.log(`Found ${activeWorkItems.length} active work items to check for closure`);

    // Track which flaws we've processed to identify work items that should be closed
    const processedFlawIds = new Set();
    
    // Initialize scan-type specific duplicate detection structures
    let duplicateDetectionData = {};
    if (scanType === 'pipeline') {
        // For pipeline scans: use file-based fuzzy matching
        duplicateDetectionData = {
            flawFiles: new Map(), // file -> [{cwe, line, workItemId, workItemState}]
            existingFlawNumbers: {}, // veracodeFlawId -> workItemId
            existingIssueStates: {} // veracodeFlawId -> workItemState
        };
    } else {
        // For policy scans: use exact flaw ID matching
        duplicateDetectionData = {
            existingFlaws: {}, // flawNumber -> true
            existingFlawNumbers: {}, // flawNumber -> workItemId
            existingIssueStates: {} // flawNumber -> workItemState
        };
    }
    
    // Populate duplicate detection data from existing work items
    populateDuplicateDetectionData(existingWorkItems, duplicateDetectionData, scanType, debug);

    // Process the flaws using ADO-specific functions
    let createdCount = 0;
    let reopenedCount = 0;
    let skippedCount = 0;
    let closedCount = 0;

    if (scanType === 'pipeline') {
        const result = await processPipelineFlawsADO(adoPatchClient, adoOrg, adoProject, adoWorkItemType, flawData, {
            source_base_path_1,
            source_base_path_2,
            source_base_path_3,
            commit_hash,
            waitTime,
            fail_build,
            debug,
            existingWorkItems,
            processedFlawIds,
            duplicateDetectionData
        });
        createdCount = result.createdCount;
        reopenedCount = result.reopenedCount;
        skippedCount = result.skippedCount;
        closedCount = closePipelineFlaws(adoClient, adoOrg, adoProject, activeWorkItems, result.processedFlawIds, commit_hash, debug)
    } else {
        const result = await processPolicyFlawsADO(adoPatchClient, adoOrg, adoProject, adoWorkItemType, flawData, {
            source_base_path_1,
            source_base_path_2,
            source_base_path_3,
            commit_hash,
            waitTime,
            fail_build,
            debug,
            existingWorkItems,
            processedFlawIds,
            duplicateDetectionData
        });
        createdCount = result.createdCount;
        reopenedCount = result.reopenedCount;
        skippedCount = result.skippedCount;
    }

    // Close work items that are no longer present in the scan results
    closedCount = 0;
    if (autoCloseFindings) {
        console.log(`\nChecking for work items to close (flaws not found in current scan)...`);
        console.log(`Processing ${activeWorkItems.length} active work items against ${processedFlawIds.size} processed flaw IDs`);
        
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
                await closeWorkItem(adoPatchClient, adoOrg, adoProject, workItemId, 'NOT_FOUND', commit_hash, debug, adoCloseState);
                closedCount++;
                
                // Wait between API calls to avoid rate limiting
                await new Promise(resolve => setTimeout(resolve, waitTime * 1000));
            } else {
                if (debug === 'true') {
                    console.log(`Keeping work item ${workItemId} open - flaw still present: "${title}"`);
                }
            }
        } catch (error) {
            if (error.response && error.response.status === 400) {
                console.log(`Work item ${workItem.id} not found (may have been deleted) - skipping closure: "${title}"`);
            } else {
                console.error(`Failed to close work item ${workItem.id}: ${error.message}`);
                if (fail_build === 'true') {
                    throw error;
                }
            }
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

async function getExistingWorkItems(adoQueryClient, adoClient, adoOrg, adoProject, debug) {
    try {
        // URL encode the organization and project names
        const encodedOrg = encodeURIComponent(adoOrg);
        const encodedProject = encodeURIComponent(adoProject);
        
        // Try different API versions and approaches
        const apiVersions = ['7.0', '6.0', '5.1'];
        let lastError = null;
        
        for (const apiVersion of apiVersions) {
            try {
                const url = `/${encodedOrg}/${encodedProject}/_apis/wit/wiql?api-version=${apiVersion}`;
                const query = {
                    query: `SELECT [System.Id], [System.Title], [System.State], [System.Tags], [System.ChangedDate] FROM WorkItems WHERE [System.Tags] Contains 'Veracode' AND [System.TeamProject] = '${adoProject}' ORDER BY [System.ChangedDate] DESC`
                };

                if (debug === 'true') {
                    console.log(`Trying API version ${apiVersion}...`);
                    console.log('Querying existing work items with query:', JSON.stringify(query, null, 2));
                    console.log('Full URL:', `${adoQueryClient.defaults.baseURL}${url}`);
                }

                const response = await adoQueryClient.post(url, query);
                const workItemIds = response.data.workItems.map(wi => wi.id);

                if (workItemIds.length === 0) {
                    console.log(`No existing work items with Veracode tags found in project '${adoProject}'`);
                    if (debug === 'true') {
                        console.log('Query executed successfully but returned no results');
                        console.log('This could mean:');
                        console.log('  1. No work items exist with "Veracode" tag in this project');
                        console.log('  2. The project name might be incorrect');
                        console.log('  3. The WIQL query syntax might need adjustment');
                    }
                    return [];
                }

                console.log(`Found ${workItemIds.length} existing work items with Veracode tags in project '${adoProject}' using API version ${apiVersion}`);
                if (debug === 'true') {
                    console.log('Work item IDs found:', workItemIds);
                }

                // Get full details for each work item with pagination (max 200 per request)
                const workItems = [];
                const batchSize = 200;
                
                for (let i = 0; i < workItemIds.length; i += batchSize) {
                    const batch = workItemIds.slice(i, i + batchSize);
                    const detailsUrl = `/${encodedOrg}/${encodedProject}/_apis/wit/workitems?ids=${batch.join(',')}&$expand=all&api-version=${apiVersion}`;
                    
                    if (debug === 'true') {
                        console.log(`Fetching work item details batch ${Math.floor(i/batchSize) + 1}/${Math.ceil(workItemIds.length/batchSize)} (${batch.length} items)`);
                    }
                    
                    const detailsResponse = await adoClient.get(detailsUrl);
                    const batchWorkItems = detailsResponse.data.value || [];
                    workItems.push(...batchWorkItems);
                    
                    // Small delay between batches to avoid rate limiting
                    if (i + batchSize < workItemIds.length) {
                        await new Promise(resolve => setTimeout(resolve, 100));
                    }
                }
                
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
                lastError = error;
                if (debug === 'true') {
                    console.log(`API version ${apiVersion} failed:`, error.message);
                    if (error.response) {
                        console.log(`  Status: ${error.response.status}`);
                        console.log(`  Data:`, error.response.data);
                    }
                }
                // Continue to next API version
            }
        }
        
        // If all API versions failed, try a fallback approach using direct work items API
        console.log('WIQL query failed, trying fallback approach...');
        try {
            // Note: The $filter approach may not work as expected, but let's try it
            const fallbackUrl = `/${encodedOrg}/${encodedProject}/_apis/wit/workitems?$filter=System.Tags Contains 'Veracode'&$expand=all&api-version=7.0`;
            const fallbackResponse = await adoClient.get(fallbackUrl);
            const workItems = fallbackResponse.data.value || [];
            
            if (workItems.length === 0) {
                console.log('No existing work items with Veracode tags found (fallback method)');
                return [];
            }
            
            console.log(`Found ${workItems.length} existing work items with Veracode tags using fallback method`);
            return workItems;
        } catch (fallbackError) {
            console.log('Fallback method also failed:', fallbackError.message);
            // If fallback also fails, return empty array instead of throwing error
            // This allows the import to continue even if we can't get existing work items
            console.log('Continuing without existing work item data - deduplication will be limited');
            return [];
        }
    } catch (error) {
        console.error('Error fetching existing work items:', error.message);
        if (debug === 'true' && error.response) {
            console.error('Response status:', error.response.status);
            console.error('Response data:', error.response.data);
            console.error('Response headers:', error.response.headers);
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
        const cweName = flaw.issue_type || 'Unknown';
        const flawId = flaw.issue_id || 'Unknown';
        return `Veracode Flaw (Static): ${cweName}, Flaw ${flawId}`
    } else {
        // For policy scans, use flaw number format
        const cweName = flaw.finding_details?.cwe?.name || 'Unknown';
        const flawId = flaw.issue_id || 'Unknown';
        return `Veracode Flaw (Static): ${cweName}, Flaw ${flawId}`
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

function formatMitigation(annotation){
    const mitigationStatus = ['COMMENT', 'FP', 'APPROVED', 'REJECTED']
    let mitigation = ''

    const created = annotation.created || 'Unknown';
    const comment = annotation.comment || 'Unknown';
    const action = annotation.action || 'Unknown';
    const user_name = annotation.user_name || 'Unknown';

    const technique = annotation.technique || 'Unknown';
    const specifics = annotation.specifics || 'Unknown';
    const remaining_risk = annotation.remaining_risk || 'Unknown';
    const verification = annotation.verification || 'Unknown';
    
    const mitigation_title = created + ":" + user_name + ":" + action;
    mitigation += mitigation_title + "<br>";
    mitigation += "<b>User:</b> " + user_name + "<br>";;
    mitigation += "<b>Created:</b> " + created + "<br>";;
    mitigation += "<b>Action:</b> " + action + "<br>";;

    if(!mitigationStatus.includes(action)){
        mitigation += "<b>Technique:</b> " + technique + "<br/>";
        mitigation += "<b>Specifics:</b> " + specifics + "<br>";
        mitigation += "<b>Remaining Risk:</b> " + remaining_risk + "<br>";
        mitigation += "<b>Verification:</b> " + verification + "<br>";
    } else {
        mitigation += "<b>Comment:</b>" + comment;
    }

    return { mitigation_title, mitigation }
}

async function checkExistingComments(adoClient, url, workItemId){
    try {
        const response = await adoClient.get(url, {
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        return response.data.comments
    } catch (error) {
        console.error(`Failed to get comment for work item ${workItemId}:`, error.message);
        throw error;
    }
}

async function updateWorkItem(adoClient, adoOrg, adoProject, workItemId, annotations, params) {
    const { commit_hash, debug, workItemType } = params;
    
    const sorted_annotations = annotations.sort(function(a, b){
        const dateA = new Date(a.created);
        const dateB = new Date(b.created);
        return dateA - dateB;
    })

    if (workItemType === 'Bug') {
        // For Bug work items, add mitigation information to Discussion field individually
        // We need to check existing Discussion content to avoid duplicates
        const url = `/${adoOrg}/${adoProject}/_apis/wit/workitems/${workItemId}?api-version=7.0`;
        
        // Get current work item to check existing Discussion content
        let existingDiscussion = '';
        try {
            const currentWorkItem = await adoClient.get(url);
            existingDiscussion = currentWorkItem.data.fields['System.History'] || '';
        } catch (error) {
            console.error(`Failed to get current work item ${workItemId} for Discussion check:`, error.message);
        }
        
        // Process each annotation individually to avoid duplicates
        for (const annot of sorted_annotations) {
            const { mitigation_title, mitigation } = formatMitigation(annot);
            
            // Check if this mitigation already exists in Discussion
            const duplicate_mitigation = existingDiscussion.includes(mitigation_title);
            
            if (!duplicate_mitigation) {
                // Add this specific mitigation to Discussion
                const payload = [
                    {
                        op: 'add',
                        path: '/fields/System.History',
                        value: mitigation
                    }
                ];
                
                try {
                    await adoClient.patch(url, payload, {
                        headers: {
                            'Content-Type': 'application/json-patch+json'
                        }
                    });
                    if (debug === 'true') {
                        console.log(`Added mitigation "${mitigation_title}" to Bug work item ${workItemId} Discussion field`);
                    }
                    
                    // Update our local copy to avoid duplicates in the same run
                    existingDiscussion += mitigation;
                } catch (error) {
                    console.error(`Failed to add mitigation "${mitigation_title}" to Bug work item ${workItemId}:`, error.message);
                }
            } else {
                if (debug === 'true') {
                    console.log(`Skipping duplicate mitigation "${mitigation_title}" found in Bug work item ${workItemId} Discussion`);
                }
            }
        }
    } else {
        // For Issue work items, use comments (existing behavior)
        const url = `/${adoOrg}/${adoProject}/_apis/wit/workItems/${workItemId}/comments?api-version=7.0-preview.3`;
        
        for(const annot of sorted_annotations){
            const { mitigation_title, mitigation } = formatMitigation(annot)
            const comments = await checkExistingComments(adoClient, url, workItemId)

            let duplicate_comment = comments.find(({text}) => text.startsWith(mitigation_title))
            
            if(duplicate_comment === undefined){
                const payload = { text: mitigation }
                
                addComment(adoClient, url, workItemId, payload, debug)
            } else {
                if(debug === 'true'){
                    console.log(`Skipping duplicate comment found for work item ${workItemId} with ${mitigation_title}`);
                }
            }
        }
    }
}

async function addComment(adoClient, url, workItemId, payload, debug){
    try {
        const response = await adoClient.post(url, payload, {
            headers: {
                'Content-Type': 'application/json'
            }
        });
        console.log('Work item comment added successfully');
        if (debug === 'true'){
            console.log('Adding Mitigation Comments to work item with payload:', JSON.stringify(payload, null, 2));
        }
        return response;
    } catch (error) {
        console.error(`Failed to add comment to work item ${workItemId}:`, error.message);
        throw error;
    }
}

async function reopenWorkItem(adoClient, adoOrg, adoProject, workItemId, params) {
    const { source_base_path_1, source_base_path_2, source_base_path_3, commit_hash, debug, adoReopenState } = params;
    
    const url = `/${adoOrg}/${adoProject}/_apis/wit/workitems/${workItemId}?api-version=7.0`;
    
    // Use configurable reopen state, with fallback to common states
    const candidateStates = adoReopenState ? [adoReopenState] : ['To Do', 'Active', 'New', 'Open'];
    
    for (const state of candidateStates) {
        const payload = [
            {
                op: 'replace',
                path: '/fields/System.State',
                value: state
            },
            {
                op: 'add',
                path: '/fields/System.History',
                value: `Reopened by Veracode scan - Commit: ${commit_hash || 'Unknown'}`
            }
        ];

        if (debug === 'true') {
            console.log(`Attempting to reopen work item ${workItemId} using state "${state}" with payload:`, JSON.stringify(payload, null, 2));
        }

        try {
            const response = await adoClient.patch(url, payload, {
                headers: {
                    'Content-Type': 'application/json-patch+json'
                }
            });
            if (debug === 'true') {
                console.log(`Work item ${workItemId} reopened successfully with state "${state}"`);
            }
            return response.data;
        } catch (error) {
            const status = error?.response?.status;
            if (debug === 'true') {
                console.log(`Reopening with state "${state}" failed${status ? ` (status ${status})` : ''}. Trying next candidate...`);
                if (error?.response?.data) {
                    console.log('ADO error response:', JSON.stringify(error.response.data));
                }
            }
            // Try next candidate state on 400/422 errors, otherwise rethrow
            if (status && (status === 400 || status === 422)) {
                continue;
            }
            throw error;
        }
    }

    // If none of the states worked, throw a clear error
    throw new Error(`Failed to reopen work item ${workItemId}: none of the candidate states were accepted (${candidateStates.join(', ')})`);
}

async function createWorkItem(adoClient, adoOrg, project, workItemType, flaw, params) {
    const { source_base_path_1, source_base_path_2, source_base_path_3, commit_hash, debug, scanType, adoOpenState } = params;

    // Extract fields for title and tags based on scan type
    const flawId = flaw.issue_id || 'Unknown';
    let cweName, cweId;
    if (scanType === 'pipeline') {
        cweName = flaw.issue_type || 'Unknown';
        cweId = flaw.cwe_id || 'Unknown';
    } else {
        cweName = flaw.finding_details?.cwe?.name || 'Unknown';
        cweId = flaw.finding_details?.cwe?.id || 'Unknown';
    }
    const cweTag = cweId !== 'Unknown' ? `CWE_${cweId}` : '';

    // Format the description as HTML
    const description = formatDescriptionHTML(flaw, {
        source_base_path_1,
        source_base_path_2,
        source_base_path_3,
        commit_hash,
        scanType
    });

    // Now create the work item
    const url = `/${adoOrg}/${project}/_apis/wit/workitems/$${workItemType}?api-version=7.0`;
    const tags = cweTag ? `Veracode;Security;${cweTag}` : 'Veracode;Security';
    
    // Create title without duplication
    let title;
    if (scanType === 'pipeline') {
        // Pipeline: Just use the VeracodeFlawID which already contains the CWE name
        title = createVeracodeFlawId(flaw, scanType);
    } else {
        // Policy: Add category to the VeracodeFlawID
        const category = flaw.finding_details?.finding_category?.name || 'Unknown';
        const baseTitle = createVeracodeFlawId(flaw, scanType);
        title = `${baseTitle} ('${category}')`;
    }
    
    // Create payload based on work item type
    let payload;
    // Normalize type comparison to be case-insensitive
    if (String(workItemType).toLowerCase() === 'bug') {
        // Bug work item type - use Repro Steps field for description
        // Some ADO processes map description differently. To be robust, we set BOTH
        // Repro Steps and System.Description so the content shows regardless of template.
        payload = [
            {
                op: 'add',
                path: '/fields/System.Title',
                value: title
            },
            {
                op: 'add',
                path: '/fields/Microsoft.VSTS.TCM.ReproSteps',
                value: description
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
                value: mapSeverity(scanType === 'pipeline' ? flaw.severity : flaw.finding_details?.severity)
            },
            {
                op: 'add',
                path: '/fields/System.State',
                value: adoOpenState || 'New'
            }
        ];
    } else {
        // Issue work item type - use Description field (existing behavior)
        payload = [
            {
                op: 'add',
                path: '/fields/System.Title',
                value: title
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
                value: mapSeverity(scanType === 'pipeline' ? flaw.severity : flaw.finding_details?.severity)
            }
        ];
    }

    if (debug === 'true') {
        console.log('Creating work item with:');
        console.log('Base URL:', adoClient.defaults.baseURL);
        console.log('Organization:', adoOrg);
        console.log('Project:', project);
        console.log('URL:', url);
        console.log('Full URL:', `${adoClient.defaults.baseURL}${url}`);
        console.log('Payload:', JSON.stringify(payload, null, 2));
    }

    // For Bug, we might need to adapt payload to process templates. Try candidates when needed.
    const isBug = String(workItemType).toLowerCase() === 'bug';
    if (isBug) {
        // Build candidate payloads derived from the primary Bug payload above
        const baseAdds = payload.filter(p => p.path !== '/fields/Microsoft.VSTS.TCM.ReproSteps' && p.path !== '/fields/System.Description');
        const repro = { op: 'add', path: '/fields/Microsoft.VSTS.TCM.ReproSteps', value: description };
        const desc  = { op: 'add', path: '/fields/System.Description', value: description };
        const candidates = [
            [...baseAdds, repro, desc],
            [...baseAdds, repro],
            [...baseAdds, desc],
            [...baseAdds]
        ];

        for (let i = 0; i < candidates.length; i++) {
            try {
                if (debug === 'true') {
                    console.log(`Posting Bug create with candidate #${i+1}`);
                }
                const response = await adoClient.post(url, candidates[i], {
                    headers: { 'Content-Type': 'application/json-patch+json' }
                });
                if (debug === 'true') {
                    console.log('Response:', JSON.stringify(response.data, null, 2));
                }
                // If last candidate (no description fields) was used, add description to Discussion
                if (i === candidates.length - 1) {
                    try {
                        const discussUrl = `/${adoOrg}/${project}/_apis/wit/workitems/${response.data.id}?api-version=7.0`;
                        const discussPayload = [{ op: 'add', path: '/fields/System.History', value: description }];
                        await adoClient.patch(discussUrl, discussPayload, { headers: { 'Content-Type': 'application/json-patch+json' } });
                    } catch (e) {
                        console.error(`Failed to backfill Discussion for Bug ${response.data?.id}: ${e.message}`);
                    }
                }
                return response.data;
            } catch (error) {
                const status = error?.response?.status;
                console.error(`Bug create candidate #${i+1} failed${status ? ` (status ${status})` : ''}: ${error.message}`);
                if (error?.response?.data) {
                    console.error('ADO response:', JSON.stringify(error.response.data));
                }
                if (!(status && (status === 400 || status === 422))) {
                    throw error;
                }
                // try next
            }
        }
        // If all candidates failed, throw
        throw new Error('Failed to create Bug work item after trying all payload variants');
    }

    // Non-Bug types: single post as before
    try {
        const response = await adoClient.post(url, payload, {
            headers: {
                'Content-Type': 'application/json-patch+json'
            }
        });
        if (debug === 'true') {
            console.log('Response:', JSON.stringify(response.data, null, 2));
        }
        return response.data;
    } catch (error) {
        console.error('Error creating work item:', error.message);
        if (error.response) {
            console.error('Status:', error.response.status);
            console.error('Data:', error.response.data);
        }
        throw error;
    }
}

function formatDescriptionHTML(flaw, params) {
    const { source_base_path_1, source_base_path_2, source_base_path_3, commit_hash, scanType } = params;
    const issueId = flaw.issue_id || 'Unknown';
    
    // Extract fields based on scan type
    let severity, cweId, cweName, cweUrl, category, moduleName, filePath, lineNumber, attackVector, descriptionText, procedure, references, veracodeLink, buildId, policyLink;
    
    if (scanType === 'pipeline') {
        severity = flaw.severity || 'Unknown';
        cweId = flaw.cwe_id || 'Unknown';
        cweName = flaw.issue_type || 'Unknown';
        cweUrl = cweId !== 'Unknown' ? `https://cwe.mitre.org/data/definitions/${cweId}.html` : '';
        category = 'Unknown'; // Pipeline scans don't have category
        moduleName = 'Unknown'; // Pipeline scans don't have module name
        filePath = flaw.files?.source_file?.file || 'Unknown';
        lineNumber = flaw.files?.source_file?.line || 'Unknown';
        attackVector = 'Unknown'; // Pipeline scans don't have attack vector
        descriptionText = flaw.display_text || '';
        procedure = ''; // Pipeline scans don't have procedure
        references = []; // Pipeline scans don't have references
        veracodeLink = ''; // Pipeline scans don't have veracode link
        buildId = ''; // Pipeline scans don't have build ID
        policyLink = ''; // Pipeline scans don't have policy link
    } else {
        severity = flaw.finding_details?.severity || 'Unknown';
        cweId = flaw.finding_details?.cwe?.id || 'Unknown';
        cweName = flaw.finding_details?.cwe?.name || 'Unknown';
        cweUrl = flaw.finding_details?.cwe?.url || (cweId !== 'Unknown' ? `https://cwe.mitre.org/data/definitions/${cweId}.html` : '');
        category = flaw.finding_details?.finding_category?.name || 'Unknown';
        moduleName = flaw.finding_details?.module_name || 'Unknown';
        filePath = flaw.finding_details?.file_path || 'Unknown';
        lineNumber = flaw.finding_details?.file_line_number || 'Unknown';
        attackVector = flaw.finding_details?.attack_vector || 'Unknown';
        descriptionText = flaw.description || '';
        procedure = flaw.finding_details?.procedure || '';
        references = flaw.finding_details?.references || [];
        veracodeLink = flaw.finding_details?.veracode_link || '';
        buildId = flaw.finding_details?.build_id || '';
        policyLink = flaw.finding_details?.policy_link || '';
    }
    
    // Apply path replacements
    if (source_base_path_1) filePath = filePath.replace(source_base_path_1, '');
    if (source_base_path_2) filePath = filePath.replace(source_base_path_2, '');
    if (source_base_path_3) filePath = filePath.replace(source_base_path_3, '');

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

async function closeWorkItem(adoClient, adoOrg, adoProject, workItemId, resolution, commit_hash, debug, adoCloseState) {
    const url = `/${adoOrg}/${adoProject}/_apis/wit/workitems/${workItemId}?api-version=7.0`;

    // Create appropriate closure message based on resolution
    let closureMessage;
    if (resolution === 'MITIGATED') {
        closureMessage = `This work item has been automatically closed by Veracode automation because the finding has been mitigated (APPROVED status). Closed by Veracode scan from commit ${commit_hash || 'Unknown'}.`;
    } else if (resolution === 'CLOSED BY SCAN') {
        closureMessage = `This work item has been automatically closed by Veracode automation because the flaw is no longer present in the latest scan results. Closed by Veracode scan from commit ${commit_hash || 'Unknown'}.`;
    } else {
        closureMessage = `This work item has been automatically closed by Veracode automation. Closed by Veracode scan from commit ${commit_hash || 'Unknown'}.`;
    }

    // Use configurable close state, with fallback to common states
    const candidateStates = adoCloseState ? [adoCloseState] : ['Done', 'Closed', 'Resolved', 'Completed'];

    for (const state of candidateStates) {
        const payload = [
            {
                op: 'replace',
                path: '/fields/System.State',
                value: state
            },
            {
                op: 'add',
                path: '/fields/System.History',
                value: closureMessage
            }
        ];

        if (debug === 'true') {
            console.log(`Attempting to close work item ${workItemId} using state "${state}" with payload:`, JSON.stringify(payload, null, 2));
        }

        try {
            const response = await adoClient.patch(url, payload, {
                headers: {
                    'Content-Type': 'application/json-patch+json'
                }
            });
            if (debug === 'true') {
                console.log(`Work item ${workItemId} closed successfully with state "${state}"`);
            }
            return response.data;
        } catch (error) {
            const status = error?.response?.status;
            if (debug === 'true') {
                console.log(`Closing with state "${state}" failed${status ? ` (status ${status})` : ''}. Trying next candidate...`);
                if (error?.response?.data) {
                    console.log('ADO error response:', JSON.stringify(error.response.data));
                }
            }
            // Try next candidate state on 400/422 errors, otherwise rethrow
            if (status && (status === 400 || status === 422)) {
                continue;
            }
            throw error;
        }
    }

    // If none of the states worked, throw a clear error
    throw new Error(`Failed to close work item ${workItemId}: none of the candidate states were accepted (${candidateStates.join(', ')})`);
}

async function closePipelineFlaws(adoClient, adoOrg, adoProject, activeWorkItems, processedFlawIds, commit_hash, debug){
    // Close work items that are no longer present in the scan results
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
                await closeWorkItem(adoClient, adoOrg, adoProject, workItemId, 'CLOSED BY SCAN', commit_hash, debug, adoCloseState);
                closedCount++;
                
                // Wait between API calls to avoid rate limiting
                await new Promise(resolve => setTimeout(resolve, waitTime * 1000));
            } else {
                if (debug === 'true') {
                    console.log(`Keeping work item ${workItemId} open - flaw still present: "${title}"`);
                }
            }
        } catch (error) {
            if (error.response && error.response.status === 400) {
                console.log(`Work item ${workItem.id} not found (may have been deleted) - skipping closure: "${title}"`);
            } else {
                console.error(`Failed to close work item ${workItem.id}: ${error.message}`);
                if (fail_build === 'true') {
                    throw error;
                }
            }
        }
    }

    return closedCount
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

// Helper function to populate duplicate detection data from existing work items
function populateDuplicateDetectionData(existingWorkItems, duplicateDetectionData, scanType, debug) {
    if (debug === 'true') {
        console.log(`Populating duplicate detection data for ${scanType} scan with ${existingWorkItems.length} existing work items`);
    }
    
    existingWorkItems.forEach(workItem => {
        const title = workItem.fields['System.Title'] || '';
        const workItemId = workItem.id;
        const workItemState = workItem.fields['System.State'] || 'Unknown';
        
        if (debug === 'true') {
            console.log(`Processing existing work item ${workItemId}: "${title}"`);
        }
        
        if (scanType === 'pipeline') {
            // Extract Veracode Flaw ID from title for pipeline scans
            const veracodeFlawId = getVeracodeFlawIDFromTitle(title);
            if (!veracodeFlawId) {
                if (debug === 'true') {
                    console.log(`No Veracode Flaw ID found in title: "${title}"`);
                }
                return;
            }
            
            // Parse pipeline flaw ID: [VID:CWE:filename:linenum]
            const flawInfo = parseVeracodeFlawID(veracodeFlawId);
            if (flawInfo && flawInfo.file) {
                const flawData = {
                    cwe: flawInfo.cwe,
                    line: flawInfo.line,
                    workItemId: workItemId,
                    workItemState: workItemState
                };
                
                if (duplicateDetectionData.flawFiles.has(flawInfo.file)) {
                    duplicateDetectionData.flawFiles.get(flawInfo.file).push(flawData);
                } else {
                    duplicateDetectionData.flawFiles.set(flawInfo.file, [flawData]);
                }
                
                duplicateDetectionData.existingFlawNumbers[veracodeFlawId] = workItemId;
                duplicateDetectionData.existingIssueStates[veracodeFlawId] = workItemState;
                
                if (debug === 'true') {
                    console.log(`Added pipeline flaw data: File=${flawInfo.file}, CWE=${flawInfo.cwe}, Line=${flawInfo.line}, WorkItem=${workItemId}`);
                }
            } else {
                if (debug === 'true') {
                    console.log(`Failed to parse pipeline flaw ID: ${veracodeFlawId}`);
                }
            }
        } else {
            // Extract flaw ID directly from title for policy scans
            // Title format: "Veracode Flaw (Static): [CWE Name], Flaw [ID]"
            const flawIdMatch = title.match(/Flaw (\d+)/);
            if (flawIdMatch) {
                const flawId = flawIdMatch[1];
                duplicateDetectionData.existingFlaws[flawId] = true;
                duplicateDetectionData.existingFlawNumbers[flawId] = workItemId;
                duplicateDetectionData.existingIssueStates[flawId] = workItemState;
                
                if (debug === 'true') {
                    console.log(`✅ Added policy flaw data: FlawId=${flawId}, WorkItem=${workItemId}`);
                }
            } else {
                if (debug === 'true') {
                    console.log(`❌ Failed to extract flaw ID from title: "${title}"`);
                }
            }
        }
    });
    
    if (debug === 'true' && scanType === 'pipeline') {
        console.log(`Final duplicate detection data for pipeline scan:`);
        console.log(`  Files with flaws:`, Array.from(duplicateDetectionData.flawFiles.keys()));
        for (const [file, flaws] of duplicateDetectionData.flawFiles.entries()) {
            console.log(`  File ${file}:`, flaws);
        }
    }
}

// Helper function to extract Veracode Flaw ID from work item title
function getVeracodeFlawIDFromTitle(title) {
    const start = title.indexOf('[VID');
    if (start === -1) return null;
    const end = title.indexOf(']', start);
    if (end === -1) return null;
    return title.substring(start, end + 1);
}

// Helper function to parse Veracode Flaw ID
function parseVeracodeFlawID(vid) {
    if (!vid) return null;
    const parts = vid.replace(/^\[VID:/, '').replace(/\]$/, '').split(':');
    
    if (parts.length === 1) {
        // Policy scan: [VID:FlawID]
        return {
            prefix: '[VID',
            flawNum: parts[0]
        };
    } else if (parts.length === 3) {
        // Pipeline scan: [VID:CWE:filename:linenum]
        return {
            prefix: '[VID',
            cwe: parts[0],
            file: parts[1],
            line: parts[2]
        };
    }
    return null;
}

// Pipeline-specific duplicate detection (fuzzy matching)
function pipelineIssueExists(flaw, duplicateDetectionData, debug) {
    const cweId = flaw.cwe_id || 'Unknown';
    const fileName = flaw.files?.source_file?.file || 'Unknown';
    const lineNumber = flaw.files?.source_file?.line || 'Unknown';
    
    if (debug === 'true') {
        console.log(`Checking pipeline duplicate for: CWE=${cweId}, File=${fileName}, Line=${lineNumber}`);
        console.log(`Available files in duplicate detection data:`, Array.from(duplicateDetectionData.flawFiles.keys()));
    }
    
    if (!duplicateDetectionData.flawFiles.has(fileName)) {
        if (debug === 'true') {
            console.log(`File ${fileName} not found in existing flaws`);
        }
        return null;
    }
    
    const existingFlaws = duplicateDetectionData.flawFiles.get(fileName);
    const newFlawLine = parseInt(lineNumber);
    
    if (debug === 'true') {
        console.log(`Found ${existingFlaws.length} existing flaws in file ${fileName}:`, existingFlaws);
    }
    
    for (const existingFlaw of existingFlaws) {
        // Check CWE match
        if (existingFlaw.cwe === cweId) {
            // Check line range (±10 lines)
            const existingFlawLine = parseInt(existingFlaw.line);
            if (debug === 'true') {
                console.log(`CWE match found! Checking line range: new=${newFlawLine}, existing=${existingFlawLine} (range: ${existingFlawLine - 10} to ${existingFlawLine + 10})`);
            }
            if (newFlawLine >= (existingFlawLine - 10) && newFlawLine <= (existingFlawLine + 10)) {
                if (debug === 'true') {
                    console.log(`DUPLICATE FOUND! WorkItem ID: ${existingFlaw.workItemId}, State: ${existingFlaw.workItemState}`);
                }
                return {
                    workItemId: existingFlaw.workItemId,
                    workItemState: existingFlaw.workItemState
                };
            }
        }
    }
    
    if (debug === 'true') {
        console.log(`No duplicate found for this flaw`);
    }
    return null;
}

// Policy-specific duplicate detection (exact matching by flaw ID)
function policyIssueExists(flaw, duplicateDetectionData) {
    const flawId = flaw.issue_id || 'Unknown';
    
    // Use flaw ID directly for deduplication
    if (duplicateDetectionData.existingFlaws[flawId] === true) {
        return {
            workItemId: duplicateDetectionData.existingFlawNumbers[flawId],
            workItemState: duplicateDetectionData.existingIssueStates[flawId]
        };
    }
    
    return null;
}

// Helper function to process annotations and determine action (same logic as GitHub)
function processAnnotationsADO(annotations) {
    if (!annotations || annotations.length === 0) {
        return { action: 'none', annotations: [] };
    }
    
    // Sort all annotations by created date (most recent first)
    const sortedAnnotations = annotations.sort((a, b) => new Date(b.created) - new Date(a.created));
    
    // Find the most recent APPROVED or REJECTED annotation (these take precedence)
    const mostRecentApprovedOrRejected = sortedAnnotations.find(ann => 
        ann.action === 'APPROVED' || ann.action === 'REJECTED'
    );
    
    // If we have an APPROVED or REJECTED annotation, use it to determine the action
    if (mostRecentApprovedOrRejected) {
        if (mostRecentApprovedOrRejected.action === 'APPROVED') {
            return { 
                action: 'close', 
                annotations: sortedAnnotations,
                mostRecent: mostRecentApprovedOrRejected
            };
        } else if (mostRecentApprovedOrRejected.action === 'REJECTED') {
            return { 
                action: 'reopen', 
                annotations: sortedAnnotations,
                mostRecent: mostRecentApprovedOrRejected
            };
        }
    }
    
    // If no APPROVED or REJECTED annotations, use the most recent annotation for update
    const mostRecent = sortedAnnotations[0];
    return { 
        action: 'update', 
        annotations: sortedAnnotations,
        mostRecent: mostRecent
    };
}

// ADO-specific pipeline flaws processing
async function processPipelineFlawsADO(adoPatchClient, adoOrg, adoProject, adoWorkItemType, flawData, params) {
    const { source_base_path_1, source_base_path_2, source_base_path_3, commit_hash, waitTime, fail_build, debug, existingWorkItems, processedFlawIds, duplicateDetectionData, adoOpenState, adoReopenState } = params;
    
    let createdCount = 0;
    let reopenedCount = 0;
    let skippedCount = 0;
    
    const flaws = flawData.findings || [];
    console.log(`Processing ${flaws.length} pipeline flaws for ADO`);
    
    for (const flaw of flaws) {
        try {
            const flawId = flaw.issue_id || 'Unknown';
            const cweId = flaw.cwe_id || 'Unknown';
            const cweName = flaw.issue_type || 'Unknown';
            
            // Create a unique identifier for the flaw
            const veracodeFlawId = createVeracodeFlawId(flaw, 'pipeline');
            
            // Track this flaw as processed
            processedFlawIds.add(veracodeFlawId);
            
            if (debug === 'true') {
                console.log(`Processing pipeline flaw ${flawId} with Veracode ID: ${veracodeFlawId}`);
            }
            
            // Check if work item already exists using pipeline-specific fuzzy matching
            const existingWorkItem = pipelineIssueExists(flaw, duplicateDetectionData, debug);
            
            if (existingWorkItem) {
                const workItemState = existingWorkItem.workItemState;
                const workItemId = existingWorkItem.workItemId;
                console.log(`Work item already exists for pipeline flaw ${flawId} (ID: ${workItemId}, State: ${workItemState})`);
                
                if (workItemState === 'Closed' || workItemState === 'Resolved') {
                    console.log(`Reopening closed work item ${workItemId} for flaw ${flawId}`);
                    await reopenWorkItem(adoPatchClient, adoOrg, adoProject, workItemId, {
                        source_base_path_1,
                        source_base_path_2,
                        source_base_path_3,
                        commit_hash,
                        debug,
                        adoReopenState
                    });
                    reopenedCount++;
                } else {
                    console.log(`Work item ${workItemId} is already open (State: ${workItemState}), skipping creation`);
                    skippedCount++;
                }
            } else {
                // Create new work item
                console.log(`Creating new work item for pipeline flaw ${flawId} (Veracode ID: ${veracodeFlawId})`);
                const workItem = await createWorkItem(adoPatchClient, adoOrg, adoProject, adoWorkItemType, flaw, {
                    source_base_path_1,
                    source_base_path_2,
                    source_base_path_3,
                    commit_hash,
                    debug,
                    scanType: 'pipeline',
                    adoOpenState
                });

                console.log(`Successfully created work item ${workItem.id} for flaw ${flawId}`);
                createdCount++;
            }

            // Wait between API calls to avoid rate limiting
            await new Promise(resolve => setTimeout(resolve, waitTime * 1000));
        } catch (error) {
            if (debug === 'true') {
                console.error('Detailed error information for pipeline flaw:');
                console.error('Error message:', error.message);
                if (error.response) {
                    console.error('Response status:', error.response.status);
                    console.error('Response data:', error.response.data);
                }
            }
            core.error(`Failed to process pipeline work item for flaw ${flaw.issue_id}: ${error.message}`);
            if (fail_build === 'true') {
                throw error;
            }
        }
    }
    
    return { createdCount, reopenedCount, skippedCount };
}

// ADO-specific policy flaws processing
async function processPolicyFlawsADO(adoPatchClient, adoOrg, adoProject, adoWorkItemType, flawData, params) {
    const { source_base_path_1, source_base_path_2, source_base_path_3, commit_hash, waitTime, fail_build, debug, existingWorkItems, processedFlawIds, duplicateDetectionData, adoOpenState, adoReopenState } = params;
    
    let createdCount = 0;
    let reopenedCount = 0;
    let skippedCount = 0;
    let closedCount = 0;
    
    const flaws = flawData._embedded?.findings || [];
    console.log(`Processing ${flaws.length} policy flaws for ADO`);
    
    for (const flaw of flaws) {
        try {
            const flawId = flaw.issue_id || 'Unknown';
            const cweId = flaw.finding_details?.cwe?.id || 'Unknown';
            const cweName = flaw.finding_details?.cwe?.name || 'Unknown';
            const annotations = flaw.annotations || [];
            const flawStatus = flaw.finding_status?.status
            const flawResolution = flaw.finding_status?.resolution
            
            // Create a unique identifier for the flaw
            const veracodeFlawId = createVeracodeFlawId(flaw, 'policy');
            
            // Track this flaw as processed
            processedFlawIds.add(veracodeFlawId);
            
            if (debug === 'true') {
                console.log(`Processing policy flaw ${flawId} with Veracode ID: ${veracodeFlawId}`);
            }
            
            // Check if work item already exists using policy-specific exact matching
            const existingWorkItem = policyIssueExists(flaw, duplicateDetectionData);
            
            if (existingWorkItem) {
                const workItemState = existingWorkItem.workItemState;
                const workItemId = existingWorkItem.workItemId;
                console.log(`✅ DEDUPLICATION: Work item already exists for policy flaw ${flawId} (ID: ${workItemId}, State: ${workItemState})`);
                
                if (workItemState === 'Closed' || workItemState === 'Resolved') {
                    console.log(`Reopening closed work item ${workItemId} for flaw ${flawId}`);
                    await reopenWorkItem(adoPatchClient, adoOrg, adoProject, workItemId, {
                        source_base_path_1,
                        source_base_path_2,
                        source_base_path_3,
                        commit_hash,
                        debug,
                        adoReopenState
                    });
                    reopenedCount++;
                } else {
                    console.log(`Work item ${workItemId} is already open (State: ${workItemState}), skipping creation`);
                    skippedCount++;

                }
            } else {
                // Create new work item
                console.log(`Creating new work item for policy flaw ${flawId} (Veracode ID: ${veracodeFlawId})`);
                const workItem = await createWorkItem(adoPatchClient, adoOrg, adoProject, adoWorkItemType, flaw, {
                    source_base_path_1,
                    source_base_path_2,
                    source_base_path_3,
                    commit_hash,
                    debug,
                    scanType: 'policy',
                    adoOpenState
                });

                console.log(`Successfully created work item ${workItem.id} for flaw ${flawId}`);
                createdCount++;
            }

            // Wait between API calls to avoid rate limiting
            await new Promise(resolve => setTimeout(resolve, waitTime * 1000));
        } catch (error) {
            if (debug === 'true') {
                console.error('Detailed error information for policy flaw:');
                console.error('Error message:', error.message);
                if (error.response) {
                    console.error('Response status:', error.response.status);
                    console.error('Response data:', error.response.data);
                }
            }
            core.error(`Failed to process policy work item for flaw ${flaw.issue_id}: ${error.message}`);
            if (fail_build === 'true') {
                throw error;
            }
        }
    }
    
    // Process mitigation status and annotations for existing work items
    console.log(`\nProcessing mitigation status and annotations...`);
    for (const flaw of flaws) {
        try {
            const flawId = flaw.issue_id || 'Unknown';
            const annotations = flaw.annotations || [];
            const resolutionStatus = flaw.finding_status?.resolution_status;
            
            // Find existing work item for this flaw
            const existingWorkItem = policyIssueExists(flaw, duplicateDetectionData);
            
            if (existingWorkItem) {
                const workItemState = existingWorkItem.workItemState;
                const workItemId = existingWorkItem.workItemId;
                
                // Process annotations to determine action (same logic as GitHub)
                const annotationResult = processAnnotationsADO(annotations);
                
                // Check if flaw is mitigated (APPROVED status) - same logic as GitHub
                if (resolutionStatus === 'APPROVED') {
                    if (workItemState !== 'Closed' && workItemState !== 'Resolved' && workItemState !== 'Done') {
                        console.log(`Closing work item ${workItemId} for flaw ${flawId} - finding has been mitigated (APPROVED status)`);
                        await closeWorkItem(adoPatchClient, adoOrg, adoProject, workItemId, 'MITIGATED', commit_hash, debug, adoCloseState);
                        closedCount++;
                        
                        // Wait between API calls to avoid rate limiting
                        await new Promise(resolve => setTimeout(resolve, waitTime * 1000));
                    }
                } else {
                    // Flaw is NOT mitigated - check if work item should be reopened
                    const isWorkItemClosed = workItemState === 'Closed' || workItemState === 'Resolved' || workItemState === 'Done';
                    
                    if (isWorkItemClosed) {
                        console.log(`Reopening work item ${workItemId} for flaw ${flawId} - flaw is not mitigated but work item is closed`);
                        
                        try {
                            await reopenWorkItem(adoPatchClient, adoOrg, adoProject, workItemId, {
                                source_base_path_1,
                                source_base_path_2,
                                source_base_path_3,
                                commit_hash,
                                debug,
                        adoReopenState
                            });
                            reopenedCount++;
                            console.log(`✅ Successfully reopened work item ${workItemId} for flaw ${flawId} (not mitigated)`);
                            
                            // Wait between API calls to avoid rate limiting
                            await new Promise(resolve => setTimeout(resolve, waitTime * 1000));
                        } catch (reopenError) {
                            console.error(`❌ Failed to reopen work item ${workItemId} for flaw ${flawId}:`, reopenError.message);
                            if (debug === 'true') {
                                console.error('Reopen error details:', reopenError);
                            }
                        }
                    }
                }
                
                // Handle annotation-based actions (reopen if rejected)
                if (annotationResult.action === 'reopen') {
                    console.log(`Reopening work item ${workItemId} for flaw ${flawId} - most recent annotation is REJECTED`);
                    
                    // Reopen the work item if it's closed
                    if (workItemState === 'Closed' || workItemState === 'Resolved' || workItemState === 'Done') {
                        try {
                            await reopenWorkItem(adoPatchClient, adoOrg, adoProject, workItemId, {
                                source_base_path_1,
                                source_base_path_2,
                                source_base_path_3,
                                commit_hash,
                                debug,
                        adoReopenState
                            });
                            reopenedCount++;
                            console.log(`✅ Successfully reopened work item ${workItemId} for flaw ${flawId}`);
                            
                            // Wait between API calls to avoid rate limiting
                            await new Promise(resolve => setTimeout(resolve, waitTime * 1000));
                        } catch (reopenError) {
                            console.error(`❌ Failed to reopen work item ${workItemId} for flaw ${flawId}:`, reopenError.message);
                            if (debug === 'true') {
                                console.error('Reopen error details:', reopenError);
                            }
                        }
                    } else {
                        console.log(`Work item ${workItemId} is already open (State: ${workItemState}), no need to reopen`);
                    }
                }
                
                // Update work item with mitigation annotations (if any)
                if (annotations.length > 0) {
                    console.log(`Updating work item ${workItemId} with ${annotations.length} mitigation annotations`);
                    await updateWorkItem(adoPatchClient, adoOrg, adoProject, workItemId, annotations, {
                        commit_hash,
                        debug,
                        workItemType: adoWorkItemType
                    });
                }
            }
        } catch (error) {
            if (debug === 'true') {
                console.error(`Error processing mitigation status for flaw ${flaw.issue_id}:`, error.message);
            }
        }
    }
    
    return { createdCount, reopenedCount, skippedCount, closedCount };
}

module.exports = {
    importFlawsToADO
}; 