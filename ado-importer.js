const core = require('@actions/core');
const axios = require('axios');
const fs = require('fs');

async function importFlawsToADO(params) {
    const {
        resultsFile,
        scaFile,
        includeSCA,
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
        autoCloseFindings,
        sandboxName
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
            flaws = flawData._embedded.findings || [];
            if (flaws.length > 0) {
                console.log(`Flaws found to import! (${flaws.length} static findings)`);
            }
        } else {
            console.log('No flaws found to import!');
            flaws = [];
        }
    }

    if (flaws.length === 0) {
        console.log('No static flaws found to import!');
        // Don't return early - SCA findings may still need to be processed
        if (!includeSCA || !scaFile || !fs.existsSync(scaFile)) {
            console.log('No SCA findings to process either. Exiting.');
            return;
        }
        console.log('Continuing to process SCA findings...');
    } else {
        console.log(`Importing ${scanType} flaws into Azure DevOps. ${waitTime} seconds between imports (to handle rate limiting)`);
    }

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

    // Only process static flaws if there are any
    if (flaws.length > 0) {
        if (scanType === 'pipeline') {
        const result = await processPipelineFlawsADO(adoPatchClient, adoQueryClient, adoClient, adoOrg, adoProject, adoWorkItemType, flawData, {
            source_base_path_1,
            source_base_path_2,
            source_base_path_3,
            commit_hash,
            waitTime,
            fail_build,
            debug,
            existingWorkItems,
            processedFlawIds,
            duplicateDetectionData,
            adoOpenState,
            adoCloseState,
            adoReopenState,
            scanType: 'pipeline',
            sandboxName: sandboxName
        });
        createdCount = result.createdCount;
        reopenedCount = result.reopenedCount;
        skippedCount = result.skippedCount;
        closedCount = closePipelineFlaws(adoClient, adoOrg, adoProject, activeWorkItems, result.processedFlawIds, commit_hash, debug, adoCloseState)
    } else {
        const result = await processPolicyFlawsADO(adoPatchClient, adoQueryClient, adoClient, adoOrg, adoProject, adoWorkItemType, flawData, {
            source_base_path_1,
            source_base_path_2,
            source_base_path_3,
            commit_hash,
            waitTime,
            fail_build,
            debug,
            existingWorkItems,
            processedFlawIds,
            duplicateDetectionData,
            adoOpenState,
            adoCloseState,
            adoReopenState,
            scanType: 'policy',
            sandboxName: sandboxName
        });
        createdCount = result.createdCount;
        reopenedCount = result.reopenedCount;
        skippedCount = result.skippedCount;
        closedCount = result.closedCount;
        }
    } else {
        console.log('Skipping static flaws processing (no flaws found).');
    }

    // Process SCA findings if requested
    if (includeSCA && scaFile && fs.existsSync(scaFile)) {
        console.log('\n=== Processing SCA Findings ===');
        const scaData = JSON.parse(fs.readFileSync(scaFile, 'utf8'));
        const scaResult = await processSCAFindingsADO(adoPatchClient, adoQueryClient, adoClient, adoOrg, adoProject, adoWorkItemType, scaData, {
            source_base_path_1,
            source_base_path_2,
            source_base_path_3,
            commit_hash,
            waitTime,
            fail_build,
            debug,
            existingWorkItems,
            processedFlawIds,
            duplicateDetectionData,
            adoOpenState,
            adoCloseState,
            adoReopenState,
            sandboxName: sandboxName,
            autoCloseFindings: autoCloseFindings
        });
        createdCount += scaResult.createdCount;
        reopenedCount += scaResult.reopenedCount;
        skippedCount += scaResult.skippedCount;
        closedCount += scaResult.closedCount;
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
        // Handle both static scan (contains "flaw") and SCA (contains "SCA")
        if (title.toLowerCase().includes('veracode')) {
            if (title.toLowerCase().includes('sca')) {
                // For SCA findings, check if CVE and component match
                return coreParts.every(part => 
                    title.toLowerCase().includes(part.toLowerCase())
                );
            } else if (title.toLowerCase().includes('flaw')) {
                // For static scan findings
                return coreParts.every(part => 
                    title.toLowerCase().includes(part.toLowerCase())
                );
            }
        }
        
        return false;
    });
}

function extractCoreFlawParts(veracodeFlawId) {
    // Extract the key identifying parts from the flaw ID
    // Handle both static scan format [VID:flawNumber] and SCA format Veracode SCA: CVE-NAME - COMPONENT
    if (veracodeFlawId.startsWith('Veracode SCA:')) {
        // For SCA: extract CVE name and component filename
        const parts = veracodeFlawId.replace('Veracode SCA:', '').trim().split(' - ');
        return parts.filter(part => part && part !== 'Unknown');
    } else {
        // For static scans: Remove the [VID:] wrapper and split by colons
        const cleanId = veracodeFlawId.replace(/^\[VID:/, '').replace(/\]$/, '');
        return cleanId.split(':').filter(part => part && part !== 'Unknown');
    }
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
        // Check if TSRV fields contain meaningful data (not all "Unknown")
        const hasTSRVData = technique !== 'Unknown' || specifics !== 'Unknown' || remaining_risk !== 'Unknown' || verification !== 'Unknown';
        
        if (hasTSRVData) {
            // Use TSRV format when we have meaningful data
            mitigation += "<b>Technique:</b> " + technique + "<br/>";
            mitigation += "<b>Specifics:</b> " + specifics + "<br>";
            mitigation += "<b>Remaining Risk:</b> " + remaining_risk + "<br>";
            mitigation += "<b>Verification:</b> " + verification + "<br>";
        } else {
            // Fall back to comment format when TSRV data is not available
            mitigation += "<b>Comment:</b> " + comment + "<br>";
        }
    } else {
        mitigation += "<b>Comment:</b> " + comment + "<br>";
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

// Normalize HTML/text for robust duplicate detection
function normalizeTextForCompare(text) {
    if (!text) return '';
    try {
        const noHtml = String(text).replace(/<[^>]*>/g, ' ');
        return noHtml.replace(/\s+/g, ' ').trim().toLowerCase();
    } catch (_) {
        return String(text).toLowerCase();
    }
}

// Fetch all previous System.History additions for a work item via Updates API
async function fetchWorkItemHistoryEntries(adoClient, adoOrg, adoProject, workItemId, debug) {
    const pageSize = 200;
    let skip = 0;
    let allHistory = [];
    while (true) {
        const updatesUrl = `/${adoOrg}/${adoProject}/_apis/wit/workItems/${workItemId}/updates?$top=${pageSize}&$skip=${skip}&api-version=7.0`;
        if (debug === 'true') {
            console.log(`Fetching work item updates: ${updatesUrl}`);
        }
        const res = await adoClient.get(updatesUrl);
        const values = res.data?.value || [];
        for (const upd of values) {
            const fields = upd.fields || {};
            const hist = fields['System.History'];
            // Can appear as { newValue: 'text', oldValue: '...' } or direct string in some templates
            if (hist) {
                if (typeof hist === 'string') {
                    allHistory.push(hist);
                } else if (typeof hist.newValue === 'string') {
                    allHistory.push(hist.newValue);
                }
            }
        }
        if (values.length < pageSize) break;
        skip += pageSize;
    }
    return allHistory;
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
        // Use Updates API to gather all existing discussion entries to avoid duplicates reliably
        const historyEntries = await fetchWorkItemHistoryEntries(adoClient, adoOrg, adoProject, workItemId, debug);
        const existingSet = new Set(historyEntries.map(normalizeTextForCompare));
        const workItemUrl = `/${adoOrg}/${adoProject}/_apis/wit/workitems/${workItemId}?api-version=7.0`;

        for (const annot of sorted_annotations) {
            const { mitigation_title, mitigation } = formatMitigation(annot);
            const key = normalizeTextForCompare(mitigation);
            if (!existingSet.has(key)) {
                const payload = [
                    {
                        op: 'add',
                        path: '/fields/System.History',
                        value: mitigation
                    }
                ];
                try {
                    await adoClient.patch(workItemUrl, payload, {
                        headers: {
                            'Content-Type': 'application/json-patch+json'
                        }
                    });
                    existingSet.add(key);
                    if (debug === 'true') {
                        console.log(`Added mitigation "${mitigation_title}" to Bug work item ${workItemId} Discussion field`);
                    }
                } catch (error) {
                    console.error(`Failed to add mitigation "${mitigation_title}" to Bug work item ${workItemId}:`, error.message);
                }
            } else if (debug === 'true') {
                console.log(`Skipping duplicate mitigation "${mitigation_title}" found in Bug work item ${workItemId} Discussion`);
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
    const { source_base_path_1, source_base_path_2, source_base_path_3, commit_hash, debug, adoReopenState, sandboxName, reopenComment } = params;
    
    const url = `/${adoOrg}/${adoProject}/_apis/wit/workitems/${workItemId}?api-version=7.0`;
    
    // Use provided reopenComment or default message
    const expectedComment = reopenComment || `Reopened by Veracode scan - Commit: ${commit_hash || 'Unknown'}`;
    let existingReopenComment = false;
    try {
        const historyEntries = await fetchWorkItemHistoryEntries(adoClient, adoOrg, adoProject, workItemId, debug);
        const existingSet = new Set(historyEntries.map(normalizeTextForCompare));
        existingReopenComment = existingSet.has(normalizeTextForCompare(expectedComment));
    } catch (error) {
        console.error(`Failed to check existing history for work item ${workItemId}:`, error.message);
    }
    
    // Get current tags to preserve them and add sandbox tag if needed
    let currentTags = '';
    let sandboxTagToAdd = '';
    if (sandboxName) {
        sandboxTagToAdd = `sandbox-${sandboxName}`;
        try {
            // Fetch current work item to get existing tags
            const workItemUrl = `/${adoOrg}/${adoProject}/_apis/wit/workitems/${workItemId}?$expand=all&api-version=7.0`;
            const workItemResponse = await adoClient.get(workItemUrl);
            currentTags = workItemResponse.data.fields['System.Tags'] || '';
            
            // Check if sandbox tag already exists
            if (currentTags && currentTags.includes(sandboxTagToAdd)) {
                sandboxTagToAdd = ''; // Already has the tag, no need to add
            } else if (currentTags) {
                // Append sandbox tag to existing tags
                currentTags += `;${sandboxTagToAdd}`;
            } else {
                // No existing tags, just use sandbox tag
                currentTags = sandboxTagToAdd;
            }
        } catch (error) {
            console.warn(`Failed to fetch current tags for work item ${workItemId}, will add sandbox tag anyway:`, error.message);
            currentTags = sandboxTagToAdd;
        }
    }
    
    // Use configurable reopen state, with fallback to common states
    const candidateStates = adoReopenState ? [adoReopenState] : ['To Do', 'Active', 'New', 'Open'];
    
    for (const state of candidateStates) {
        const payload = existingReopenComment ? [
            {
                op: 'replace',
                path: '/fields/System.State',
                value: state
            }
        ] : [
            {
                op: 'replace',
                path: '/fields/System.State',
                value: state
            },
            {
                op: 'add',
                path: '/fields/System.History',
                value: expectedComment
            }
        ];
        
        // Add sandbox tag if needed
        if (sandboxTagToAdd && currentTags) {
            payload.push({
                op: 'replace',
                path: '/fields/System.Tags',
                value: currentTags
            });
        }

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
    const { source_base_path_1, source_base_path_2, source_base_path_3, commit_hash, debug, scanType, adoOpenState, sandboxName } = params;

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
    let tags = cweTag ? `Veracode;Security;${cweTag}` : 'Veracode;Security';
    
    // Add sandbox tag if sandbox name is provided
    if (sandboxName) {
        tags += `;sandbox-${sandboxName}`;
    }
    
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

    // Check if closure comment already exists to avoid duplicates using Updates API
    let existingCloseComment = false;
    try {
        const historyEntries = await fetchWorkItemHistoryEntries(adoClient, adoOrg, adoProject, workItemId, debug);
        const existingSet = new Set(historyEntries.map(normalizeTextForCompare));
        existingCloseComment = existingSet.has(normalizeTextForCompare(closureMessage));
    } catch (error) {
        console.error(`Failed to check existing history for work item ${workItemId}:`, error.message);
    }

    // Use configurable close state, with fallback to common states
    const candidateStates = adoCloseState ? [adoCloseState] : ['Done', 'Closed', 'Resolved', 'Completed'];

    for (const state of candidateStates) {
        const payload = existingCloseComment ? [
            {
                op: 'replace',
                path: '/fields/System.State',
                value: state
            }
        ] : [
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

async function closePipelineFlaws(adoClient, adoOrg, adoProject, activeWorkItems, processedFlawIds, commit_hash, debug, adoCloseState){
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
    
    // Find the most recent APPROVED/APPROVE or REJECTED/REJECT annotation (these take precedence)
    const mostRecentApprovedOrRejected = sortedAnnotations.find(ann => {
        const action = ann.action.toUpperCase();
        return action === 'APPROVED' || action === 'APPROVE' || action === 'REJECTED' || action === 'REJECT';
    });
    
    // If we have an APPROVED/APPROVE or REJECTED/REJECT annotation, use it to determine the action
    if (mostRecentApprovedOrRejected) {
        const action = mostRecentApprovedOrRejected.action.toUpperCase();
        if (action === 'APPROVED' || action === 'APPROVE') {
            return { 
                action: 'close', 
                annotations: sortedAnnotations,
                mostRecent: mostRecentApprovedOrRejected
            };
        } else if (action === 'REJECTED' || action === 'REJECT') {
            return { 
                action: 'reopen', 
                annotations: sortedAnnotations,
                mostRecent: mostRecentApprovedOrRejected
            };
        }
    }
    
    // If no APPROVED/APPROVE or REJECTED/REJECT annotations, use the most recent annotation for update
    const mostRecent = sortedAnnotations[0];
    return { 
        action: 'update', 
        annotations: sortedAnnotations,
        mostRecent: mostRecent
    };
}

// ADO-specific pipeline flaws processing
async function processPipelineFlawsADO(adoPatchClient, adoQueryClient, adoClient, adoOrg, adoProject, adoWorkItemType, flawData, params) {
    const { source_base_path_1, source_base_path_2, source_base_path_3, commit_hash, waitTime, fail_build, debug, existingWorkItems, processedFlawIds, duplicateDetectionData, adoOpenState, adoCloseState, adoReopenState, scanType, sandboxName } = params;
    
    // Local references that can be updated
    let currentExistingWorkItems = existingWorkItems;
    let currentDuplicateDetectionData = duplicateDetectionData;
    
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
            const existingWorkItem = pipelineIssueExists(flaw, currentDuplicateDetectionData, debug);
            
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
                        adoReopenState,
                        sandboxName
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
                    adoOpenState,
                    sandboxName
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
async function processPolicyFlawsADO(adoPatchClient, adoQueryClient, adoClient, adoOrg, adoProject, adoWorkItemType, flawData, params) {
    const { source_base_path_1, source_base_path_2, source_base_path_3, commit_hash, waitTime, fail_build, debug, existingWorkItems, processedFlawIds, duplicateDetectionData, adoOpenState, adoCloseState, adoReopenState, scanType, sandboxName } = params;
    
    // Local references that can be updated
    let currentExistingWorkItems = existingWorkItems;
    let currentDuplicateDetectionData = duplicateDetectionData;
    
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
            const existingWorkItem = policyIssueExists(flaw, currentDuplicateDetectionData);
            
            if (existingWorkItem) {
                const workItemState = existingWorkItem.workItemState;
                const workItemId = existingWorkItem.workItemId;
                console.log(`✅ DEDUPLICATION: Work item already exists for policy flaw ${flawId} (ID: ${workItemId}, State: ${workItemState})`);

                // Guard: do NOT reopen if the flaw is mitigated (APPROVED) even if the work item is closed.
                const resolutionStatusEarly = flaw.finding_status?.resolution_status;
                const isClosedState = workItemState === 'Closed' || workItemState === 'Resolved' || workItemState === 'Done';
                const shouldReopen = isClosedState && resolutionStatusEarly !== 'APPROVED';

                if (shouldReopen) {
                    console.log(`Reopening closed work item ${workItemId} for flaw ${flawId}`);
                    await reopenWorkItem(adoPatchClient, adoOrg, adoProject, workItemId, {
                        source_base_path_1,
                        source_base_path_2,
                        source_base_path_3,
                        commit_hash,
                        debug,
                        adoReopenState,
                        sandboxName
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
                    adoOpenState,
                    sandboxName
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
    
    // Refresh existing work items and duplicate detection data if new work items were created
    // This ensures newly created work items are included in mitigation processing
    if (createdCount > 0) {
        console.log(`\nRefreshing existing work items list (${createdCount} new work item(s) created)...`);
        try {
            currentExistingWorkItems = await getExistingWorkItems(adoQueryClient, adoClient, adoOrg, adoProject, debug);
            console.log(`Found ${currentExistingWorkItems.length} existing work items after refresh`);
            
            // Re-initialize duplicate detection data structure
            currentDuplicateDetectionData = {
                existingFlaws: {}, // flawNumber -> true
                existingFlawNumbers: {}, // flawNumber -> workItemId
                existingIssueStates: {} // flawNumber -> workItemState
            };
            
            // Re-populate duplicate detection data with refreshed work items
            populateDuplicateDetectionData(currentExistingWorkItems, currentDuplicateDetectionData, scanType, debug);
            
            if (debug === 'true') {
                console.log('Duplicate detection data refreshed with newly created work items');
            }
        } catch (error) {
            console.error(`Failed to refresh existing work items: ${error.message}`);
            if (debug === 'true') {
                console.error('Continuing with original data, but newly created work items may not be processed for mitigations');
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
            
            // Find existing work item for this flaw (using refreshed data)
            const existingWorkItem = policyIssueExists(flaw, currentDuplicateDetectionData);
            
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

/**
 * Create a unique Veracode SCA finding ID for ADO
 */
function createSCAFindingID(finding) {
    const cveName = finding.finding_details?.cve?.name || 'Unknown';
    const componentFilename = finding.finding_details?.component_filename || 'Unknown';
    return `Veracode SCA: ${cveName} - ${componentFilename}`;
}

/**
 * Format SCA finding description for ADO
 */
function formatSCADescriptionHTML(finding) {
    const componentFilename = finding.finding_details?.component_filename || 'Unknown';
    const cveName = finding.finding_details?.cve?.name || 'Unknown';
    const description = finding.description || 'No description available';
    const cvss = finding.finding_details?.cve?.cvss || 'N/A';
    const severity = finding.finding_details?.cve?.severity || 'Unknown';
    const cveHref = finding.finding_details?.cve?.href;
    const exploitability = finding.finding_details?.cve?.exploitability;
    const licenses = finding.finding_details?.licenses || [];

    let desc = `<b>${componentFilename} - ${cveName}</b><br><br>`;
    desc += `${description}<br><br>`;
    desc += `<b>CVSS Score:</b> ${cvss} - ${severity}<br><br>`;

    // Add EPSS information if available
    if (exploitability?.epss_percentile !== undefined && exploitability?.epss_score !== undefined) {
        desc += `<b>EPSS Percentile:</b> ${exploitability.epss_percentile}<br>`;
        desc += `<b>EPSS Score:</b> ${exploitability.epss_score}<br><br>`;
    }

    // Add CVE link if available
    if (cveHref) {
        desc += `<b>CVE Link:</b> <a href="${cveHref}">${cveHref}</a><br><br>`;
    }

    // Add license information if available
    if (licenses.length > 0) {
        const licenseIds = licenses.map(l => l.license_id).filter(Boolean);
        if (licenseIds.length > 0) {
            desc += `<b>License:</b> ${licenseIds.join(', ')}<br><br>`;
        }
    }

    return desc;
}

/**
 * Map CVE severity to ADO severity
 */
function mapSCASeverity(cveSeverity) {
    const severityMap = {
        'Very High': '1 - Critical',
        'High': '2 - High',
        'Medium': '3 - Medium',
        'Low': '4 - Low',
        'Very Low': '5 - Low',
        'Informational': '5 - Low'
    };
    return severityMap[cveSeverity] || '3 - Medium';
}

/**
 * Process SCA findings for ADO
 */
async function processSCAFindingsADO(adoPatchClient, adoQueryClient, adoClient, adoOrg, adoProject, adoWorkItemType, scaData, params) {
    const { source_base_path_1, source_base_path_2, source_base_path_3, commit_hash, waitTime, fail_build, debug, existingWorkItems, processedFlawIds, duplicateDetectionData, adoOpenState, adoCloseState, adoReopenState, sandboxName } = params;
    
    let createdCount = 0;
    let reopenedCount = 0;
    let skippedCount = 0;
    let closedCount = 0;
    
    if (!scaData._embedded || !scaData._embedded.findings) {
        console.log('No SCA findings found in input data');
        return { createdCount, reopenedCount, skippedCount, closedCount };
    }
    
    const findings = scaData._embedded.findings;
    console.log(`Processing ${findings.length} SCA findings for ADO`);
    
    for (const finding of findings) {
        try {
            const veracodeFlawId = createSCAFindingID(finding);
            const findingStatus = finding.finding_status?.status || 'UNKNOWN';
            const resolutionStatus = finding.finding_status?.resolution_status || 'NONE';
            const violatesPolicy = finding.violates_policy === true;
            
            // Track this finding as processed (regardless of status)
            processedFlawIds.add(veracodeFlawId);
            
            if (debug === 'true') {
                console.log(`Processing SCA finding with Veracode ID: ${veracodeFlawId} (Status: ${findingStatus}, Resolution Status: ${resolutionStatus}, Violates Policy: ${violatesPolicy})`);
            }
            
            // Check if work item already exists
            const existingWorkItem = findExistingWorkItem(existingWorkItems, veracodeFlawId);
            
            if (existingWorkItem) {
                const workItemState = existingWorkItem.fields['System.State'] || 'Unknown';
                const workItemId = existingWorkItem.id;
                const isClosedState = workItemState === 'Closed' || workItemState === 'Resolved' || workItemState === 'Done';
                const isOpenState = !isClosedState;
                
                console.log(`Work item already exists for SCA finding (ID: ${workItemId}, State: ${workItemState}, Finding Status: ${findingStatus}, Resolution Status: ${resolutionStatus})`);
                
                // Handle annotations if present
                if (finding.annotations && finding.annotations.length > 0) {
                    console.log(`Processing annotations for SCA finding ${veracodeFlawId}: ${finding.annotations.length} annotations`);
                    await updateWorkItem(adoClient, adoOrg, adoProject, workItemId, finding.annotations, {
                        workItemType: adoWorkItemType,
                        debug
                    });
                    
                    // Process annotations to determine action
                    const annotationResult = processAnnotationsADO(finding.annotations);
                    if (annotationResult.action === 'close' && isOpenState) {
                        console.log(`Closing work item ${workItemId} for SCA finding - most recent annotation is APPROVED`);
                        const closeUrl = `/${adoOrg}/${adoProject}/_apis/wit/workitems/${workItemId}?api-version=7.0`;
                        const closePayload = [
                            {
                                op: 'replace',
                                path: '/fields/System.State',
                                value: adoCloseState || 'Done'
                            }
                        ];
                        
                        await adoPatchClient.patch(closeUrl, closePayload, {
                            headers: {
                                'Content-Type': 'application/json-patch+json'
                            }
                        });
                    } else if (annotationResult.action === 'reopen' && isClosedState) {
                        // If most recent annotation is REJECTED, reopen the work item
                        console.log(`Reopening work item ${workItemId} for SCA finding - most recent annotation is REJECTED`);
                        const reopenComment = `The finding has been rejected on the Veracode platform`;
                        await reopenWorkItem(adoPatchClient, adoOrg, adoProject, workItemId, {
                            source_base_path_1,
                            source_base_path_2,
                            source_base_path_3,
                            commit_hash,
                            debug,
                            adoReopenState,
                            sandboxName,
                            reopenComment: reopenComment
                        });
                        
                        // Wait between API calls to avoid rate limiting
                        await new Promise(resolve => setTimeout(resolve, waitTime * 1000));
                    }
                }
                
                // Also check resolution_status for REJECTED (in case there are no annotations or annotations haven't been processed yet)
                // Get current work item state after annotation processing
                let currentWorkItemState = workItemState;
                if (finding.annotations && finding.annotations.length > 0) {
                    try {
                        const currentWorkItem = await adoClient.get(`/${adoOrg}/${adoProject}/_apis/wit/workitems/${workItemId}?api-version=7.0`);
                        currentWorkItemState = currentWorkItem.data.fields['System.State'] || workItemState;
                    } catch (error) {
                        console.warn(`Failed to fetch current work item state: ${error.message}`);
                    }
                }
                
                const isCurrentlyClosed = currentWorkItemState === 'Closed' || currentWorkItemState === 'Resolved' || currentWorkItemState === 'Done';
                const isCurrentlyOpen = !isCurrentlyClosed;
                
                // Handle REJECTED resolution_status - ensure work item is open
                if (resolutionStatus === 'REJECTED') {
                    if (isCurrentlyClosed) {
                        console.log(`Reopening work item ${workItemId} for SCA finding - resolution_status is REJECTED`);
                        const reopenComment = `The finding has been rejected on the Veracode platform`;
                        await reopenWorkItem(adoPatchClient, adoOrg, adoProject, workItemId, {
                            source_base_path_1,
                            source_base_path_2,
                            source_base_path_3,
                            commit_hash,
                            debug,
                            adoReopenState,
                            sandboxName,
                            reopenComment: reopenComment
                        });
                        
                        // Wait between API calls to avoid rate limiting
                        await new Promise(resolve => setTimeout(resolve, waitTime * 1000));
                    } else {
                        // Work item is already open, which is correct for REJECTED status
                        console.log(`Work item ${workItemId} is already open - correct state for REJECTED resolution_status`);
                    }
                    // Skip further status synchronization when resolution_status is REJECTED
                    continue;
                }
                
                // Synchronize work item state with finding status
                if (findingStatus === 'CLOSED' && isOpenState) {
                    // Finding is closed on Veracode platform, but work item is open - close it
                    console.log(`Closing open work item ${workItemId} for SCA finding - finding is CLOSED on Veracode platform`);
                    const closeUrl = `/${adoOrg}/${adoProject}/_apis/wit/workitems/${workItemId}?api-version=7.0`;
                    const closePayload = [
                        {
                            op: 'replace',
                            path: '/fields/System.State',
                            value: adoCloseState || 'Done'
                        }
                    ];
                    
                    // Only add generic comment if no annotations were processed
                    if (!finding.annotations || finding.annotations.length === 0) {
                        closePayload.push({
                            op: 'add',
                            path: '/fields/System.History',
                            value: 'Issue closed through Veracode Platform mitigation'
                        });
                    }
                    
                    await adoPatchClient.patch(closeUrl, closePayload, {
                        headers: {
                            'Content-Type': 'application/json-patch+json'
                        }
                    });
                    
                    closedCount++;
                    
                    // Wait between API calls to avoid rate limiting
                    await new Promise(resolve => setTimeout(resolve, waitTime * 1000));
                } else if (findingStatus === 'OPEN' && violatesPolicy && isClosedState) {
                    // Finding is open on Veracode platform, but work item is closed - reopen it
                    console.log(`Reopening closed work item ${workItemId} for SCA finding - finding is OPEN on Veracode platform`);
                    const reopenComment = `The finding is still open on the Veracode platform for scan ${commit_hash || 'N/A'}`;
                    await reopenWorkItem(adoPatchClient, adoOrg, adoProject, workItemId, {
                        source_base_path_1,
                        source_base_path_2,
                        source_base_path_3,
                        commit_hash,
                        debug,
                        adoReopenState,
                        sandboxName,
                        reopenComment: reopenComment
                    });
                    reopenedCount++;
                    
                    // Wait between API calls to avoid rate limiting
                    await new Promise(resolve => setTimeout(resolve, waitTime * 1000));
                } else if (findingStatus === 'OPEN' && violatesPolicy && isOpenState) {
                    // Finding is open and work item is open - ensure sandbox tag is present if needed
                    if (sandboxName) {
                        const currentWorkItem = await adoClient.get(`/${adoOrg}/${adoProject}/_apis/wit/workitems/${workItemId}?api-version=7.0`);
                        let existingTags = currentWorkItem.data.fields['System.Tags'] || '';
                        let tagsArray = existingTags.split(';').map(tag => tag.trim()).filter(tag => tag !== '');
                        const sandboxTag = `sandbox-${sandboxName}`;
                        
                        if (!tagsArray.some(tag => tag.startsWith('sandbox-'))) {
                            tagsArray.push(sandboxTag);
                            const updateUrl = `/${adoOrg}/${adoProject}/_apis/wit/workitems/${workItemId}?api-version=7.0`;
                            const updatePayload = [
                                {
                                    op: 'replace',
                                    path: '/fields/System.Tags',
                                    value: tagsArray.join(';')
                                }
                            ];
                            
                            await adoPatchClient.patch(updateUrl, updatePayload, {
                                headers: {
                                    'Content-Type': 'application/json-patch+json'
                                }
                            });
                        }
                    }
                    console.log(`Work item ${workItemId} is already open (State: ${workItemState}), skipping creation`);
                    skippedCount++;
                } else {
                    console.log(`Work item ${workItemId} state (${workItemState}) matches finding status (${findingStatus}), no action needed`);
                    skippedCount++;
                }
            } else {
                // Create new work items for findings that are:
                // 1. OPEN and violate policy, OR
                // 2. CLOSED with annotations (to create work item, add comments, and close it)
                const hasAnnotations = finding.annotations && finding.annotations.length > 0;
                const shouldCreateWorkItem = (findingStatus === 'OPEN' && violatesPolicy) || (findingStatus === 'CLOSED' && hasAnnotations);
                
                if (!shouldCreateWorkItem) {
                    if (findingStatus !== 'OPEN') {
                        console.log(`Skipping SCA finding - status is ${findingStatus}, not OPEN and no annotations`);
                    } else {
                        console.log(`Skipping SCA finding - violates_policy is ${violatesPolicy}, not true`);
                    }
                    continue;
                }
                // Create new work item
                const componentFilename = finding.finding_details?.component_filename || 'Unknown';
                const cveName = finding.finding_details?.cve?.name || 'Unknown';
                const title = `Veracode SCA - ${cveName} - ${componentFilename}`;
                const description = formatSCADescriptionHTML(finding);
                const cveSeverity = finding.finding_details?.cve?.severity || 'Medium';
                const severity = mapSCASeverity(cveSeverity);
                
                // Build tags
                let tags = 'Veracode-SCA';
                if (cveName !== 'Unknown') {
                    // Check if cveName already starts with "CVE-" to avoid duplication
                    const cveTag = cveName.startsWith('CVE-') ? cveName : `CVE-${cveName}`;
                    tags += `;${cveTag}`;
                }
                tags += `;${cveSeverity}`;
                
                // Add sandbox tag if sandbox name is provided
                if (sandboxName) {
                    tags += `;sandbox-${sandboxName}`;
                }
                
                // Create work item payload
                const url = `/${adoOrg}/${adoProject}/_apis/wit/workitems/$${adoWorkItemType}?api-version=7.0`;
                let payload;
                
                if (String(adoWorkItemType).toLowerCase() === 'bug') {
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
                            value: severity
                        },
                        {
                            op: 'add',
                            path: '/fields/System.State',
                            value: adoOpenState || 'New'
                        }
                    ];
                } else {
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
                            value: severity
                        },
                        {
                            op: 'add',
                            path: '/fields/System.State',
                            value: adoOpenState || 'To Do'
                        }
                    ];
                }
                
                try {
                    const response = await adoPatchClient.post(url, payload, {
                        headers: {
                            'Content-Type': 'application/json-patch+json'
                        }
                    });
                    
                    const workItemId = response.data.id;
                    console.log(`Successfully created work item ${workItemId} for SCA finding`);
                    
                    // Process annotations if present
                    if (finding.annotations && finding.annotations.length > 0) {
                        console.log(`Processing annotations for new SCA work item ${workItemId}: ${finding.annotations.length} annotations`);
                        await updateWorkItem(adoClient, adoOrg, adoProject, workItemId, finding.annotations, {
                            workItemType: adoWorkItemType,
                            debug
                        });
                        
                        // Process annotations to determine action
                        const annotationResult = processAnnotationsADO(finding.annotations);
                        
                        // If resolution_status is REJECTED, keep work item open (don't close it)
                        if (resolutionStatus === 'REJECTED') {
                            console.log(`Keeping newly created work item ${workItemId} open - resolution_status is REJECTED`);
                        } else if (annotationResult.action === 'close' || findingStatus === 'CLOSED') {
                            // If most recent annotation is APPROVED or finding is CLOSED, close the work item
                            console.log(`Closing newly created work item ${workItemId} - most recent annotation is APPROVED or finding is CLOSED`);
                            const closeUrl = `/${adoOrg}/${adoProject}/_apis/wit/workitems/${workItemId}?api-version=7.0`;
                            const closePayload = [
                                {
                                    op: 'replace',
                                    path: '/fields/System.State',
                                    value: adoCloseState || 'Done'
                                }
                            ];
                            
                            await adoPatchClient.patch(closeUrl, closePayload, {
                                headers: {
                                    'Content-Type': 'application/json-patch+json'
                                }
                            });
                        }
                    } else if (findingStatus === 'CLOSED') {
                        // If finding is CLOSED but has no annotations, close the work item with a generic comment
                        // Unless resolution_status is REJECTED, in which case keep it open
                        if (resolutionStatus === 'REJECTED') {
                            console.log(`Keeping newly created work item ${workItemId} open - resolution_status is REJECTED`);
                        } else {
                            console.log(`Closing newly created work item ${workItemId} - finding is CLOSED`);
                            const closeUrl = `/${adoOrg}/${adoProject}/_apis/wit/workitems/${workItemId}?api-version=7.0`;
                            const closePayload = [
                                {
                                    op: 'replace',
                                    path: '/fields/System.State',
                                    value: adoCloseState || 'Done'
                                },
                                {
                                    op: 'add',
                                    path: '/fields/System.History',
                                    value: 'Issue closed through Veracode Platform mitigation'
                                }
                            ];
                            
                            await adoPatchClient.patch(closeUrl, closePayload, {
                                headers: {
                                    'Content-Type': 'application/json-patch+json'
                                }
                            });
                        }
                    }
                    
                    createdCount++;
                } catch (error) {
                    console.error(`Error creating SCA work item: ${error.message}`);
                    if (error.response) {
                        console.error('Status:', error.response.status);
                        console.error('Data:', error.response.data);
                    }
                    if (fail_build === 'true') {
                        throw error;
                    }
                }
            }
            
            // Wait between API calls to avoid rate limiting
            await new Promise(resolve => setTimeout(resolve, waitTime * 1000));
        } catch (error) {
            if (debug === 'true') {
                console.error('Detailed error information for SCA finding:');
                console.error('Error message:', error.message);
                if (error.response) {
                    console.error('Response status:', error.response.status);
                    console.error('Response data:', error.response.data);
                }
            }
            core.error(`Failed to process SCA finding: ${error.message}`);
            if (fail_build === 'true') {
                throw error;
            }
        }
    }
    
    // Close work items that are no longer present in scan results
    if (params.autoCloseFindings === 'true' || params.autoCloseFindings === true) {
        console.log(`\nChecking for SCA work items to close (findings not found in current scan)...`);
        
        const activeWorkItems = existingWorkItems.filter(wi => {
            const state = wi.fields['System.State'] || 'Unknown';
            const tags = wi.fields['System.Tags'] || '';
            return (state !== 'Done' && state !== 'Resolved' && state !== 'Removed') && tags.includes('Veracode-SCA');
        });
        
        for (const workItem of activeWorkItems) {
            const title = workItem.fields['System.Title'] || '';
            // Extract CVE and component from title
            // Title format: "Veracode SCA - CVE-NAME - COMPONENT-FILENAME [VID-SCA:CVE-NAME:COMPONENT-FILENAME]"
            const titleMatch = title.match(/Veracode SCA - (.+?) - (.+?)(?:\s+\[VID-SCA|$)/);
            if (titleMatch) {
                const cveName = titleMatch[1];
                const componentFilename = titleMatch[2].trim();
                const veracodeFlawId = `Veracode SCA: ${cveName} - ${componentFilename}`;
                
                if (!processedFlawIds.has(veracodeFlawId)) {
                    console.log(`Closing work item ${workItem.id} - SCA finding no longer found in scan: "${title}"`);
                    
                    try {
                        const closeUrl = `/${adoOrg}/${adoProject}/_apis/wit/workitems/${workItem.id}?api-version=7.0`;
                        const closePayload = [
                            {
                                op: 'replace',
                                path: '/fields/System.State',
                                value: adoCloseState || 'Done'
                            },
                            {
                                op: 'add',
                                path: '/fields/System.History',
                                value: `Closed by Veracode automation - SCA finding no longer present in scan results`
                            }
                        ];
                        
                        await adoPatchClient.patch(closeUrl, closePayload, {
                            headers: {
                                'Content-Type': 'application/json-patch+json'
                            }
                        });
                        
                        closedCount++;
                        
                        if (waitTime > 0) {
                            await new Promise(resolve => setTimeout(resolve, waitTime * 1000));
                        }
                    } catch (error) {
                        console.error(`Failed to close work item ${workItem.id}: ${error.message}`);
                    }
                }
            }
        }
        
        if (closedCount > 0) {
            console.log(`Closed ${closedCount} SCA work items that are no longer present in scan results`);
        }
    }
    
    return { createdCount, reopenedCount, skippedCount, closedCount };
}

module.exports = {
    importFlawsToADO,
    processSCAFindingsADO
}; 