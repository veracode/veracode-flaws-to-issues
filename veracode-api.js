//
// Veracode API client with HMAC authentication
//

const http = require('http');
const https = require('https');
const { URL } = require('url');
const { calculateAuthorizationHeader } = require('./veracode-hmac');

// Try to use proxy agents if available, otherwise fall back to direct connection
let HttpsProxyAgent, HttpProxyAgent;
try {
    HttpsProxyAgent = require('https-proxy-agent');
    HttpProxyAgent = require('http-proxy-agent');
} catch (e) {
    // Packages not available, will use direct connection
    HttpsProxyAgent = null;
    HttpProxyAgent = null;
}

/**
 * Get proxy configuration from environment variables
 * Respects HTTP_PROXY, HTTPS_PROXY, and NO_PROXY
 */
function getProxyConfig(targetUrl) {
    const urlObj = new URL(targetUrl);
    const isHttps = urlObj.protocol === 'https:';
    
    // Check NO_PROXY
    const noProxy = process.env.NO_PROXY || process.env.no_proxy || '';
    if (noProxy) {
        const noProxyList = noProxy.split(',').map(host => host.trim().toLowerCase());
        const hostname = urlObj.hostname.toLowerCase();
        if (noProxyList.some(proxy => hostname === proxy || hostname.endsWith('.' + proxy))) {
            return null; // Don't use proxy for this host
        }
    }
    
    // Get proxy URL from environment
    const proxyUrl = isHttps 
        ? (process.env.HTTPS_PROXY || process.env.https_proxy || process.env.HTTP_PROXY || process.env.http_proxy)
        : (process.env.HTTP_PROXY || process.env.http_proxy);
    
    if (!proxyUrl) {
        return null;
    }
    
    try {
        const proxy = new URL(proxyUrl);
        return {
            hostname: proxy.hostname,
            port: proxy.port || (proxy.protocol === 'https:' ? 443 : 80),
            protocol: proxy.protocol
        };
    } catch (e) {
        // Invalid proxy URL, ignore
        return null;
    }
}


/**
 * Make an authenticated Veracode API request using Node's built-in http/https
 * This automatically respects HTTP_PROXY, HTTPS_PROXY, and NO_PROXY environment variables
 */
async function veracodeApiRequest(apiKeyId, apiKeySecret, method, url, queryParams = {}) {
    const urlObj = new URL(url);
    // For signature: use only hostname (no port), Veracode API expects just the hostname
    const host = urlObj.hostname;
    const path = urlObj.pathname;
    
    // Build query string for the URL
    const queryString = Object.keys(queryParams)
        .filter(key => queryParams[key] !== undefined && queryParams[key] !== null)
        .map(key => `${encodeURIComponent(key)}=${encodeURIComponent(queryParams[key])}`)
        .join('&');
    
    // Build query string for signature (without encoding, as it goes in the data string)
    const queryStringForSignature = Object.keys(queryParams)
        .filter(key => queryParams[key] !== undefined && queryParams[key] !== null)
        .sort() // Sort alphabetically for signature
        .map(key => `${key}=${queryParams[key]}`)
        .join('&');
    
    // Format query string for signature: add ? prefix if params exist
    const urlQueryParams = queryStringForSignature ? `?${queryStringForSignature}` : '';
    
    // Generate authorization header using the same method as uploadandscan-action
    console.log(`Generating authorization header for: ${host}, ${path}, ${urlQueryParams}, ${method}`);
    const authorization = calculateAuthorizationHeader(apiKeyId, apiKeySecret, host, path, urlQueryParams, method);
    
    const fullPath = queryString ? `${path}?${queryString}` : path;
    
    // Choose http or https module based on protocol
    const httpModule = urlObj.protocol === 'https:' ? https : http;
    const isHttps = urlObj.protocol === 'https:';
    
    // Get proxy configuration
    const proxyConfig = getProxyConfig(url);
    
    return new Promise((resolve, reject) => {
        const options = {
            hostname: urlObj.hostname,
            port: urlObj.port || (isHttps ? 443 : 80),
            path: fullPath,
            method: method,
            headers: {
                'Authorization': authorization,
                'Content-Type': 'application/json',
                'Host': urlObj.host  // Use full host:port for the Host header
            }
        };
        
        // Configure proxy agent if proxy is detected and proxy agent packages are available
        if (proxyConfig) {
            const proxyUrl = `${proxyConfig.protocol}//${proxyConfig.hostname}:${proxyConfig.port}`;
            if (isHttps && HttpsProxyAgent) {
                options.agent = new HttpsProxyAgent(proxyUrl);
            } else if (!isHttps && HttpProxyAgent) {
                options.agent = new HttpProxyAgent(proxyUrl);
            } else if (proxyConfig && (!HttpsProxyAgent || !HttpProxyAgent)) {
                console.warn(`Proxy detected but proxy agent packages not available. Install them for proxy support: npm install https-proxy-agent http-proxy-agent`);
            }
        }
        
        const req = httpModule.request(options, (res) => {
            let data = '';
            
            res.on('data', (chunk) => {
                data += chunk;
            });
            
            res.on('end', () => {
                if (res.statusCode >= 200 && res.statusCode < 300) {
                    try {
                        const jsonData = JSON.parse(data);
                        console.log(`Response: ${JSON.stringify(jsonData)}`);
                        resolve(jsonData);
                    } catch (parseError) {
                        reject(new Error(`Failed to parse JSON response: ${parseError.message}`));
                    }
                } else {
                    let errorMessage = `Veracode API error: ${res.statusCode} ${res.statusMessage}`;
                    try {
                        const errorData = JSON.parse(data);
                        errorMessage += ` - ${JSON.stringify(errorData)}`;
                    } catch (e) {
                        errorMessage += ` - ${data}`;
                    }
                    reject(new Error(errorMessage));
                }
            });
        });
        
        req.on('error', (error) => {
            reject(new Error(`Veracode API request failed: ${error.message}`));
        });
        
        req.end();
    });
}

/**
 * Find application profile by name (exact match)
 */
async function findApplicationProfile(apiKeyId, apiKeySecret, profileName) {
    const url = 'https://api.veracode.com/appsec/v1/applications';
    const response = await veracodeApiRequest(apiKeyId, apiKeySecret, 'GET', url, { name: profileName });
    
    if (!response._embedded || !response._embedded.applications) {
        throw new Error(`No applications found for profile name: ${profileName}`);
    }
    
    // Find exact match
    const exactMatch = response._embedded.applications.find(app => app.profile.name === profileName);
    
    if (!exactMatch) {
        throw new Error(`No exact match found for profile name: ${profileName}. Found ${response._embedded.applications.length} profiles starting with this name.`);
    }
    
    return {
        guid: exactMatch.guid,
        name: exactMatch.profile.name,
        id: exactMatch.id
    };
}

/**
 * Find sandbox by name (exact match)
 */
async function findSandbox(apiKeyId, apiKeySecret, applicationGuid, sandboxName) {
    const url = `https://api.veracode.com/appsec/v1/applications/${applicationGuid}/sandboxes`;
    const response = await veracodeApiRequest(apiKeyId, apiKeySecret, 'GET', url);
    
    if (!response._embedded || !response._embedded.sandboxes) {
        throw new Error(`No sandboxes found for application: ${applicationGuid}`);
    }
    
    // Find exact match
    const exactMatch = response._embedded.sandboxes.find(sandbox => sandbox.name === sandboxName);
    
    if (!exactMatch) {
        throw new Error(`No exact match found for sandbox name: ${sandboxName}. Found ${response._embedded.sandboxes.length} sandboxes.`);
    }
    
    return {
        guid: exactMatch.guid,
        name: exactMatch.name,
        id: exactMatch.id
    };
}

/**
 * Get policy findings for an application
 */
async function getPolicyFindings(apiKeyId, apiKeySecret, applicationGuid, page = 0, size = 20) {
    console.log(`Getting policy findings for application: ${applicationGuid}`);
    const url = `https://api.veracode.com/appsec/v2/applications/${applicationGuid}/findings`;
    const response = await veracodeApiRequest(apiKeyId, apiKeySecret, 'GET', url, {
        scan_type: 'STATIC',
        violates_policy: 'True',
        include_annot: 'TRUE',
        page: page,
        size: size
    });
    
    return response;
}

/**
 * Get sandbox findings
 */
async function getSandboxFindings(apiKeyId, apiKeySecret, applicationGuid, sandboxGuid, page = 0, size = 20) {
    console.log(`Getting sandbox findings for application: ${applicationGuid} and sandbox: ${sandboxGuid}`);
    const url = `https://api.veracode.com/appsec/v2/applications/${applicationGuid}/findings`;
    const response = await veracodeApiRequest(apiKeyId, apiKeySecret, 'GET', url, {
        scan_type: 'STATIC',
        violates_policy: 'True',
        include_annot: 'TRUE',
        context: sandboxGuid,
        page: page,
        size: size
    });
    
    return response;
}

/**
 * Get all findings (handles pagination)
 */
async function getAllFindings(apiKeyId, apiKeySecret, applicationGuid, sandboxGuid = null) {
    const size = 20;
    let page = 0;
    let allFindings = [];
    let totalPages = 1;
    
    do {
        const response = sandboxGuid 
            ? await getSandboxFindings(apiKeyId, apiKeySecret, applicationGuid, sandboxGuid, page, size)
            : await getPolicyFindings(apiKeyId, apiKeySecret, applicationGuid, page, size);
        
        if (page === 0) {
            totalPages = response.page?.total_pages || 1;
        }
        
        if (response._embedded && response._embedded.findings) {
            allFindings = allFindings.concat(response._embedded.findings);
        }
        
        page++;
    } while (page < totalPages);
    
    // Return in the same format as a single page response
    return {
        _embedded: {
            findings: allFindings
        },
        page: {
            size: allFindings.length,
            total_elements: allFindings.length,
            total_pages: 1,
            number: 0
        },
        _links: sandboxGuid ? {} : {}
    };
}

module.exports = {
    findApplicationProfile,
    findSandbox,
    getPolicyFindings,
    getSandboxFindings,
    getAllFindings,
    veracodeApiRequest
};

