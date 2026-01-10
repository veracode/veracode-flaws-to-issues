//
// Veracode HMAC signature generation
// Based on the implementation from veracode/uploadandscan-action
//

const sjcl = require('sjcl');
const crypto = require('crypto');

const authorizationScheme = "VERACODE-HMAC-SHA-256";
const requestVersion = "vcode_request_version_1";
const nonceSize = 16;

function computeHashHex(message, key_hex) {
    let key_bits = sjcl.codec.hex.toBits(key_hex);
    let hmac_bits = (new sjcl.misc.hmac(key_bits, sjcl.hash.sha256)).mac(message);
    let hmac = sjcl.codec.hex.fromBits(hmac_bits);
    return hmac;
}

function calulateDataSignature(apiKeyBytes, nonceBytes, dateStamp, data) {
    let kNonce = computeHashHex(nonceBytes, apiKeyBytes);
    let kDate = computeHashHex(dateStamp, kNonce);
    let kSig = computeHashHex(requestVersion, kDate);
    let kFinal = computeHashHex(data, kSig);
    return kFinal;
}

function newNonce() {
    return crypto.randomBytes(nonceSize).toString('hex').toUpperCase();
}

function toHexBinary(input) {
    return sjcl.codec.hex.fromBits(sjcl.codec.utf8String.toBits(input));
}

/**
 * Calculate Veracode API authorization header
 * @param {string} id - API ID
 * @param {string} key - API Key (base64 encoded, will be converted to hex)
 * @param {string} hostName - Hostname (without port)
 * @param {string} uriString - URI path
 * @param {string} urlQueryParams - Query parameters as string (e.g., "?param1=value1&param2=value2")
 * @param {string} httpMethod - HTTP method (GET, POST, etc.)
 * @returns {string} Authorization header value
 */
function calculateAuthorizationHeader(id, key, hostName, uriString, urlQueryParams, httpMethod) {
    // Append query params to URI string
    uriString += urlQueryParams;
    
    // Build data string: id={id}&host={hostName}&url={uriString}&method={httpMethod}
    let data = `id=${id}&host=${hostName}&url=${uriString}&method=${httpMethod}`;
    
    // Get timestamp
    let dateStamp = Date.now().toString();
    
    // Generate nonce
    let nonceBytes = newNonce();
    
    // Convert API key from base64 to hex (Veracode API keys are base64 encoded)
    let apiKeyHex;
    try {
        // Try to decode from base64 first
        const decodedKey = Buffer.from(key, 'base64');
        apiKeyHex = decodedKey.toString('hex').toUpperCase();
    } catch (e) {
        // If base64 decode fails, assume it's already hex or convert from UTF-8
        try {
            apiKeyHex = Buffer.from(key, 'hex').toString('hex').toUpperCase();
        } catch (e2) {
            // If that fails, convert from UTF-8 to hex
            apiKeyHex = sjcl.codec.hex.fromBits(sjcl.codec.utf8String.toBits(key)).toUpperCase();
        }
    }
    
    // Calculate data signature using the key derivation chain
    let dataSignature = calulateDataSignature(apiKeyHex, nonceBytes, dateStamp, data);
    
    // Build authorization parameter
    let authorizationParam = `id=${id},ts=${dateStamp},nonce=${toHexBinary(nonceBytes)},sig=${dataSignature}`;
    
    // Build full authorization header
    let header = authorizationScheme + " " + authorizationParam;
    
    return header;
}

module.exports = {
    calculateAuthorizationHeader
};

