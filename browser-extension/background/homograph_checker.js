// ==================== HOMOGRAPH CHECKER ====================
// Lightweight client-side homograph/phishing detection
// Runs instantly, no network calls needed

/**
 * Check a URL for homograph attack indicators.
 * 
 * @param {string} url - The URL to check
 * @returns {Object} - { isSuspicious: bool, riskBoost: number, reasons: string[] }
 */
function checkHomograph(url) {
    const result = {
        isSuspicious: false,
        riskBoost: 0,
        reasons: []
    };

    try {
        const urlObj = new URL(url);
        const hostname = urlObj.hostname.toLowerCase();

        // Check 1: Punycode domain (xn--)
        if (hostname.includes('xn--')) {
            result.riskBoost += 10;
            result.reasons.push('Punycode (xn--) domain detected — may be visually deceptive');
        }

        // Check 2: Mixed Unicode scripts
        if (hasMixedScripts(url)) {
            result.riskBoost += 15;
            result.reasons.push('Mixed Unicode scripts detected — possible visual impersonation');
        }

        // Check 3: HTTPS/HTTP embedded in hostname
        const cleanHostname = hostname.replace(/^www\./, '');
        if (cleanHostname.includes('https') ||
            (cleanHostname.includes('http') && !cleanHostname.includes('httpd'))) {
            result.riskBoost += 12;
            result.reasons.push('Protocol string (http/https) found inside hostname');
        }

        // Check 4: Brand impersonation
        const brandCheck = checkBrandImpersonation(hostname);
        if (brandCheck) {
            result.riskBoost += 8;
            result.reasons.push(brandCheck);
        }

        // Check 5: Lookalike character substitutions
        const lookalikes = countLookalikeChars(hostname);
        if (lookalikes >= 3) {
            result.riskBoost += 5;
            result.reasons.push(`Multiple lookalike character substitutions (${lookalikes} found)`);
        }

        result.isSuspicious = result.riskBoost > 0;

    } catch (error) {
        console.error('Homograph check error:', error);
    }

    return result;
}

/**
 * Detect mixed Unicode scripts (Latin mixed with Cyrillic, Greek, etc.)
 */
function hasMixedScripts(text) {
    let hasLatin = false;
    let hasOther = false;

    for (const char of text) {
        const code = char.codePointAt(0);
        if (code === undefined) continue;

        // Basic Latin (A-Z, a-z)
        if ((code >= 0x0041 && code <= 0x005A) || (code >= 0x0061 && code <= 0x007A)) {
            hasLatin = true;
        }
        // Cyrillic
        else if (code >= 0x0400 && code <= 0x04FF) {
            hasOther = true;
        }
        // Greek
        else if (code >= 0x0370 && code <= 0x03FF) {
            hasOther = true;
        }
        // Armenian
        else if (code >= 0x0530 && code <= 0x058F) {
            hasOther = true;
        }

        if (hasLatin && hasOther) return true;
    }

    return false;
}

/**
 * Check if hostname contains a brand name but isn't the official domain.
 */
function checkBrandImpersonation(hostname) {
    const brands = {
        'paypal': 'paypal.com',
        'google': 'google.com',
        'facebook': 'facebook.com',
        'amazon': 'amazon.com',
        'microsoft': 'microsoft.com',
        'apple': 'apple.com',
        'netflix': 'netflix.com',
        'instagram': 'instagram.com',
        'chase': 'chase.com',
        'wellsfargo': 'wellsfargo.com'
    };

    for (const [brand, official] of Object.entries(brands)) {
        if (hostname.includes(brand) &&
            !hostname.endsWith(official) &&
            !hostname.endsWith('.' + official)) {
            return `Brand "${brand}" found in non-official domain (expected *${official})`;
        }
    }

    return null;
}

/**
 * Count characters commonly used as lookalikes (0→o, 1→l, etc.)
 */
function countLookalikeChars(hostname) {
    const lookalikes = new Set(['0', '1', '!', '$', '5']);
    let count = 0;
    for (const char of hostname) {
        if (lookalikes.has(char)) count++;
    }
    return count;
}
