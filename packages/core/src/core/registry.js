/**
 * registry.js - The "Driver" System
 * Allows users to register model-specific profiles (e.g. DeepSeek, Claude)
 * so the core knows how to extract JSON from their unique noise.
 */

const PROFILES = new Map();

// Default Profile: Standard JSON handling
const DEFAULT_PROFILE = {
    extractors: [
        // Standard Markdown Code Block Stripper
        (text) => text.replace(/^```[a-z]*\s*/i, "").replace(/\s*```$/, "")
    ]
};

PROFILES.set('default', DEFAULT_PROFILE);

export function registerProfile(name, config) {
    PROFILES.set(name, config);
}

export function getProfile(name) {
    return PROFILES.get(name) || PROFILES.get('default');
}
