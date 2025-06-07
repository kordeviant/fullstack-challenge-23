"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_fetch_1 = __importStar(require("node-fetch"));
const promises_1 = __importDefault(require("fs/promises"));
const path_1 = __importDefault(require("path"));
const node_html_parser_1 = require("node-html-parser");
class LegacyAuthClient {
    constructor(baseUrl, credentials, loginPageUrl = '/login', loginPostUrl = '/login', sessionFile = './session.json', sessionTimeoutHours = 24) {
        this.session = null;
        this.baseUrl = baseUrl.replace(/\/$/, ''); // Remove trailing slash
        this.credentials = credentials;
        this.loginPageUrl = loginPageUrl;
        this.loginPostUrl = loginPostUrl;
        this.sessionFile = sessionFile;
        this.sessionTimeout = sessionTimeoutHours * 60 * 60 * 1000; // Convert to milliseconds
    }
    async loadSession() {
        try {
            const sessionData = await promises_1.default.readFile(this.sessionFile, 'utf-8');
            this.session = JSON.parse(sessionData);
        }
        catch (error) {
            console.log('No existing session found or invalid session file');
            this.session = null;
        }
    }
    async saveSession(cookies) {
        const sessionData = {
            cookies,
            timestamp: Date.now(),
            expiresIn: this.sessionTimeout
        };
        try {
            // Create directory if it doesn't exist
            const dir = path_1.default.dirname(this.sessionFile);
            await promises_1.default.mkdir(dir, { recursive: true });
            await promises_1.default.writeFile(this.sessionFile, JSON.stringify(sessionData, null, 2));
            this.session = sessionData;
            console.log('Session saved successfully');
        }
        catch (error) {
            console.error('Error saving session:', error);
        }
    }
    isSessionValid() {
        if (!this.session)
            return false;
        const now = Date.now();
        const sessionAge = now - this.session.timestamp;
        const maxAge = this.session.expiresIn || this.sessionTimeout;
        return sessionAge < maxAge;
    }
    parseCookies(response) {
        const setCookieHeader = response.headers.raw()['set-cookie'];
        if (!setCookieHeader)
            return [];
        return setCookieHeader.map((cookie) => {
            // Extract the cookie name=value part (before the first semicolon)
            return cookie.split(';')[0];
        });
    }
    getCookieHeader(cookies) {
        const cookiesToUse = cookies || (this.session?.cookies) || [];
        return cookiesToUse.join('; ');
    }
    mergeCookies(existingCookies, newCookies) {
        const cookieMap = new Map();
        // Add existing cookies
        existingCookies.forEach(cookie => {
            const [name, value] = cookie.split('=');
            if (name && value) {
                cookieMap.set(name.trim(), cookie);
            }
        });
        // Override with new cookies
        newCookies.forEach(cookie => {
            const [name, value] = cookie.split('=');
            if (name && value) {
                cookieMap.set(name.trim(), cookie);
            }
        });
        return Array.from(cookieMap.values());
    }
    extractHiddenFields(html) {
        const hiddenFields = {};
        try {
            const root = (0, node_html_parser_1.parse)(html);
            // Find all hidden input fields in the login form
            const hiddenInputs = root.querySelectorAll('input[type="hidden"]');
            hiddenInputs.forEach(input => {
                const name = input.getAttribute('name');
                const value = input.getAttribute('value');
                if (name && value !== null) {
                    hiddenFields[name] = value;
                }
            });
        }
        catch (error) {
            console.warn('Error parsing HTML for hidden fields:', error);
        }
        return hiddenFields;
    }
    async getLoginPage() {
        try {
            console.log('Fetching login page to get initial cookies...');
            const response = await (0, node_fetch_1.default)(`${this.baseUrl}${this.loginPageUrl}`, {
                method: 'GET',
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                }
            });
            if (!response.ok) {
                throw new Error(`Failed to fetch login page: ${response.status} ${response.statusText}`);
            }
            const html = await response.text();
            const cookies = this.parseCookies(response);
            const hiddenFields = this.extractHiddenFields(html);
            console.log('Login page loaded successfully, cookies received:', cookies.length);
            console.log('Hidden fields found:', Object.keys(hiddenFields));
            return { cookies, hiddenFields };
        }
        catch (error) {
            console.error('Error fetching login page:', error);
            throw error;
        }
    }
    async login() {
        try {
            // First, get the login page to collect initial cookies
            const loginPageData = await this.getLoginPage();
            console.log('Attempting to login...');
            // Create FormData with credentials
            const formData = new node_fetch_1.FormData();
            formData.append('username', this.credentials.username);
            formData.append('password', this.credentials.password);
            // Add all hidden fields from the login page
            Object.entries(loginPageData.hiddenFields || {}).forEach(([name, value]) => {
                formData.append(name, value);
                console.log(`Adding hidden field: ${name}`);
            });
            const loginResponse = await (0, node_fetch_1.default)(`${this.baseUrl}${this.loginPostUrl}`, {
                method: 'POST',
                headers: {
                    'Cookie': this.getCookieHeader(loginPageData.cookies),
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                },
                body: formData,
                // redirect: 'manual' // Handle redirects manually to capture cookies
            });
            // Get new cookies from login response
            const newCookies = this.parseCookies(loginResponse);
            // Merge cookies from login page and login response
            const allCookies = this.mergeCookies(loginPageData.cookies, newCookies);
            // Check if login was successful
            const isSuccess = loginResponse.status === 302 || // Redirect on success
                loginResponse.status === 200 || // Success page
                loginResponse.status === 303;
            if (!isSuccess) {
                console.error('Login failed:', loginResponse.status, loginResponse.statusText);
                return false;
            }
            if (allCookies.length === 0) {
                console.error('No cookies received from login process');
                return false;
            }
            await this.saveSession(allCookies);
            console.log('Login successful');
            return true;
        }
        catch (error) {
            console.error('Login error:', error);
            return false;
        }
    }
    async ensureAuthenticated() {
        await this.loadSession();
        if (this.isSessionValid()) {
            console.log('Using existing valid session');
            return true;
        }
        console.log('Session expired or invalid, logging in...');
        return await this.login();
    }
    async getUsers() {
        if (!(await this.ensureAuthenticated())) {
            console.error('Authentication failed');
            return null;
        }
        try {
            console.log('Fetching users...');
            const response = await (0, node_fetch_1.default)(`${this.baseUrl}/api/users`, {
                method: 'GET',
                headers: {
                    'Cookie': this.getCookieHeader(),
                    'Accept': 'application/json',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                }
            });
            if (response.status === 401 || response.status === 403) {
                console.log('Session expired, attempting to re-login...');
                this.session = null; // Clear invalid session
                if (await this.login()) {
                    // Retry the request with new session
                    return await this.getUsers();
                }
                else {
                    console.error('Re-login failed');
                    return null;
                }
            }
            if (!response.ok) {
                console.error('Failed to fetch users:', response.status, response.statusText);
                return null;
            }
            const users = await response.json();
            console.log(`Successfully fetched ${users.length} users`);
            return users;
        }
        catch (error) {
            console.error('Error fetching users:', error);
            return null;
        }
    }
    async makeAuthenticatedRequest(endpoint, options = {}) {
        if (!(await this.ensureAuthenticated())) {
            throw new Error('Authentication failed');
        }
        const response = await (0, node_fetch_1.default)(`${this.baseUrl}${endpoint}`, {
            ...options,
            headers: {
                'Cookie': this.getCookieHeader(),
                'Accept': 'application/json',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                ...options.headers
            }
        });
        if (response.status === 401 || response.status === 403) {
            console.log('Session expired, attempting to re-login...');
            this.session = null;
            if (await this.login()) {
                // Retry the request
                return await this.makeAuthenticatedRequest(endpoint, options);
            }
            else {
                throw new Error('Re-authentication failed');
            }
        }
        return response;
    }
    async saveUsersToFile(filename = './users.json') {
        const users = await this.getUsers();
        if (users) {
            try {
                const dir = path_1.default.dirname(filename);
                await promises_1.default.mkdir(dir, { recursive: true });
                await promises_1.default.writeFile(filename, JSON.stringify(users, null, 2));
                console.log(`Users saved to ${filename}`);
            }
            catch (error) {
                console.error('Error saving users to file:', error);
            }
        }
    }
}
// Usage example
async function main() {
    const client = new LegacyAuthClient('https://challenge.sunvoy.com', // Base URL
    {
        username: encodeURIComponent('demo@example.org'),
        password: 'test'
    }, '/login', // Login page URL (GET)
    '/login', // Login post URL (POST)
    './session.json', // Session file path
    24 // Session timeout in hours
    );
    try {
        // Get users and save to file
        await client.saveUsersToFile('./data/users.json');
        // Or just get users
        const users = await client.getUsers();
        if (users) {
            console.log('Users:', users);
        }
        // Make other authenticated requests
        const response = await client.makeAuthenticatedRequest('/api/some-endpoint');
        if (response.ok) {
            const data = await response.json();
            console.log('Other data:', data);
        }
    }
    catch (error) {
        console.error('Error:', error);
    }
}
// Run the example
main();
