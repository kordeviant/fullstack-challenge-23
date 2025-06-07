import fetch from 'node-fetch';
import fs from 'fs/promises';
import path from 'path';
import { parse } from 'node-html-parser';
const crypto = require('crypto');
const { JSDOM } = require("jsdom");

function extractJsonFromHtml(html: string) {
  const dom = new JSDOM(html);
  const doc = dom.window.document;

  const jsonData = {
    access_token: doc.querySelector("#access_token")?.value || null,
    openId: doc.querySelector("#openId")?.value || null,
    userId: doc.querySelector("#userId")?.value || null,
    apiuser: doc.querySelector("#apiuser")?.value || null,
    operateId: doc.querySelector("#operateId")?.value || null,
    language: doc.querySelector("#language")?.value || null
  };

  return jsonData;
}

function createSignedRequest(params: object, secret: string) {
  const timestamp = Math.floor(Date.now() / 1000);
  const requestParams: any = { ...params, timestamp: timestamp.toString() };

  // Sort and format parameters into query string
  const queryString = Object.keys(requestParams)
    .sort()
    .map(key => `${key}=${encodeURIComponent(requestParams[key])}`)
    .join("&");

  // Generate HMAC-SHA1 hash
  const hmac = crypto.createHmac("sha1", secret);
  hmac.update(queryString);
  const checkcode = hmac.digest("hex").toUpperCase();

  return {
    payload: queryString,
    checkcode: checkcode,
    fullPayload: `${queryString}&checkcode=${checkcode}`,
    timestamp: timestamp
  };
}

function sendUserRequest(url: string, accessToken: string, apiUser: string, userId: string, secret: string) {
  const openId = "openid456";
  const operateId = "op789";
  const language = "en_US";

  const requestParams = {
    access_token: accessToken,
    apiuser: apiUser,
    openId: openId,
    operateId: operateId,
    userId: userId,
    language: language
  };

  // Generate signed request
  const signedRequest = createSignedRequest(requestParams, secret);

  const options = {
    method: "POST",
    headers: {
      "accept": "*/*",
      "accept-language": "en-US,en;q=0.9",
      "content-type": "application/x-www-form-urlencoded",
      "Referer": "https://challenge.sunvoy.com/",
      "Referrer-Policy": "strict-origin-when-cross-origin"
    },
    body: signedRequest.fullPayload
  };

  return fetch(url, options)
}

interface LoginCredentials {
  username: string;
  password: string;
}

interface StoredSession {
  cookies: string[];
  timestamp: number;
  expiresIn?: number; // in milliseconds
}

interface User {
  [key: string]: any;
}

interface LoginPageData {
  cookies: string[];
  hiddenFields?: { [key: string]: string };
}

class LegacyAuthClient {
  private baseUrl: string;
  private credentials: LoginCredentials;
  private sessionFile: string;
  private session: StoredSession | null = null;
  private sessionTimeout: number; // in milliseconds
  private loginPageUrl: string;
  private loginPostUrl: string;

  constructor(
    baseUrl: string,
    credentials: LoginCredentials,
    loginPageUrl: string = '/login',
    loginPostUrl: string = '/login',
    sessionFile: string = './session.json',
    sessionTimeoutHours: number = 24
  ) {
    this.baseUrl = baseUrl.replace(/\/$/, ''); // Remove trailing slash
    this.credentials = credentials;
    this.loginPageUrl = loginPageUrl;
    this.loginPostUrl = loginPostUrl;
    this.sessionFile = sessionFile;
    this.sessionTimeout = sessionTimeoutHours * 60 * 60 * 1000; // Convert to milliseconds
  }

  private async loadSession(): Promise<void> {
    try {
      const sessionData = await fs.readFile(this.sessionFile, 'utf-8');
      this.session = JSON.parse(sessionData);
    } catch (error) {
      console.log('No existing session found or invalid session file');
      this.session = null;
    }
  }

  private async saveSession(cookies: string[]): Promise<void> {
    const sessionData: StoredSession = {
      cookies,
      timestamp: Date.now(),
      expiresIn: this.sessionTimeout
    };

    try {
      // Create directory if it doesn't exist
      const dir = path.dirname(this.sessionFile);
      await fs.mkdir(dir, { recursive: true });

      await fs.writeFile(this.sessionFile, JSON.stringify(sessionData, null, 2));
      this.session = sessionData;
      console.log('Session saved successfully');
    } catch (error) {
      console.error('Error saving session:', error);
    }
  }

  private isSessionValid(): boolean {
    if (!this.session) return false;

    const now = Date.now();
    const sessionAge = now - this.session.timestamp;
    const maxAge = this.session.expiresIn || this.sessionTimeout;

    return sessionAge < maxAge;
  }

  private parseCookies(response: any): string[] {
    const setCookieHeader = response.headers.raw()['set-cookie'];
    if (!setCookieHeader) return [];

    return setCookieHeader.map((cookie: string) => {
      // Extract the cookie name=value part (before the first semicolon)
      return cookie.split(';')[0];
    });
  }

  private getCookieHeader(cookies?: string[]): string {
    const cookiesToUse = cookies || (this.session?.cookies) || [];
    return cookiesToUse.join('; ');
  }

  private mergeCookies(existingCookies: string[], newCookies: string[]): string[] {
    const cookieMap = new Map<string, string>();

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

  private extractHiddenFields(html: string): { [key: string]: string } {
    const hiddenFields: { [key: string]: string } = {};

    try {
      const root = parse(html);

      // Find all hidden input fields in the login form
      const hiddenInputs = root.querySelectorAll('input[type="hidden"]');

      hiddenInputs.forEach(input => {
        const name = input.getAttribute('name');
        const value = input.getAttribute('value');
        if (name && value !== null) {
          hiddenFields[name] = value!;
        }
      });

    } catch (error) {
      console.warn('Error parsing HTML for hidden fields:', error);
    }

    return hiddenFields;
  }
  private async getLoginPage(): Promise<LoginPageData> {
    try {
      console.log('Fetching login page to get initial cookies...');

      const response = await fetch(`${this.baseUrl}${this.loginPageUrl}`, {
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

    } catch (error) {
      console.error('Error fetching login page:', error);
      throw error;
    }
  }
  async login(): Promise<boolean> {
    try {
      // First, get the login page to collect initial cookies
      const loginPageData = await this.getLoginPage();

      console.log('Attempting to login...');

      // Create FormData with credentials
      const formData = new FormData();
      // Add all hidden fields from the login page
      Object.entries(loginPageData.hiddenFields || {}).forEach(([name, value]) => {
        formData.append(name, value);
        console.log(`Adding hidden field: ${name}`);
      });
      formData.append('username', this.credentials.username);
      formData.append('password', this.credentials.password);


      const loginResponse = await fetch(`${this.baseUrl}${this.loginPostUrl}`, {
        method: 'POST',
        headers: {
          "content-type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams(formData as any).toString(),
        redirect: 'manual' // Handle redirects manually to capture cookies
      });

      console.log(`${this.baseUrl}${this.loginPostUrl}`);

      // Get new cookies from login response
      const newCookies = this.parseCookies(loginResponse);

      // Merge cookies from login page and login response
      const allCookies = this.mergeCookies(loginPageData.cookies, newCookies);

      // Check if login was successful
      const isSuccess =
        loginResponse.status === 302 || // Redirect on success
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

    } catch (error) {
      console.error('Login error:', error);
      return false;
    }
  }

  async ensureAuthenticated(): Promise<boolean> {
    await this.loadSession();

    if (this.isSessionValid()) {
      console.log('Using existing valid session');
      return true;
    }

    console.log('Session expired or invalid, logging in...');
    return await this.login();
  }

  async getUsers(): Promise<User[] | null> {
    if (!(await this.ensureAuthenticated())) {
      console.error('Authentication failed');
      return null;
    }

    try {
      console.log('Fetching users...');

      const response = await fetch(`${this.baseUrl}/api/users`, {
        method: 'POST',
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
        } else {
          console.error('Re-login failed');
          return null;
        }
      }

      if (!response.ok) {
        console.error('Failed to fetch users:', response.status, response.statusText);
        return null;
      }

      const users = await response.json() as User[];
      console.log(`Successfully fetched ${users.length} users`);
      return users;

    } catch (error) {
      console.error('Error fetching users:', error);
      return null;
    }
  }

  async makeAuthenticatedRequest(endpoint: string, options: any = {}): Promise<any> {
    if (!(await this.ensureAuthenticated())) {
      throw new Error('Authentication failed');
    }

    const response = await fetch(`${this.baseUrl}${endpoint}`, {
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
      } else {
        throw new Error('Re-authentication failed');
      }
    }

    return response;
  }

  async saveUsersToFile(filename: string = './users.json'): Promise<User[]> {
    const users = await this.getUsers();

    if (users) {
      try {
        const dir = path.dirname(filename);
        await fs.mkdir(dir, { recursive: true });

        await fs.writeFile(filename, JSON.stringify(users, null, 2));
        console.log(`Users saved to ${filename}`);
      } catch (error) {
        console.error('Error saving users to file:', error);
      }
    } else {
      throw new Error("no users")
    }
    return users

  }
}
function extractJsUrls(html: string) {
  const scriptRegex = /<script\s+src="([^"]+)"/g;
  const urls = [];
  let match;

  while ((match = scriptRegex.exec(html)) !== null) {
    urls.push(match[1]);
  }

  return urls;
}
function extractSecret(text: string) {
  const match = text.match(/r\.createHmac\("sha1",\s*"(.*?)"\)/);
  return match ? match[1] : null; // Returns extracted secret or null if not found
}

function extractRemoteApiUrl(htmlText: string) {
  const match = htmlText.match(/window\.REMOTE_API_URL\s*=\s*"(.*?)";/);
  return match ? match[1] : null; // Returns the extracted URL or null if not found
}


async function main() {
  const client = new LegacyAuthClient(
    'https://challenge.sunvoy.com', // Base URL
    {
      username: 'demo@example.org',
      password: 'test'
    },
    '/login',      // Login page URL (GET)
    '/login',      // Login post URL (POST)
    './session.json', // Session file path
    24 // Session timeout in hours
  );

  try {
    // Get users and save to file
    const users = await client.saveUsersToFile('./data/users.json');

    // Make other authenticated requests
    const settingsGetReq = await client.makeAuthenticatedRequest('/settings', { method: "GET" });
    const settingsUrlText = await settingsGetReq.text();
    const settingsUrl = extractRemoteApiUrl(settingsUrlText);
    const jsUrlForSecret = extractJsUrls(settingsUrlText);
    const tokenGetReq = await client.makeAuthenticatedRequest('/settings/tokens', { method: "GET" });
    const tokenHtmlText = await tokenGetReq.text();
    const tokenJson = extractJsonFromHtml(tokenHtmlText);
    const secretJsReq = await client.makeAuthenticatedRequest(jsUrlForSecret[1], { method: "GET" });
    const textsecret = await secretJsReq.text();
    const secret = extractSecret(textsecret);

    const userDataReq = await sendUserRequest(settingsUrl! + '/api/settings', tokenJson.access_token, tokenJson.apiuser, tokenJson.userId, secret!);
    const userDataJson = await userDataReq.json()
    try {
      const dir = path.dirname('./data/users.json');
      await fs.mkdir(dir, { recursive: true });

      await fs.writeFile('./data/users.json', JSON.stringify([...users, userDataJson], null, 2));
      console.log(`Users saved to ${'./data/users.json'}`);
    } catch (error) {
      console.error('Error saving users to file:', error);
    }

  } catch (error) {
    console.error('Error:', error);
  }
}

main();