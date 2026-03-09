/**
 * Base error class for all Passkey-related operations.
 */
export class PasskeyError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'PasskeyError';
    }
}

/**
 * Thrown when a user explicitly cancels the Face ID / Touch ID / Security Key prompt.
 */
export class PasskeyCancelledError extends PasskeyError {
    constructor() {
        super('Passkey operation was cancelled by the user');
        this.name = 'PasskeyCancelledError';
    }
}

/**
 * Thrown when the server fails to verify the passkey response.
 */
export class PasskeyVerificationError extends PasskeyError {
    constructor(message: string) {
        super(message);
        this.name = 'PasskeyVerificationError';
    }
}

/**
 * Configuration options for the PocketBasePasskey SDK.
 */
export interface PasskeyOptions {
    /** The base URL of your PocketBase server (e.g., 'http://localhost:8090'). */
    apiUrl: string;
    /** 
     * Optional: An instance of the official PocketBase JavaScript SDK.
     * If provided, the SDK will automatically authenticate this instance on successful login.
     */
    pb?: any;
}

/**
 * The main SDK class for handling Passkey registration and authentication with PocketBase.
 */
export class PocketBasePasskey {
    private apiUrl: string;
    private pb?: any;

    /**
     * Initializes the Passkey SDK.
     * @param options - A configuration object or just the API URL string.
     */
    constructor(options: PasskeyOptions | string) {
        if (typeof options === 'string') {
            this.apiUrl = options;
        } else {
            this.apiUrl = options.apiUrl || (options.pb?.baseUrl);
            this.pb = options.pb;
        }

        if (!this.apiUrl) {
            throw new PasskeyError('API URL is required');
        }

        // Ensure no trailing slash
        this.apiUrl = this.apiUrl.replace(/\/$/, '');
    }

    /**
     * Completes the entire Passkey registration flow in a single call.
     * This will trigger the browser's biometric/security key prompt.
     * 
     * @param userId - The ID (Record ID) of the user to register the passkey for.
     * @returns A promise that resolves to the registration result from the server.
     * @throws {PasskeyCancelledError} If the user cancels the prompt.
     * @throws {PasskeyVerificationError} If the server-side verification fails.
     */
    async register(userId: string): Promise<any> {
        try {
            const options = await this.registerBegin(userId);
            return await this.registerFinish(userId, options);
        } catch (err: any) {
            if (err.name === 'NotAllowedError' || err.message?.includes('cancelled')) {
                throw new PasskeyCancelledError();
            }
            throw err;
        }
    }

    /**
     * Completes the entire Passkey login flow in a single call.
     * If a PocketBase instance was provided in the constructor, it will be automatically authenticated.
     * 
     * @param userId - The ID (Record ID) of the user to authenticate.
     * @returns A promise that resolves to the authentication result (contains token and record).
     * @throws {PasskeyCancelledError} If the user cancels the prompt.
     * @throws {PasskeyVerificationError} If the credentials are invalid or verification fails.
     */
    async login(userId: string): Promise<any> {
        try {
            const options = await this.loginBegin(userId);
            const result = await this.loginFinish(userId, options);

            // If we have a pb instance, automatically authenticate it
            if (this.pb && result.token && result.record) {
                this.pb.authStore.save(result.token, result.record);
            }

            return result;
        } catch (err: any) {
            if (err.name === 'NotAllowedError' || err.message?.includes('cancelled')) {
                throw new PasskeyCancelledError();
            }
            throw err;
        }
    }

    // --- Private/Lower-level methods ---

    /**
     * Fetch registration options from the server.
     * @internal
     */
    private async registerBegin(userId: string): Promise<any> {
        const res = await fetch(`${this.apiUrl}/api/passkey/register/begin`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ userId })
        });
        const data = await res.json();
        if (!res.ok) throw new PasskeyError(data.error || 'Failed to begin registration');
        return data;
    }

    /**
     * Create the credential locally and send verification data to the server.
     * @internal
     */
    private async registerFinish(userId: string, data: any): Promise<any> {
        const options = data.publicKey || data;
        const creationOptions: PublicKeyCredentialCreationOptions = {
            ...options,
            challenge: this.base64urlToBuffer(options.challenge),
            user: {
                ...options.user,
                id: this.base64urlToBuffer(options.user?.id)
            }
        };

        if (creationOptions.excludeCredentials) {
            creationOptions.excludeCredentials = creationOptions.excludeCredentials.map(cred => ({
                ...cred,
                id: this.base64urlToBuffer(cred.id as unknown as string)
            }));
        }

        const credential = await navigator.credentials.create({
            publicKey: creationOptions
        }) as PublicKeyCredential;

        if (!credential) throw new PasskeyCancelledError();

        const response = credential.response as AuthenticatorAttestationResponse;
        const body = {
            userId,
            id: credential.id,
            rawId: this.bufferToBase64url(new Uint8Array(credential.rawId)),
            type: credential.type,
            response: {
                attestationObject: this.bufferToBase64url(new Uint8Array(response.attestationObject)),
                clientDataJSON: this.bufferToBase64url(new Uint8Array(response.clientDataJSON)),
            },
            transports: response.getTransports ? response.getTransports() : [],
        };

        const finishRes = await fetch(`${this.apiUrl}/api/passkey/register/finish`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });

        const finishData = await finishRes.json();
        if (!finishRes.ok) throw new PasskeyVerificationError(finishData.error || 'Registration failed');
        return finishData;
    }

    /**
     * Fetch login options from the server.
     * @internal
     */
    private async loginBegin(userId: string): Promise<any> {
        const res = await fetch(`${this.apiUrl}/api/passkey/login/begin`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ userId })
        });
        const data = await res.json();
        if (!res.ok) throw new PasskeyError(data.error || 'Failed to begin login');
        return data;
    }

    /**
     * Handle biometric prompt for authentication and verify response with the server.
     * @internal
     */
    private async loginFinish(userId: string, data: any): Promise<any> {
        const options = data.publicKey || data;
        const requestOptions: PublicKeyCredentialRequestOptions = {
            ...options,
            challenge: this.base64urlToBuffer(options.challenge)
        };

        if (requestOptions.allowCredentials) {
            requestOptions.allowCredentials = requestOptions.allowCredentials.map(cred => ({
                ...cred,
                id: this.base64urlToBuffer(cred.id as unknown as string)
            }));
        }

        const assertion = await navigator.credentials.get({
            publicKey: requestOptions
        }) as PublicKeyCredential;

        if (!assertion) throw new PasskeyCancelledError();

        const response = assertion.response as AuthenticatorAssertionResponse;
        const body = {
            userId,
            id: assertion.id,
            rawId: this.bufferToBase64url(new Uint8Array(assertion.rawId)),
            type: assertion.type,
            response: {
                authenticatorData: this.bufferToBase64url(new Uint8Array(response.authenticatorData)),
                clientDataJSON: this.bufferToBase64url(new Uint8Array(response.clientDataJSON)),
                signature: this.bufferToBase64url(new Uint8Array(response.signature)),
                userHandle: response.userHandle ? this.bufferToBase64url(new Uint8Array(response.userHandle)) : null,
            },
        };

        const finishRes = await fetch(`${this.apiUrl}/api/passkey/login/finish`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });

        const finishData = await finishRes.json();
        if (!finishRes.ok) throw new PasskeyVerificationError(finishData.error || 'Login failed');

        if (!finishData.token) {
            throw new PasskeyVerificationError('No token received');
        }

        return finishData;
    }

    // --- Utils ---

    /**
     * Decodes a base64url string to an ArrayBuffer.
     * @private
     */
    private base64urlToBuffer(base64url: string): ArrayBuffer {
        if (!base64url || typeof base64url !== 'string') {
            return new ArrayBuffer(0);
        }
        const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
        const padLen = (4 - (base64.length % 4)) % 4;
        const paddedBase64 = base64 + '='.repeat(padLen);
        const binary = atob(paddedBase64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    /**
     * Encodes a Uint8Array to a base64url string.
     * @private
     */
    private bufferToBase64url(buffer: Uint8Array): string {
        const binary = String.fromCharCode(...buffer);
        const base64 = btoa(binary);
        return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }
}
