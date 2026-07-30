import { startRegistration, startAuthentication } from '@simplewebauthn/browser';
export { AuthenticationResponseJSON, PublicKeyCredentialCreationOptionsJSON, PublicKeyCredentialRequestOptionsJSON, RegistrationResponseJSON } from '@simplewebauthn/browser';

type LocalWebAuthnBrowserEndpoints = {
    exchangeEnrollment: string;
    registrationOptions: string;
    registrationVerify: string;
    authenticationOptions: string;
    authenticationVerify: string;
    logout: string;
};
type EnrollmentIdentity = {
    id?: string;
    name: string;
    displayName?: string;
    email?: string;
};
type LocalWebAuthnBrowserOptions = {
    basePath?: string;
    endpoints?: Partial<LocalWebAuthnBrowserEndpoints>;
    fetch?: typeof globalThis.fetch;
    ceremonies?: {
        startRegistration: typeof startRegistration;
        startAuthentication: typeof startAuthentication;
    };
};
declare class LocalWebAuthnBrowserError extends Error {
    readonly code: string;
    readonly status: number;
    constructor(code: string, message: string, status: number);
}
declare class LocalWebAuthnBrowser {
    #private;
    constructor(options?: LocalWebAuthnBrowserOptions);
    exchangeEnrollment(token: string): Promise<EnrollmentIdentity>;
    registerPasskey(label?: string): Promise<{
        verified: true;
    }>;
    signIn(): Promise<{
        verified: true;
    }>;
    signOut(): Promise<{
        signed_out: true;
    }>;
}
declare function consumeEnrollmentToken(location: Pick<Location, 'pathname' | 'hash'>, history?: Pick<History, 'replaceState'>, expectedPath?: string): string | null;

export { type EnrollmentIdentity, LocalWebAuthnBrowser, type LocalWebAuthnBrowserEndpoints, LocalWebAuthnBrowserError, type LocalWebAuthnBrowserOptions, consumeEnrollmentToken };
