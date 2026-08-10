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
/**
 * Why an enrollment token was refused, as reported by the server.
 *
 * Mirrors `EnrollmentGrantState` in `@localwebauthn/server`, redeclared rather than
 * imported so the browser package keeps no dependency on the server package. Only
 * `'used'` is worth a distinct message: an enrollment link is single-use, so if the
 * person holding it did not spend it, somebody else did.
 */
type EnrollmentRefusal = 'used' | 'superseded' | 'expired' | 'unknown';
declare class LocalWebAuthnBrowserError extends Error {
    readonly code: string;
    readonly status: number;
    /**
     * Present when the server explained a refused enrollment token. Absent on every
     * other failure, and absent when the host does not forward it.
     */
    readonly enrollmentState?: EnrollmentRefusal;
    constructor(code: string, message: string, status: number, enrollmentState?: EnrollmentRefusal);
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

export { type EnrollmentIdentity, type EnrollmentRefusal, LocalWebAuthnBrowser, type LocalWebAuthnBrowserEndpoints, LocalWebAuthnBrowserError, type LocalWebAuthnBrowserOptions, consumeEnrollmentToken };
