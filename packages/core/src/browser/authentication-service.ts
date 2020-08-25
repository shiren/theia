/********************************************************************************
 * Copyright (C) 2020 Red Hat, Inc. and others.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * This Source Code may also be made available under the following Secondary
 * Licenses when the conditions for such availability set forth in the Eclipse
 * Public License v. 2.0 are satisfied: GNU General Public License, version 2
 * with the GNU Classpath Exception which is available at
 * https://www.gnu.org/software/classpath/license.html.
 *
 * SPDX-License-Identifier: EPL-2.0 OR GPL-2.0 WITH Classpath-exception-2.0
 ********************************************************************************/

/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
// code copied and modified from https://github.com/microsoft/vscode/blob/1.47.3/src/vs/workbench/services/authentication/browser/authenticationService.ts

import { injectable } from 'inversify';
import { Emitter, Event } from '../common/event';
import { StorageService } from '../browser/storage-service';

export interface AuthenticationSession {
    id: string;
    accessToken: string;
    account: {
        label: string;
        id: string;
    }
    scopes: ReadonlyArray<string>;
}

export interface AuthenticationSessionsChangeEvent {
    added: ReadonlyArray<string>;
    removed: ReadonlyArray<string>;
    changed: ReadonlyArray<string>;
}

export interface AuthenticationProviderInformation {
    id: string;
    label: string;
}

export interface AuthenticationProvider {
    id: string;

    supportsMultipleAccounts: boolean;

    label: string;

    hasSessions(): boolean;

    signOut(accountName: string): Promise<void>;

    getSessions(): Promise<ReadonlyArray<AuthenticationSession>>;

    updateSessionItems(event: AuthenticationSessionsChangeEvent): Promise<void>;

    login(scopes: string[]): Promise<AuthenticationSession>;

    logout(sessionId: string): Promise<void>;
}
export const AuthenticationService = Symbol('AuthenticationService');

export interface AuthenticationService {
    isAuthenticationProviderRegistered(id: string): boolean;
    getProviderIds(): string[];
    registerAuthenticationProvider(id: string, provider: AuthenticationProvider): void;
    unregisterAuthenticationProvider(id: string): void;
    sessionsUpdate(providerId: string, event: AuthenticationSessionsChangeEvent): void;

    readonly onDidRegisterAuthenticationProvider: Event<AuthenticationProviderInformation>;
    readonly onDidUnregisterAuthenticationProvider: Event<AuthenticationProviderInformation>;

    readonly onDidChangeSessions: Event<{ providerId: string, label: string, event: AuthenticationSessionsChangeEvent }>;
    getSessions(providerId: string): Promise<ReadonlyArray<AuthenticationSession>>;
    getLabel(providerId: string): string;
    supportsMultipleAccounts(providerId: string): boolean;
    login(providerId: string, scopes: string[]): Promise<AuthenticationSession>;
    logout(providerId: string, sessionId: string): Promise<void>;

    signOutOfAccount(providerId: string, accountName: string): Promise<void>;
}

@injectable()
export class AuthenticationServiceImpl implements AuthenticationService {
    private authenticationProviders: Map<string, AuthenticationProvider> = new Map<string, AuthenticationProvider>();

    private onDidRegisterAuthenticationProviderEmitter: Emitter<AuthenticationProviderInformation> = new Emitter<AuthenticationProviderInformation>();
    readonly onDidRegisterAuthenticationProvider: Event<AuthenticationProviderInformation> = this.onDidRegisterAuthenticationProviderEmitter.event;

    private onDidUnregisterAuthenticationProviderEmitter: Emitter<AuthenticationProviderInformation> = new Emitter<AuthenticationProviderInformation>();
    readonly onDidUnregisterAuthenticationProvider: Event<AuthenticationProviderInformation> = this.onDidUnregisterAuthenticationProviderEmitter.event;

    private onDidChangeSessionsEmitter: Emitter<{ providerId: string, label: string, event: AuthenticationSessionsChangeEvent }> =
        new Emitter<{ providerId: string, label: string, event: AuthenticationSessionsChangeEvent }>();
    readonly onDidChangeSessions: Event<{ providerId: string, label: string, event: AuthenticationSessionsChangeEvent }> = this.onDidChangeSessionsEmitter.event;

    getProviderIds(): string[] {
        const providerIds: string[] = [];
        this.authenticationProviders.forEach(provider => {
            providerIds.push(provider.id);
        });
        return providerIds;
    }

    isAuthenticationProviderRegistered(id: string): boolean {
        return this.authenticationProviders.has(id);
    }

    registerAuthenticationProvider(id: string, authenticationProvider: AuthenticationProvider): void {
        this.authenticationProviders.set(id, authenticationProvider);
        this.onDidRegisterAuthenticationProviderEmitter.fire({ id, label: authenticationProvider.label });
    }

    unregisterAuthenticationProvider(id: string): void {
        const provider = this.authenticationProviders.get(id);
        if (provider) {
            this.authenticationProviders.delete(id);
            this.onDidUnregisterAuthenticationProviderEmitter.fire({ id, label: provider.label });
        }
    }

    async sessionsUpdate(id: string, event: AuthenticationSessionsChangeEvent): Promise<void> {
        const provider = this.authenticationProviders.get(id);
        if (provider) {
            await provider.updateSessionItems(event);
            this.onDidChangeSessionsEmitter.fire({ providerId: id, label: provider.label, event: event });
        }
    }

    getLabel(id: string): string {
        const authProvider = this.authenticationProviders.get(id);
        if (authProvider) {
            return authProvider.label;
        } else {
            throw new Error(`No authentication provider '${id}' is currently registered.`);
        }
    }

    supportsMultipleAccounts(id: string): boolean {
        const authProvider = this.authenticationProviders.get(id);
        if (authProvider) {
            return authProvider.supportsMultipleAccounts;
        } else {
            throw new Error(`No authentication provider '${id}' is currently registered.`);
        }
    }

    async getSessions(id: string): Promise<ReadonlyArray<AuthenticationSession>> {
        const authProvider = this.authenticationProviders.get(id);
        if (authProvider) {
            return await authProvider.getSessions();
        } else {
            throw new Error(`No authentication provider '${id}' is currently registered.`);
        }
    }

    async login(id: string, scopes: string[]): Promise<AuthenticationSession> {
        const authProvider = this.authenticationProviders.get(id);
        if (authProvider) {
            return authProvider.login(scopes);
        } else {
            throw new Error(`No authentication provider '${id}' is currently registered.`);
        }
    }

    async logout(id: string, sessionId: string): Promise<void> {
        const authProvider = this.authenticationProviders.get(id);
        if (authProvider) {
            return authProvider.logout(sessionId);
        } else {
            throw new Error(`No authentication provider '${id}' is currently registered.`);
        }
    }

    async signOutOfAccount(id: string, accountName: string): Promise<void> {
        const authProvider = this.authenticationProviders.get(id);
        if (authProvider) {
            return authProvider.signOut(accountName);
        } else {
            throw new Error(`No authentication provider '${id}' is currently registered.`);
        }
    }
}

export interface AllowedExtension {
    id: string;
    name: string;
}

export async function readAllowedExtensions(storageService: StorageService, providerId: string, accountName: string): Promise<AllowedExtension[]> {
    let trustedExtensions: AllowedExtension[] = [];
    try {
        const trustedExtensionSrc: string | undefined = await storageService.getData(`${providerId}-${accountName}`);
        if (trustedExtensionSrc) {
            trustedExtensions = JSON.parse(trustedExtensionSrc);
        }
    } catch (err) {
        console.log(err);
    }

    return trustedExtensions;
}
