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
// code copied and modified from https://github.com/microsoft/vscode/blob/1.47.3/src/vs/workbench/api/common/extHostAuthentication.ts

import { Disposable } from './types-impl';
import {
    AuthenticationExt,
    AuthenticationMain, Plugin as InternalPlugin,
    PLUGIN_RPC_CONTEXT
} from '../common/plugin-api-rpc';
import { RPCProtocol } from '../common/rpc-protocol';
import { Emitter, Event } from '@theia/core/lib/common/event';
import * as theia from '@theia/plugin';
import { AuthenticationSessionsChangeEvent } from '../common/plugin-api-rpc-model';

export class AuthenticationExtImpl implements AuthenticationExt {
    private proxy: AuthenticationMain;
    private authenticationProviders: Map<string, theia.AuthenticationProvider> = new Map<string, theia.AuthenticationProvider>();

    private _providerIds: string[] = [];

    private _providers: theia.AuthenticationProviderInformation[] = [];

    private onDidChangeAuthenticationProvidersEmitter = new Emitter<theia.AuthenticationProvidersChangeEvent>();
    readonly onDidChangeAuthenticationProviders: Event<theia.AuthenticationProvidersChangeEvent> = this.onDidChangeAuthenticationProvidersEmitter.event;

    private onDidChangeSessionsEmitter = new Emitter<theia.AuthenticationSessionsChangeEvent>();
    readonly onDidChangeSessions: Event<theia.AuthenticationSessionsChangeEvent> = this.onDidChangeSessionsEmitter.event;

    constructor(rpc: RPCProtocol) {
        this.proxy = rpc.getProxy(PLUGIN_RPC_CONTEXT.AUTHENTICATION_MAIN);
    }

    getProviderIds(): Promise<ReadonlyArray<string>> {
        return this.proxy.$getProviderIds();
    }

    get providerIds(): string[] {
        return this._providerIds;
    }

    get providers(): ReadonlyArray<theia.AuthenticationProviderInformation> {
        return Object.freeze(this._providers.slice());
    }

    async getSession(requestingExtension: InternalPlugin, providerId: string, scopes: string[],
                     options: theia.AuthenticationGetSessionOptions & { createIfNone: true }): Promise<theia.AuthenticationSession>;
    async getSession(requestingExtension: InternalPlugin, providerId: string, scopes: string[],
                     options: theia.AuthenticationGetSessionOptions = {}): Promise<theia.AuthenticationSession | undefined> {
        const provider = this.authenticationProviders.get(providerId);
        const extensionName = requestingExtension.model.displayName || requestingExtension.model.name;
        const extensionId = requestingExtension.model.id.toLowerCase();

        if (!provider) {
            throw new Error(`An authentication provider with id '${providerId}' was not found.`);
        }

        const orderedScopes = scopes.sort().join(' ');
        const sessions = (await provider.getSessions()).filter(s => s.scopes.slice().sort().join(' ') === orderedScopes);

        if (sessions.length > 0) {
            if (!provider.supportsMultipleAccounts) {
                const session = sessions[0];
                const allowed = await this.proxy.$getSessionsPrompt(providerId, session.account.label, provider.label, extensionId, extensionName);
                if (allowed) {
                    return session;
                } else {
                    throw new Error('User did not consent to login.');
                }
            }

            // On renderer side, confirm consent, ask user to choose between accounts if multiple sessions are valid
            const selected = await this.proxy.$selectSession(providerId, provider.label, extensionId, extensionName, sessions, scopes, !!options.clearSessionPreference);
            return sessions.find(session => session.id === selected.id);
        } else {
            if (options.createIfNone) {
                const isAllowed = await this.proxy.$loginPrompt(provider.label, extensionName);
                if (!isAllowed) {
                    throw new Error('User did not consent to login.');
                }

                const session = await provider.login(scopes);
                await this.proxy.$setTrustedExtensionAndAccountPreference(providerId, session.account.label, extensionId, extensionName, session.id);
                return session;
            } else {
                await this.proxy.$requestNewSession(providerId, scopes, extensionId, extensionName);
                return undefined;
            }
        }
    }

    async logout(providerId: string, sessionId: string): Promise<void> {
        const provider = this.authenticationProviders.get(providerId);
        if (!provider) {
            return this.proxy.$logout(providerId, sessionId);
        }

        return provider.logout(sessionId);
    }

    registerAuthenticationProvider(provider: theia.AuthenticationProvider): theia.Disposable {
        if (this.authenticationProviders.get(provider.id)) {
            throw new Error(`An authentication provider with id '${provider.id}' is already registered.`);
        }

        this.authenticationProviders.set(provider.id, provider);
        if (this._providerIds.indexOf(provider.id) === -1) {
            this._providerIds.push(provider.id);
        }

        if (!this._providers.find(p => p.id === provider.id)) {
            this._providers.push({
                id: provider.id,
                label: provider.label
            });
        }

        const listener = provider.onDidChangeSessions(e => {
            this.proxy.$updateSessions(provider.id, e);
        });

        this.proxy.$registerAuthenticationProvider(provider.id, provider.label, provider.supportsMultipleAccounts);

        return new Disposable(() => {
            listener.dispose();
            this.authenticationProviders.delete(provider.id);
            const index = this._providerIds.findIndex(id => id === provider.id);
            if (index > -1) {
                this._providerIds.splice(index);
            }

            const i = this._providers.findIndex(p => p.id === provider.id);
            if (i > -1) {
                this._providers.splice(i);
            }

            this.proxy.$unregisterAuthenticationProvider(provider.id);
        });
    }

    $login(providerId: string, scopes: string[]): Promise<theia.AuthenticationSession> {
        const authProvider = this.authenticationProviders.get(providerId);
        if (authProvider) {
            return Promise.resolve(authProvider.login(scopes));
        }

        throw new Error(`Unable to find authentication provider with handle: ${providerId}`);
    }

    $logout(providerId: string, sessionId: string): Promise<void> {
        const authProvider = this.authenticationProviders.get(providerId);
        if (authProvider) {
            return Promise.resolve(authProvider.logout(sessionId));
        }

        throw new Error(`Unable to find authentication provider with handle: ${providerId}`);
    }

    $getSessions(providerId: string): Promise<ReadonlyArray<theia.AuthenticationSession>> {
        const authProvider = this.authenticationProviders.get(providerId);
        if (authProvider) {
            return Promise.resolve(authProvider.getSessions());
        }

        throw new Error(`Unable to find authentication provider with handle: ${providerId}`);
    }

    $onDidChangeAuthenticationSessions(id: string, label: string, event: AuthenticationSessionsChangeEvent): Promise<void> {
        this.onDidChangeSessionsEmitter.fire({ provider: { id, label }, ...event });
        return Promise.resolve();
    }

   async $onDidChangeAuthenticationProviders(added: theia.AuthenticationProviderInformation[], removed: theia.AuthenticationProviderInformation[]): Promise<void> {
        added.forEach(id => {
            if (this._providers.indexOf(id) === -1) {
                this._providers.push(id);
            }
        });

        removed.forEach(p => {
            const index = this._providers.findIndex(provider => provider.id === p.id);
            if (index > -1) {
                this._providers.splice(index);
            }
        });

        this.onDidChangeAuthenticationProvidersEmitter.fire({ added, removed });
    }
}
