function purgeModal(el) {
	el.dispatchEvent(new CustomEvent('modal-close', { bubbles: true }));
	el.remove();
}
document.addEventListener('DOMContentLoaded', () => {
	// 1. HTMX Component Discovery Bridge
	document.body.addEventListener('htmx:afterSwap', (event) => {
		if (window.Alpine && event.detail.target) {
			if (typeof window.Alpine.initTree === 'function') {
				window.Alpine.initTree(event.detail.target);
			} else if (typeof window.Alpine.processTree === 'function') {
				window.Alpine.processTree(event.detail.target);
			}
		}
	});

	// Hypermedia Semantic Error Status Compliance (§14.4 / §9.4)
	document.body.addEventListener('htmx:beforeOnLoad', function (evt) {
		if (evt.detail.xhr.status === 422) {
			evt.detail.shouldSwap = true;
			evt.detail.isError = false;
		}
	});
});

document.addEventListener('alpine:init', () => {
	Alpine.data('urlManager', () => ({
		urls: [],
		newUrl: '',
		error: '',
		init() {
			try {
				this.urls = JSON.parse(this.$el.dataset.initialUrls || '[]') || [];
			} catch (e) {
				this.urls = [];
			}
		},
		addUrl() {
			this.error = '';
			const trimmed = this.newUrl.trim();
			if (!trimmed) return;
			try {
				new URL(trimmed);
				if (!this.urls.includes(trimmed)) {
					this.urls.push(trimmed);
				}
				this.newUrl = '';
			} catch (e) {
				this.error = 'Invalid URL format (must include protocol like http:// or https://)';
			}
		},
		removeUrl(index) {
			this.urls.splice(index, 1);
		}
	}));

	// Redirect URI whitelist with a default entry. Initial values arrive as data attributes, never as interpolated
	// JavaScript, so a URI containing quotes cannot break out of the expression.
	Alpine.data('redirectUriManager', () => ({
		urls: [],
		defaultUrl: '',
		newUrl: '',
		init() {
			try {
				this.urls = JSON.parse(this.$el.dataset.initialUrls || '[]') || [];
			} catch (e) {
				this.urls = [];
			}
			this.defaultUrl = this.$el.dataset.defaultUrl || '';
		},
		addUrl() {
			const value = this.newUrl.trim();
			if (!value) return;
			if (!this.urls.includes(value)) {
				this.urls.push(value);
			}
			if (!this.defaultUrl) {
				this.defaultUrl = value;
			}
			this.newUrl = '';
		},
		removeUrl(index) {
			const removed = this.urls[index];
			this.urls.splice(index, 1);
			if (this.defaultUrl === removed) {
				this.defaultUrl = this.urls[0] || '';
			}
		}
	}));

	// Consolidated tagListManager
	Alpine.data('tagListManager', () => ({
		tags: [],
		builtIn: [],
		selectedBuiltIn: [],
		newTag: '',
		error: '',
		inputName: '',
		isAudience: false,

		init() {
			this.inputName = this.$el.dataset.inputName || 'tags';
			this.isAudience = this.$el.dataset.isAudience === 'true';
			try {
				this.builtIn = JSON.parse(this.$el.dataset.builtIn) || [];
			} catch(e) {
				this.builtIn = [];
			}
			let initList = [];
			try {
				initList = JSON.parse(this.$el.dataset.initialTags) || [];
			} catch(e) {
				initList = [];
			}

			initList.forEach(t => {
				if (this.builtIn.includes(t)) {
					this.selectedBuiltIn.push(t);
				} else if (t.trim() !== '') {
					this.tags.push(t.trim());
				}
			});
		},
		addTag() {
			this.error = '';
			const trimmed = this.newTag.trim();
			if (!trimmed) return;

			if (this.isAudience) {
				if (trimmed.includes(' ') || (!trimmed.includes('://') && !/^[a-zA-Z0-9_:-]+$/.test(trimmed))) {
					this.error = 'Must be an absolute URI or valid system identifier';
					return;
				}
			}

			if (this.builtIn.includes(trimmed)) {
				if (!this.selectedBuiltIn.includes(trimmed)) {
					this.selectedBuiltIn.push(trimmed);
				}
				this.newTag = '';
				return;
			}

			if (this.tags.includes(trimmed)) {
				this.error = 'Value already exists';
				return;
			}
			this.tags.push(trimmed);
			this.newTag = '';
		},
		removeTag(index) {
			this.tags.splice(index, 1);
		}
	}));

	Alpine.data('lifetimeCalculator', () => ({
		seconds: 3600,
		value: 1,
		unit: 'hours',
		init() {
			this.seconds = parseInt(this.$el.dataset.initialSeconds) || 3600;
			const totalSec = parseInt(this.seconds) || 0;
			if (totalSec % 86400 === 0 && totalSec > 0) {
				this.value = totalSec / 86400;
				this.unit = 'days';
			} else if (totalSec % 3600 === 0 && totalSec > 0) {
				this.value = totalSec / 3600;
				this.unit = 'hours';
			} else if (totalSec % 60 === 0 && totalSec > 0) {
				this.value = totalSec / 60;
				this.unit = 'minutes';
			} else {
				this.value = totalSec;
				this.unit = 'seconds';
			}
		},
		updateSeconds() {
			const val = parseFloat(this.value) || 0;
			let multiplier = 1;
			if (this.unit === 'minutes') multiplier = 60;
			else if (this.unit === 'hours') multiplier = 3600;
			else if (this.unit === 'days') multiplier = 86400;
			this.seconds = Math.round(val * multiplier);
		},
		snapToPublicDefault() {
			this.value = 1;
			this.unit = 'days';
			this.updateSeconds();
		}
	}));

	Alpine.data('idpRouter', (initialAllowed, allProviders) => ({
		allProviders: allProviders || [],
		allowed: initialAllowed || [],
		init() {
			// Keep initial selection
		}
	}));

	Alpine.data('secretGenerator', (initialSecret) => ({
		secret: initialSecret || '',
		generate() {
			const bytes = new Uint8Array(32);
			window.crypto.getRandomValues(bytes);
			let binary = '';
			for (let i = 0; i < 32; i++) {
				binary += String.fromCharCode(bytes[i]);
			}
			this.secret = btoa(binary)
				.replace(/\+/g, '-')
				.replace(/\//g, '_')
				.replace(/=/g, '');
		}
	}));

	Alpine.data('applicationFormManager', () => ({
		authMethod: 'client_secret_post',
		enforceRtr: false,
		init() {
			this.authMethod = this.$el.dataset.initialAuthMethod || 'client_secret_post';
			this.enforceRtr = this.$el.dataset.enforceRtr === 'true';

			// Watch authMethod to automatically cascade zero-trust RTR locking rules
			this.$watch('authMethod', (val) => {
				if (val === 'none') {
					this.enforceRtr = true;
				}
			});
		}
	}));

	Alpine.data('oidcFormManager', () => {
		return {
			idpType: 'username-password',
			alias: '',
			name: '',

			discoveryEndpoint: '',
			issuer: '',
			discoveryResult: null,
			discoveryRaw: '',
			discoveryError: '',
			isDiscovering: false,

			clientID: '',
			clientSecret: '',
			authMethod: 'client_secret_basic',

			pkceEnabled: false,
			pkceLocked: false,

			parEnabled: false,
			parLocked: false,
			parEnforced: false,

			sloEnabled: false,
			sloSupported: false,

			selectedScopes: [],
			selectedAcrValues: [],
			selectedClaims: [],
			selectedDomainAliases: [],
			userIdentifierClaim: 'sub',

			discoveredScopes: [],
			discoveredAcrValues: [],

			ial: 1,
			aal: 1,

			// Advanced Multi-Dimensional Mapping Grid Store
			// Schema: { "raw_acr": { aal: number, ial: number } }
			acrToTuple: {},

			amrToAAL: {
				pwd: 1, mfa: 2, otp: 2, sms: 2, hwk: 3
			},
			customAmrs: [],

			init() {
				this.idpType = this.$el.dataset.idpType || 'username-password';
				this.alias = this.$el.dataset.alias || '';
				this.name = this.$el.dataset.name || '';

				let cfg = {};
				try {
					cfg = JSON.parse(this.$el.dataset.config || '{}') || {};
				} catch(e) {}

				this.discoveryEndpoint = cfg.discovery_endpoint || '';
				this.issuer = cfg.issuer || '';
				this.discoveryRaw = cfg.discovery_result || '';
				this.clientID = cfg.client_id || '';
				this.clientSecret = cfg.client_secret || '';
				this.authMethod = cfg.authentication_method || 'client_secret_basic';

				this.pkceEnabled = !!cfg.pkce_enabled;
				this.parEnabled = !!cfg.par_enabled;
				this.sloEnabled = !!cfg.slo_enabled;

				this.selectedScopes = cfg.scopes || [];
				this.selectedAcrValues = cfg.acr_values || [];
				this.selectedClaims = cfg.claims || [];
				this.selectedDomainAliases = cfg.domain_aliases || [];
				this.userIdentifierClaim = cfg.user_identifier_claim || 'sub';

				this.ial = cfg.ial || 1;
				this.aal = cfg.aal || 1;

				this.acrToTuple = cfg.acr_to_tuple || {};

				this.amrToAAL = cfg.amr_to_aal && Object.keys(cfg.amr_to_aal).length > 0 ? cfg.amr_to_aal : {
					pwd: 1, mfa: 2, otp: 2, sms: 2, hwk: 3
				};
				this.customAmrs = Object.keys(cfg.amr_to_aal || {})
					.filter(k => !['pwd', 'mfa', 'otp', 'sms', 'hwk'].includes(k))
					.map(k => ({ key: k, value: String(cfg.amr_to_aal[k]) })) || [];

				if (this.discoveryRaw) {
					try {
						const result = JSON.parse(this.discoveryRaw);
						this.applyDiscoveryPayload(result);
					} catch(e) {}
				}

				// 1. Enforce strict Type-Sanitization on stored configurations
				if (this.acrToTuple) {
					Object.keys(this.acrToTuple).forEach(key => {
						if (this.acrToTuple[key]) {
							this.acrToTuple[key].aal = String(this.acrToTuple[key].aal ?? '0');
							this.acrToTuple[key].ial = String(this.acrToTuple[key].ial ?? '0');
						}
					});
				} else {
					this.acrToTuple = {};
				}

				// 2. Prefill tuple configurations cleanly for any remaining elements
				if (this.selectedAcrValues && this.selectedAcrValues.length > 0) {
					this.selectedAcrValues.forEach(acr => {
						if (!this.acrToTuple[acr]) {
							let meta = this.resolveAcrMetadata(acr);
							this.acrToTuple[acr] = {
								aal: String(meta.aal),
								ial: String(meta.ial)
							};
						}
					});
				}

				this.syncComputedRules();
			},

			handleIdpTypeChange(val) {
				this.idpType = val;
				if (val === 'oidc' && !this.alias) {
					this.alias = 'oidc';
				}
			},

			handleAuthMethodChange(val) {
				this.authMethod = val;
				this.syncComputedRules();
			},

			handlePkceChange(checked) {
				if (!this.pkceLocked) {
					this.pkceEnabled = checked;
				}
			},

			handleParChange(checked) {
				if (!this.parLocked) {
					this.parEnabled = checked;
				}
			},

			handleSloChange(checked) {
				this.sloEnabled = checked;
			},

			toggleScope(scope) {
				if (this.selectedScopes.includes(scope)) {
					this.selectedScopes = this.selectedScopes.filter(s => s !== scope);
				} else {
					this.selectedScopes.push(scope);
				}
			},

			toggleAcr(acr) {
				if (this.selectedAcrValues.includes(acr)) {
					this.selectedAcrValues = this.selectedAcrValues.filter(a => a !== acr);
					if (this.acrToTuple && this.acrToTuple[acr]) {
						delete this.acrToTuple[acr];
					}
				} else {
					this.selectedAcrValues.push(acr);

					if (!this.acrToTuple) {
						this.acrToTuple = {};
					}

					// Resolve suggestions and mount immediately as String values to prevent select dropouts
					let meta = this.resolveAcrMetadata(acr);
					this.acrToTuple[acr] = {
						aal: String(meta.aal),
						ial: String(meta.ial)
					};
				}
			},

			addCustomAmr() {
				this.customAmrs.push({ key: '', value: '' });
			},

			removeCustomAmr(index) {
				this.customAmrs.splice(index, 1);
			},

			resolveAcrMetadata(acr) {
				if (!acr) return { label: '', aal: 0, ial: 0 };

				let lower = acr.toLowerCase();
				const replacements = [
					{ old: 'authentication_level', new: 'aal' },
					{ old: 'identification_level', new: 'ial' },
					{ old: 'authentication', new: 'auth' },
					{ old: 'identification', new: 'iden' },
					{ old: 'username-password', new: 'pwd' },
					{ old: 'password', new: 'pwd' },
					{ old: 'multifactor', new: 'mfa' },
					{ old: 'one_factor', new: '1fa' },
					{ old: 'two_factor', new: '2fa' }
				];

				replacements.forEach(r => {
					lower = lower.split(r.old).join(r.new);
				});

				// Extract Right-Most 11 Characters for the Display Tag
				let label = lower;
				if (lower.length > 11) {
					label = lower.substring(lower.length - 11);
				}

				// Determine Security Buckets
				let aal = 0;
				let ial = 0;

				// Evaluate AAL metrics
				if (lower.includes('aal:3') || lower.includes('aal3') || lower.includes('aal:4') || lower.includes('aal4') || lower.includes('loa-3')) {
					aal = 3;
				} else if (lower.includes('aal:2') || lower.includes('aal2') || lower.includes('mfa') || lower.includes('2fa') || lower.includes('loa-2')) {
					aal = 2;
				} else if (lower.includes('aal:1') || lower.includes('aal1') || lower.includes('pwd') || lower.includes('1fa') || lower.includes('loa-1')) {
					aal = 1;
				}

				// Evaluate IAL metrics
				if (lower.includes('ial:3') || lower.includes('ial3') || lower.includes('ial:4') || lower.includes('ial4')) {
					ial = 3;
				} else if (lower.includes('ial:2') || lower.includes('ial2')) {
					ial = 2;
				} else if (lower.includes('ial:1') || lower.includes('ial1')) {
					ial = 1;
				}

				return { label, aal, ial };
			},

			// Core Pillar Slicing Routine using the dynamic target AAL column values
			getAcrValuesForLevel(aalTargetColumn) {
				if (!this.discoveryResult || !this.discoveryResult.acr_values_supported) {
					return [];
				}

				let filtered = this.discoveryResult.acr_values_supported.filter(acr => {
					let meta = this.resolveAcrMetadata(acr);
					return String(meta.aal) === String(aalTargetColumn);
				});

				return filtered.sort((a, b) => {
					let labelA = this.resolveAcrMetadata(a).label;
					let labelB = this.resolveAcrMetadata(b).label;
					return labelA.localeCompare(labelB);
				});
			},

			formatAcrLabel(acr) {
				return this.resolveAcrMetadata(acr).label;
			},

			discoverEndpoint() {
				const urlStr = this.discoveryEndpoint.trim();
				if (!urlStr) {
					this.discoveryError = 'Please enter a discovery endpoint URL';
					return;
				}
				try {
					new URL(urlStr);
				} catch (e) {
					this.discoveryError = 'Invalid discovery URL format';
					return;
				}
				this.discoveryError = '';
				this.isDiscovering = true;

				window.fetch('/admin/idps/discover?url=' + encodeURIComponent(urlStr))
					.then(r => {
						if (!r.ok) {
							throw new Error('Failed to fetch well-known configuration');
						}
						return r.json();
					})
					.then(data => {
						this.isDiscovering = false;
						this.discoveryResult = data;
						this.discoveryRaw = JSON.stringify(data);

						if (data.issuer) {
							this.issuer = data.issuer;
						}

						this.applyDiscoveryPayload(data);
					})
					.catch(err => {
						this.isDiscovering = false;
						this.discoveryError = err.message || 'Failed to discover provider metadata';
					});
			},

			applyDiscoveryPayload(data) {
				this.discoveryResult = data;

				if (data.scopes_supported) {
					this.discoveredScopes = data.scopes_supported;
				} else {
					this.discoveredScopes = ['openid', 'profile', 'email', 'offline_access'];
				}

				if (data.acr_values_supported) {
					this.discoveredAcrValues = data.acr_values_supported;

					// Filter out any selected items that are no longer offered by the upstream IDP
					this.selectedAcrValues = this.selectedAcrValues.filter(acr => {
						const staysSelected = this.discoveredAcrValues.includes(acr);

						// Garbage collect its independent system tuple configurations mapping if it was dropped
						if (!staysSelected && this.acrToTuple && this.acrToTuple[acr]) {
							delete this.acrToTuple[acr];
						}
						return staysSelected;
					});
				} else {
					this.discoveredAcrValues = [];
					this.selectedAcrValues = [];
					this.acrToTuple = {};
				}

				const supportedAuth = data.token_endpoint_auth_methods_supported || [];
				if (supportedAuth.length > 0 && !supportedAuth.includes(this.authMethod)) {
					if (supportedAuth.includes('client_secret_basic')) {
						this.authMethod = 'client_secret_basic';
					} else if (supportedAuth.includes('client_secret_post')) {
						this.authMethod = 'client_secret_post';
					} else if (supportedAuth.includes('none')) {
						this.authMethod = 'none';
					} else {
						this.authMethod = supportedAuth[0];
					}
				}

				this.syncComputedRules();
			},

			syncComputedRules() {
				let codeChallengeSupported = false;
				if (this.discoveryResult && this.discoveryResult.code_challenge_methods_supported) {
					codeChallengeSupported = this.discoveryResult.code_challenge_methods_supported.includes('S256');
				}

				if (this.authMethod === 'none') {
					this.pkceEnabled = true;
					this.pkceLocked = true;
				} else {
					this.pkceLocked = !codeChallengeSupported;
					if (this.pkceLocked) {
						this.pkceEnabled = codeChallengeSupported;
					}
				}

				let parSupported = false;
				if (this.discoveryResult && this.discoveryResult.pushed_authorization_request_endpoint) {
					parSupported = true;
				}

				if (this.discoveryResult && this.discoveryResult.require_pushed_authorization_requests === true) {
					this.parEnabled = true;
					this.parLocked = true;
					this.parEnforced = true;
				} else {
					this.parLocked = !parSupported;
					this.parEnforced = false;
					if (this.parLocked) {
						this.parEnabled = false;
					}
				}

				this.sloSupported = false;
				if (this.discoveryResult) {
					if (this.discoveryResult.end_session_endpoint || this.discoveryResult.backchannel_logout_supported === true) {
						this.sloSupported = true;
					}
				}
			}
		};
	});

	Alpine.data('idpRouter', (initialAllowed, availablePool, initialDefaultIdp) => ({
		allowedIds: initialAllowed || [],
		defaultId: initialDefaultIdp || '',
		available: availablePool || [],
		allowedList: [],
		isInvalidState: false,

		init() {
			this.updateAllowedList();
		},

		toggleIdp(id) {
			if (this.allowedIds.includes(id)) {
				this.allowedIds = this.allowedIds.filter(x => x !== id);
				if (this.defaultId === id) this.defaultId = '';
			} else {
				this.allowedIds.push(id);
			}
			this.updateAllowedList();
		},

		updateAllowedList() {
			let list = [];
			if (this.allowedIds.includes('username-password')) {
				list.push({ id: 'username-password', name: 'Local Accounts' });
			}
			this.available.forEach(p => {
				if (this.allowedIds.includes(p.id)) {
					list.push({ id: p.id, name: p.name });
				}
			});
			this.allowedList = list;
			this.isInvalidState = (this.allowedIds.length === 0);

			this.$dispatch('idp-count-update', { count: this.allowedIds.length });
		}
	}));

	// 4. CSP-Compliant Single URI Input Validator
	Alpine.data('uriValidator', () => ({
		value: '',
		error: '',
		init() {
			this.value = this.$el.dataset.initialValue || '';
		},
		validate() {
			const trimmed = this.value.trim();
			if (!trimmed) {
				this.error = '';
				return;
			}
			if (!trimmed.includes('://')) {
				this.error = 'Invalid URL format (must include protocol like http:// or https://)';
			} else {
				this.error = '';
			}
		}
	}));

	// Root state of the admin shell. The active navigation key arrives as a data attribute.
	Alpine.data('adminShell', () => ({
		mobileMenu: false,
		modalOpen: false,
		currentTab: '',
		init() {
			this.currentTab = this.$el.dataset.currentTab || '';
		}
	}));

	// 5. CSP-Compliant Modal Controller
	Alpine.data('modalController', () => ({
		isOpen: true,
		init() {
			this.$dispatch('modal-open');
		},
		close() {
			this.isOpen = false;
			window.setTimeout(purgeModal, 200, this.$el);
		}
	}));

	// 6. CSP-Compliant Async ID & Secret Generator
	Alpine.data('idSecretGenerator', () => ({
		value: '',
		showSecret: false,
		init() {
			this.value = this.$el.dataset.initialValue || '';
		},
		generate() {
			window.fetch('/admin/applications/generate-secret')
				.then(response => response.text())
				.then(text => {
					this.value = text;
				});
		},
		toggleShow() {
			this.showSecret = !this.showSecret;
		}
	}));
});
