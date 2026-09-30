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

	// Hypermedia semantic error statuses: htmx discards non-2xx responses unless told otherwise, and the decision
	// lives in htmx:beforeSwap. Validation failures (422) and section fragments flagged by the server are swapped in.
	document.body.addEventListener('htmx:beforeSwap', function (evt) {
		const xhr = evt.detail.xhr;
		if (xhr.status === 422 || xhr.getResponseHeader('X-Admin-Fragment') === 'true') {
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
				this.$dispatch('input');
			} catch (e) {
				this.error = 'Invalid URL format (must include protocol like http:// or https://)';
			}
		},
		removeUrl(index) {
			this.urls.splice(index, 1);
			this.$dispatch('input');
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
			this.$dispatch('input');
		},
		removeUrl(index) {
			const removed = this.urls[index];
			this.urls.splice(index, 1);
			if (this.defaultUrl === removed) {
				this.defaultUrl = this.urls[0] || '';
			}
			this.$dispatch('input');
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
			this.$dispatch('input');
		},
		removeTag(index) {
			this.tags.splice(index, 1);
			this.$dispatch('input');
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

	// Tracks whether a section form has unsaved edits. List editors dispatch a bubbling 'input' event.
	Alpine.data('sectionForm', () => ({
		dirty: false,
		markDirty() {
			this.dirty = true;
		}
	}));

	// Allowed scopes with a per-scope default flag. Values arrive as data attributes.
	Alpine.data('scopePicker', () => ({
		allowed: [],
		defaults: [],
		suggestions: [],
		newScope: '',
		error: '',
		init() {
			this.allowed = this.readList('allowed');
			this.defaults = this.readList('defaults');
			this.suggestions = this.readList('suggestions');
		},
		readList(name) {
			try {
				return JSON.parse(this.$el.dataset[name] || '[]') || [];
			} catch (e) {
				return [];
			}
		},
		isDefault(scope) {
			return this.defaults.includes(scope);
		},
		toggleDefault(scope) {
			if (this.defaults.includes(scope)) {
				this.defaults = this.defaults.filter(s => s !== scope);
			} else {
				this.defaults.push(scope);
			}
			this.$dispatch('input');
		},
		addScope() {
			this.error = '';
			const value = this.newScope.trim();
			if (!value) return;
			if (/\s/.test(value)) {
				this.error = 'A scope cannot contain spaces';
				return;
			}
			if (this.allowed.includes(value)) {
				this.error = 'Scope already added';
				return;
			}
			this.allowed.push(value);
			this.newScope = '';
			this.$dispatch('input');
		},
		addSuggestion(scope) {
			if (!this.allowed.includes(scope)) {
				this.allowed.push(scope);
				this.$dispatch('input');
			}
		},
		removeScope(scope) {
			this.allowed = this.allowed.filter(s => s !== scope);
			this.defaults = this.defaults.filter(s => s !== scope);
			this.$dispatch('input');
		},
		get unusedSuggestions() {
			return this.suggestions.filter(s => !this.allowed.includes(s));
		}
	}));

	// Enables a destructive button only while the typed text equals the expected value (server re-checks it).
	Alpine.data('typedConfirm', () => ({
		expected: '',
		typed: '',
		init() {
			this.expected = this.$el.dataset.expected || '';
		},
		get matches() {
			return this.expected !== '' && this.typed === this.expected;
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
