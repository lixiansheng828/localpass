/**
 * LocalPass - 内容脚本
 * 版本：2.0.0
 */

(function () {
    'use strict';

    // ==================== 常量定义 ====================
    const PANEL_ID = 'lpcrx-panel';
    const NOTIFICATION_DURATION = 3000;

    const STORAGE_KEYS = {
        PASSWORDS: 'passwords',
        MASTER: 'master',
        SETTINGS: 'settings'
    };

    const DEFAULT_SETTINGS = {
        clickCount: 5,
        clickInterval: 300,
        maxClickCount: 10,
        pbkdf2Iterations: 200000,
        minPasswordLength: 4,
        autoClosePanel: true,
        showSuccessNotifications: true,
        panelMaxHeight: 260,
        panelWidth: 280
    };

    const REGEX = {
        PASSWORD_REPEAT: /(.)\1{2,}/,
        COMMON_PATTERNS: /123|abc|qwert|asdf|zxcv/i,
        USERNAME_FIELDS: /user|email|login|账户|账号|名/i
    };

    // ==================== 日志工具 ====================
    const Logger = {
        log(...args) { console.log('[LocalPass:Content]', ...args); },
        warn(...args) { console.warn('[LocalPass:Content] ⚠️', ...args); },
        error(...args) { console.error('[LocalPass:Content] ❌', ...args); },
        debug(...args) { console.debug('[LocalPass:Content] 🔍', ...args); }
    };

    // ==================== Base64 编解码 ====================
    const Base64 = {
        fromBuffer(buf) {
            return btoa(String.fromCharCode(...new Uint8Array(buf)));
        },
        toBuffer(s) {
            return Uint8Array.from(atob(s), c => c.charCodeAt(0));
        }
    };

    // ==================== 错误处理 ====================
    const ErrorHandler = {
        showNotification(message, type = 'error') {
            if (!document?.body) return;

            const existing = document.querySelector('.localpass-notification');
            if (existing) existing.remove();

            const notification = document.createElement('div');
            notification.className = 'localpass-notification';
            notification.textContent = type === 'success' ? `✅ ${message}` : `❌ ${message}`;
            notification.style.cssText = `
        position: fixed; top: 20px; right: 20px; z-index: 2147483647;
        background: ${type === 'success' ? '#d4edda' : '#f8d7da'};
        color: ${type === 'success' ? '#155724' : '#721c24'};
        padding: 12px 20px; border-radius: 6px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        font-size: 14px; font-family: sans-serif;
        border: 1px solid ${type === 'success' ? '#c3e6cb' : '#f5c6cb'};
        animation: slideIn 0.3s ease;
        max-width: 300px; word-break: break-word;
      `;

            if (!document.querySelector('#localpass-animation')) {
                const style = document.createElement('style');
                style.id = 'localpass-animation';
                style.textContent = `
          @keyframes slideIn {
            from { opacity: 0; transform: translateX(20px); }
            to { opacity: 1; transform: translateX(0); }
          }
        `;
                document.head.appendChild(style);
            }

            document.body.appendChild(notification);
            setTimeout(() => notification.remove(), NOTIFICATION_DURATION);
        }
    };

    // ==================== 存储管理 ====================
    const StorageManager = {
        async get(keys) {
            try {
                if (!chrome.runtime?.id) return {};
                return await chrome.storage.local.get(keys);
            } catch {
                return {};
            }
        },
        async set(data) {
            try {
                if (!chrome.runtime?.id) return;
                await chrome.storage.local.set(data);
            } catch (error) {
                Logger.error('存储失败', error);
            }
        },
        invalidate() { }
    };

    // ==================== 加密工具 ====================
    const CryptoService = {
        encoder: new TextEncoder(),
        decoder: new TextDecoder(),

        async deriveKey(password, salt, iterations = DEFAULT_SETTINGS.pbkdf2Iterations) {
            const baseKey = await crypto.subtle.importKey(
                'raw',
                this.encoder.encode(String(password || '')),
                { name: 'PBKDF2' },
                false,
                ['deriveKey']
            );

            return crypto.subtle.deriveKey(
                {
                    name: 'PBKDF2',
                    salt: salt instanceof Uint8Array ? salt : new Uint8Array(salt),
                    iterations,
                    hash: 'SHA-256'
                },
                baseKey,
                { name: 'AES-GCM', length: 256 },
                false,
                ['encrypt', 'decrypt']
            );
        },

        async encrypt(key, plaintext) {
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const ciphertext = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv },
                key,
                this.encoder.encode(plaintext)
            );
            return {
                iv: Base64.fromBuffer(iv),
                data: Base64.fromBuffer(ciphertext)
            };
        },

        async decrypt(key, iv_b64, data_b64) {
            const iv = Base64.toBuffer(iv_b64);
            const ciphertext = Base64.toBuffer(data_b64);
            const plaintext = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv },
                key,
                ciphertext
            );
            return this.decoder.decode(plaintext);
        },

        async verifyMaster(password, masterInfo) {
            if (!masterInfo || masterInfo.empty) return true;
            try {
                const salt = Base64.toBuffer(masterInfo.salt);
                const key = await this.deriveKey(password, salt, masterInfo.iterations);
                await this.decrypt(key, masterInfo.verifier.iv, masterInfo.verifier.data);
                return true;
            } catch {
                return false;
            }
        },

        async getDecryptionKey(masterInfo, masterPassword = null) {
            if (!masterInfo) return null;
            if (masterInfo.empty) return { key: null, empty: true, cancelled: false };

            const saltBytes = Base64.toBuffer(masterInfo.salt);
            const iterations = masterInfo.iterations || DEFAULT_SETTINGS.pbkdf2Iterations;

            if (!masterPassword) {
                masterPassword = prompt('请输入主密码以继续：');
                if (!masterPassword) return { cancelled: true };
            }

            const isValid = await this.verifyMaster(masterPassword, masterInfo);
            if (!isValid) throw new Error('主密码错误');

            const baseKey = await crypto.subtle.importKey(
                'raw',
                this.encoder.encode(masterPassword),
                { name: 'PBKDF2' },
                false,
                ['deriveKey']
            );

            return { key: baseKey, iterations, empty: false, cancelled: false };
        }
    };

    // ==================== 配置管理 ====================
    const ConfigManager = {
        settings: { ...DEFAULT_SETTINGS },

        async load() {
            try {
                const storage = await StorageManager.get([STORAGE_KEYS.SETTINGS]);
                if (storage.settings) {
                    this.settings = { ...DEFAULT_SETTINGS, ...storage.settings };
                }
                Logger.log('配置已加载', this.settings);
            } catch (error) {
                Logger.error('加载配置失败', error);
            }
        },

        get(key) {
            return this.settings[key] ?? DEFAULT_SETTINGS[key];
        }
    };

    // ==================== 面板UI ====================
    const PanelUI = {
        panel: null,
        activeInput: null,

        create() {
            if (this.panel?.isConnected) {
                this.panel.remove();
                this.panel = null;
            }

            const panel = document.createElement('div');
            panel.id = PANEL_ID;
            panel.style.cssText = `
        position: absolute; z-index: 2147483647; background: white;
        border: 1px solid #e2e8f0; padding: 12px; box-shadow: 0 8px 24px rgba(0,0,0,0.12);
        font-size: 13px; border-radius: 12px; min-width: 240px;
        max-width: ${ConfigManager.get('panelWidth')}px;
        max-height: ${ConfigManager.get('panelMaxHeight')}px;
        overflow-y: auto; font-family: -apple-system, BlinkMacSystemFont, sans-serif;
        line-height: 1.5; color: #2d3748;
      `;

            ['click', 'mousedown', 'mouseup'].forEach(event => {
                panel.addEventListener(event, e => e.stopPropagation());
            });

            const closeHandler = (e) => {
                if (this.panel && !this.panel.contains(e.target) &&
                    !e.target.closest?.('input[type=password]')) {
                    this.hide();
                }
            };
            panel._closeHandler = closeHandler;
            document.addEventListener('click', closeHandler);
            document.addEventListener('scroll', () => this.hide(), { once: true });

            this.panel = panel;
            document.body.appendChild(panel);
            return panel;
        },

        hide() { if (this.panel) this.panel.style.display = 'none'; },

        remove() {
            if (this.panel) {
                document.removeEventListener('click', this.panel._closeHandler);
                this.panel.remove();
                this.panel = null;
            }
        },

        position(input) {
            if (!this.panel || !input) return;

            const rect = input.getBoundingClientRect();
            const panelRect = this.panel.getBoundingClientRect();
            const scrollX = window.scrollX || window.pageXOffset;
            const scrollY = window.scrollY || window.pageYOffset;

            let left = rect.left + scrollX;
            let top = rect.bottom + scrollY + 8;

            if (left + panelRect.width > scrollX + window.innerWidth) {
                left = scrollX + window.innerWidth - panelRect.width - 16;
            }
            left = Math.max(scrollX + 16, left);

            if (top + panelRect.height > scrollY + window.innerHeight) {
                top = rect.top + scrollY - panelRect.height - 8;
            }
            top = Math.max(scrollY + 16, top);

            this.panel.style.left = `${left}px`;
            this.panel.style.top = `${top}px`;
        },

        async render(input) {
            if (!input) return;

            this.activeInput = input;
            const panel = this.create();
            if (!panel) return;

            panel.innerHTML = '<div style="text-align: center; padding: 20px; color: #718096;">⏳ 加载中...</div>';
            this.position(input);
            panel.style.display = 'block';

            try {
                const origin = window.location.origin;
                const storage = await StorageManager.get([STORAGE_KEYS.PASSWORDS, STORAGE_KEYS.MASTER]);
                const entries = storage.passwords?.[origin] || [];
                await this.renderContent(panel, input, origin, entries, storage.master);
            } catch (error) {
                Logger.error('渲染面板失败', error);
                panel.innerHTML = `
          <div style="padding: 20px; text-align: center;">
            <div style="font-size: 32px; margin-bottom: 12px;">❌</div>
            <div style="font-size: 12px; color: #718096;">加载失败</div>
          </div>
        `;
            }
        },

        async renderContent(panel, input, origin, entries, masterInfo) {
            panel.innerHTML = '';

            if (input.value) {
                const saveSection = this.renderSaveSection(input, origin, masterInfo);
                if (saveSection) panel.appendChild(saveSection);
            }

            if (entries.length > 0) {
                if (input.value) panel.appendChild(this.renderDivider());
                const listSection = await this.renderEntriesList(entries, origin, masterInfo);
                if (listSection) panel.appendChild(listSection);
            }

            if (!input.value && entries.length === 0) {
                panel.appendChild(this.renderEmptyState());
            }

            panel.appendChild(this.renderFooter());
            this.position(input);
        },

        renderSaveSection(input, origin, masterInfo) {
            const section = document.createElement('div');
            section.style.marginBottom = '12px';

            const title = document.createElement('div');
            title.textContent = '💾 保存新密码';
            title.style.cssText = 'font-weight: 600; margin-bottom: 8px; color: #2d3748;';
            section.appendChild(title);

            const btn = document.createElement('button');
            btn.textContent = '保存当前密码';
            btn.style.cssText = `
        width: 100%; padding: 10px 12px; 
        background: linear-gradient(135deg, #4299e1 0%, #3182ce 100%);
        color: white; border: none; border-radius: 8px; font-size: 13px;
        font-weight: 500; cursor: pointer;
      `;
            btn.onclick = (e) => {
                e.stopPropagation();
                this.handleSave(input, origin, masterInfo);
            };
            section.appendChild(btn);
            return section;
        },

        async handleSave(input, origin, masterInfo) {
            try {
                const label = prompt('添加标签：', '')?.trim();
                if (label === undefined) return;

                let username = this.guessUsername(input);
                if (!username) {
                    username = prompt('输入账号：', '')?.trim();
                    if (username === undefined) return;
                }

                let masterResult = { empty: true, key: null, cancelled: false };
                if (masterInfo && !masterInfo.empty) {
                    masterResult = await CryptoService.getDecryptionKey(masterInfo);
                    if (masterResult.cancelled) return;
                }

                let entryData;
                if (masterInfo && !masterInfo.empty) {
                    const entrySalt = crypto.getRandomValues(new Uint8Array(16));
                    const key = await CryptoService.deriveKey(
                        masterResult.key,
                        entrySalt,
                        masterInfo.iterations || DEFAULT_SETTINGS.pbkdf2Iterations
                    );
                    const enc = await CryptoService.encrypt(key, input.value);
                    entryData = {
                        iv: enc.iv,
                        data: enc.data,
                        salt: Base64.fromBuffer(entrySalt)
                    };
                } else {
                    entryData = { plain: input.value };
                }

                await this.saveEntry(origin, {
                    id: `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
                    username: username || '',
                    label: label || '',
                    ...entryData,
                    createdAt: Date.now(),
                    lastUsed: Date.now()
                });

                ErrorHandler.showNotification('密码已保存', 'success');
                this.hide();
            } catch (error) {
                Logger.error('保存失败', error);
                ErrorHandler.showNotification(`保存失败`, 'error');
            }
        },

        async saveEntry(origin, entry) {
            const storage = await StorageManager.get([STORAGE_KEYS.PASSWORDS]);
            const passwords = storage.passwords || {};
            passwords[origin] = passwords[origin] || [];
            passwords[origin].push(entry);
            await StorageManager.set({ [STORAGE_KEYS.PASSWORDS]: passwords });
        },

        async renderEntriesList(entries, origin, masterInfo) {
            const container = document.createElement('div');

            const header = document.createElement('div');
            header.style.cssText = `
        display: flex; justify-content: space-between; align-items: center;
        margin-bottom: 8px; font-weight: 600; color: #2d3748;
      `;
            header.innerHTML = `
        <span>📋 已保存凭据</span>
        <span style="background: #e2e8f0; padding: 2px 8px; border-radius: 12px; font-size: 11px;">
          ${entries.length}
        </span>
      `;
            container.appendChild(header);

            const sorted = [...entries].sort((a, b) =>
                (b.lastUsed || b.createdAt || 0) - (a.lastUsed || a.createdAt || 0)
            );

            for (const entry of sorted) {
                const item = this.renderEntryItem(entry, origin, masterInfo);
                if (item) container.appendChild(item);
            }

            return container;
        },

        renderEntryItem(entry, origin, masterInfo) {
            const item = document.createElement('div');
            item.style.cssText = `
        display: flex; justify-content: space-between; align-items: center;
        padding: 10px; margin-bottom: 6px; background: #f7fafc;
        border-radius: 8px;
      `;

            const info = document.createElement('div');
            info.style.cssText = 'flex: 1; min-width: 0;';
            info.innerHTML = `
        <div style="font-weight: 600; font-size: 13px; color: #2d3748; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
          ${this.escapeHtml(entry.label || '无标签')}
        </div>
        <div style="font-size: 11px; color: #718096; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
          ${this.escapeHtml(entry.username || '无账号')}
        </div>
      `;

            const actions = document.createElement('div');
            actions.style.cssText = 'display: flex; gap: 4px;';
            actions.innerHTML = `
        <button class="fill-btn" style="padding: 6px 10px; background: #4299e1; color: white; border: none; border-radius: 6px; font-size: 11px; cursor: pointer;">
          🔓 填充
        </button>
        <button class="delete-btn" style="padding: 6px 8px; background: white; border: 1px solid #e2e8f0; border-radius: 6px; font-size: 11px; cursor: pointer;">
          🗑️
        </button>
      `;

            actions.querySelector('.fill-btn').onclick = (e) => {
                e.stopPropagation();
                this.handleFill(entry, masterInfo, origin);
            };

            actions.querySelector('.delete-btn').onclick = (e) => {
                e.stopPropagation();
                if (confirm('确定删除此凭据？')) {
                    this.deleteEntry(origin, entry.id);
                }
            };

            item.appendChild(info);
            item.appendChild(actions);
            return item;
        },

        escapeHtml(text) {
            if (!text) return '';
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        },

        async handleFill(entry, masterInfo, origin) {
            try {
                let password;

                if (entry.plain !== undefined) {
                    password = entry.plain;
                } else {
                    let masterResult = { empty: true, key: null, cancelled: false };
                    if (masterInfo && !masterInfo.empty) {
                        masterResult = await CryptoService.getDecryptionKey(masterInfo);
                        if (masterResult.cancelled) return;
                    }

                    const saltBytes = entry.salt ?
                        Base64.toBuffer(entry.salt) :
                        Base64.toBuffer(masterInfo.salt);
                    const iterations = masterInfo.iterations || DEFAULT_SETTINGS.pbkdf2Iterations;

                    const key = await CryptoService.deriveKey(
                        masterResult.empty ? '' : masterResult.key,
                        saltBytes,
                        iterations
                    );
                    password = await CryptoService.decrypt(key, entry.iv, entry.data);
                }

                if (password) {
                    this.fillCredentials(this.activeInput, entry.username, password);
                    await this.updateEntryLastUsed(entry.id, origin);

                    if (ConfigManager.get('autoClosePanel')) {
                        this.hide();
                    }
                }
            } catch (error) {
                Logger.error('填充失败', error);
                ErrorHandler.showNotification('填充失败', 'error');
            }
        },

        async updateEntryLastUsed(entryId, origin) {
            const storage = await StorageManager.get([STORAGE_KEYS.PASSWORDS]);
            const entry = storage.passwords?.[origin]?.find(e => e.id === entryId);
            if (entry) {
                entry.lastUsed = Date.now();
                await StorageManager.set({ [STORAGE_KEYS.PASSWORDS]: storage.passwords });
            }
        },

        async deleteEntry(origin, id) {
            const storage = await StorageManager.get([STORAGE_KEYS.PASSWORDS]);
            if (!storage.passwords?.[origin]) return;

            storage.passwords[origin] = storage.passwords[origin].filter(e => e.id !== id);
            if (storage.passwords[origin].length === 0) {
                delete storage.passwords[origin];
            }

            await StorageManager.set({ [STORAGE_KEYS.PASSWORDS]: storage.passwords });
            ErrorHandler.showNotification('已删除', 'success');
            this.render(this.activeInput);
        },

        fillCredentials(passwordInput, username, password) {
            if (!passwordInput) return;

            const fillInput = (input, value) => {
                if (!input) return;
                input.value = value;
                ['input', 'change', 'blur'].forEach(eventType => {
                    input.dispatchEvent(new Event(eventType, { bubbles: true }));
                });
            };

            if (username) {
                const usernameEl = this.findUsernameField(passwordInput);
                fillInput(usernameEl, username);
            }
            fillInput(passwordInput, password);
        },

        findUsernameField(passwordInput) {
            if (!passwordInput) return null;

            if (passwordInput.form) {
                const candidates = Array.from(passwordInput.form.querySelectorAll(
                    'input[type=text], input[type=email], input[name*="user"], input[name*="email"], input[name*="login"]'
                )).filter(el => el !== passwordInput && el.type !== 'password');
                if (candidates.length) return candidates[0];
            }

            let parent = passwordInput.parentElement;
            for (let i = 0; i < 5 && parent; i++) {
                const input = parent.querySelector('input[type=text], input[type=email]');
                if (input && input !== passwordInput) return input;
                parent = parent.parentElement;
            }

            return null;
        },

        guessUsername(input) {
            return this.findUsernameField(input)?.value || '';
        },

        renderDivider() {
            const hr = document.createElement('hr');
            hr.style.cssText = 'margin: 12px 0; border: none; border-top: 1px solid #e2e8f0;';
            return hr;
        },

        renderEmptyState() {
            const div = document.createElement('div');
            div.style.cssText = `
        display: flex; flex-direction: column; align-items: center;
        padding: 24px 16px; color: #a0aec0; text-align: center;
      `;
            div.innerHTML = `
        <div style="font-size: 32px; margin-bottom: 8px;">🔍</div>
        <div style="font-size: 13px;">此站点无保存的凭据</div>
        <div style="font-size: 11px; margin-top: 4px;">输入密码后点击保存按钮</div>
      `;
            return div;
        },

        renderFooter() {
            const footer = document.createElement('div');
            footer.style.cssText = `
        margin-top: 12px; padding-top: 8px; border-top: 1px solid #e2e8f0;
        font-size: 10px; color: #a0aec0; display: flex; justify-content: space-between;
      `;
            footer.innerHTML = `
        <span>LocalPass</span>
        <span>连续点击 ${ConfigManager.get('clickCount')} 次打开</span>
      `;
            return footer;
        }
    };

    // ==================== 点击检测 ====================
    const ClickDetector = {
        state: { count: 0, target: null, timer: null, lastTime: 0 },

        init() {
            document.addEventListener('click', this.handleClick.bind(this), true);
        },

        handleClick(e) {
            const input = this.getPasswordInput(e);
            if (!input) return;

            const now = Date.now();
            const settings = ConfigManager.settings;

            if (this.state.target !== input || (now - this.state.lastTime) > settings.clickInterval) {
                this.reset();
                this.state.target = input;
                this.state.count = 1;
            } else {
                this.state.count = Math.min(this.state.count + 1, settings.maxClickCount);
            }

            this.state.lastTime = now;

            clearTimeout(this.state.timer);
            this.state.timer = setTimeout(() => this.reset(), settings.clickInterval + 100);

            if (this.state.count === settings.clickCount) {
                PanelUI.render(input);
                this.reset();
            }
        },

        getPasswordInput(e) {
            if (e.target?.tagName === 'INPUT' && e.target.type === 'password') return e.target;
            let el = e.target;
            while (el) {
                if (el.tagName === 'INPUT' && el.type === 'password') return el;
                el = el.parentElement;
            }
            return null;
        },

        reset() {
            this.state.count = 0;
            this.state.target = null;
            clearTimeout(this.state.timer);
            this.state.timer = null;
        }
    };

    // ==================== 消息监听 ====================
    const initMessageListeners = () => {
        if (!chrome.runtime?.onMessage) return;

        chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
            if (sender?.id !== chrome.runtime?.id) return false;

            switch (msg?.action) {
                case 'settingsUpdated':
                    ConfigManager.settings = { ...DEFAULT_SETTINGS, ...msg.settings };
                    sendResponse({ ok: true });
                    break;

                case 'fillPassword':
                    const input = document.activeElement?.type === 'password'
                        ? document.activeElement
                        : document.querySelector('input[type="password"]');
                    if (input) {
                        PanelUI.fillCredentials(input, msg.username, msg.password);
                        sendResponse({ ok: true });
                    } else {
                        sendResponse({ ok: false, error: '未找到密码输入框' });
                    }
                    return true;

                case 'ping':
                case 'extensionReady':
                    sendResponse({ ok: true });
                    break;
            }
            return false;
        });
    };

    // ==================== 初始化 ====================
    const init = async () => {
        try {
            await ConfigManager.load();
            ClickDetector.init();
            initMessageListeners();
            window.addEventListener('beforeunload', () => PanelUI.remove());
            Logger.log('内容脚本已初始化');
        } catch (error) {
            Logger.error('初始化失败', error);
        }
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();