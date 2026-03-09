/**
 * LocalPass - 设置页面脚本
 * 版本：2.0.0
 */

(function () {
    'use strict';

    // ==================== DOM 元素 ====================
    const DOM = {
        clickCount: document.getElementById('clickCount'),
        clickInterval: document.getElementById('clickInterval'),
        maxClickCount: document.getElementById('maxClickCount'),
        pbkdf2Iterations: document.getElementById('pbkdf2Iterations'),
        minPasswordLength: document.getElementById('minPasswordLength'),
        masterPasswordWarning: document.getElementById('masterPasswordWarning'),
        autoClosePanel: document.getElementById('autoClosePanel'),
        showSuccessNotifications: document.getElementById('showSuccessNotifications'),
        panelMaxHeight: document.getElementById('panelMaxHeight'),
        panelWidth: document.getElementById('panelWidth'),
        saveButton: document.getElementById('saveSettings'),
        resetButton: document.getElementById('resetSettings'),
        status: document.getElementById('status'),
        masterInput: document.getElementById('masterInput'),
        setMasterBtn: document.getElementById('setMasterBtn'),
        masterDot: document.getElementById('masterDot'),
        masterStatusText: document.getElementById('masterStatusText'),
        passwordStrengthContainer: document.getElementById('passwordStrengthContainer')
    };

    // ==================== 常量 ====================
    const STORAGE_KEYS = {
        SETTINGS: 'settings',
        MASTER: 'master',
        PASSWORDS: 'passwords'
    };

    const DEFAULT_SETTINGS = {
        clickCount: 5,
        clickInterval: 300,
        maxClickCount: 10,
        pbkdf2Iterations: 200000,
        minPasswordLength: 4,
        masterPasswordWarning: true,
        autoClosePanel: true,
        showSuccessNotifications: true,
        panelMaxHeight: 260,
        panelWidth: 280
    };

    const VALIDATION = {
        clickCount: { min: 2, max: 10, message: '点击次数必须在2-10之间' },
        clickInterval: { min: 100, max: 1000, message: '点击间隔必须在100-1000毫秒之间' },
        maxClickCount: { min: 5, max: 20, message: '最大点击次数必须在5-20之间' },
        pbkdf2Iterations: { min: 100000, max: 500000, message: '迭代次数必须在10万-50万之间' },
        minPasswordLength: { min: 1, max: 20, message: '最小密码长度必须在1-20之间' },
        panelMaxHeight: { min: 200, max: 500, message: '面板最大高度必须在200-500px之间' },
        panelWidth: { min: 200, max: 400, message: '面板宽度必须在200-400px之间' }
    };

    // ==================== 日志工具 ====================
    const Logger = {
        log(...args) { console.log('[LocalPass:Settings]', ...args); },
        error(...args) { console.error('[LocalPass:Settings] ❌', ...args); }
    };

    // ==================== Base64 工具 ====================
    const Base64 = {
        fromBuffer(buf) {
            return btoa(String.fromCharCode(...new Uint8Array(buf)));
        },
        toBuffer(s) {
            return Uint8Array.from(atob(s), c => c.charCodeAt(0));
        }
    };

    // ==================== 存储管理 ====================
    const StorageManager = {
        async get(keys) {
            try {
                return await chrome.storage.local.get(keys);
            } catch {
                return {};
            }
        },
        async set(data) {
            try {
                await chrome.storage.local.set(data);
            } catch (error) {
                Logger.error('存储失败', error);
            }
        }
    };

    // ==================== 加密服务 ====================
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

        async reencryptAll(passwords, oldPassword, newPassword, oldMasterInfo) {
            const results = { success: 0, failed: 0, total: 0 };
            if (!oldMasterInfo) return results;

            for (const origin of Object.keys(passwords || {})) {
                for (const entry of passwords[origin] || []) {
                    results.total++;
                    try {
                        let plain = null;

                        if (entry.plain !== undefined) {
                            plain = entry.plain;
                        } else if (entry.iv && entry.data) {
                            const saltBytes = entry.salt ? Base64.toBuffer(entry.salt) : Base64.toBuffer(oldMasterInfo.salt);
                            const key = await this.deriveKey(oldPassword || '', saltBytes, oldMasterInfo.iterations);
                            plain = await this.decrypt(key, entry.iv, entry.data);
                        }

                        if (plain !== null) {
                            if (newPassword === '' && oldMasterInfo && !oldMasterInfo.empty) {
                                entry.plain = plain;
                                delete entry.iv;
                                delete entry.data;
                                delete entry.salt;
                            } else {
                                const entrySalt = crypto.getRandomValues(new Uint8Array(16));
                                const key = await this.deriveKey(newPassword, entrySalt);
                                const enc = await this.encrypt(key, plain);
                                entry.iv = enc.iv;
                                entry.data = enc.data;
                                entry.salt = Base64.fromBuffer(entrySalt);
                                delete entry.plain;
                            }
                            results.success++;
                        } else {
                            results.failed++;
                        }
                    } catch {
                        results.failed++;
                    }
                }
            }
            return results;
        }
    };

    // ==================== 密码强度 ====================
    const PasswordStrength = {
        check(password) {
            if (!password) return { score: 0, level: '很弱', color: '#dc3545', width: '10%' };

            let score = 0;
            const len = password.length;

            if (len >= 8) score += 25;
            if (len >= 12) score += 15;
            if (len >= 16) score += 10;
            if (/[a-z]/.test(password)) score += 10;
            if (/[A-Z]/.test(password)) score += 10;
            if (/[0-9]/.test(password)) score += 10;
            if (/[^a-zA-Z0-9]/.test(password)) score += 15;
            if (len < 4) score = 0;

            score = Math.min(100, score);
            if (score >= 80) return { score, level: '很强', color: '#28a745', width: '100%' };
            if (score >= 60) return { score, level: '强', color: '#17a2b8', width: '75%' };
            if (score >= 40) return { score, level: '中等', color: '#ffc107', width: '50%' };
            if (score >= 20) return { score, level: '弱', color: '#fd7e14', width: '25%' };
            return { score, level: '很弱', color: '#dc3545', width: '10%' };
        },

        render(password, container) {
            if (!container) return;
            const result = this.check(password);
            container.innerHTML = `
                <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">
                    <div style="flex: 1; height: 6px; background: #e9ecef; border-radius: 3px; overflow: hidden;">
                        <div style="height: 100%; width: ${result.width}; background: ${result.color};"></div>
                    </div>
                    <span style="font-size: 12px; color: ${result.color}; font-weight: 600;">${result.level}</span>
                </div>
            `;
        }
    };

    // ==================== 主密码管理 ====================
    const MasterManager = {
        async loadStatus() {
            const storage = await StorageManager.get([STORAGE_KEYS.MASTER]);
            const master = storage.master;

            if (!DOM.masterStatusText || !DOM.masterDot) return;

            if (!master) {
                DOM.masterStatusText.textContent = '未设置主密码';
                DOM.masterDot.className = 'status-dot';
                DOM.masterDot.style.background = '';
            } else if (master.empty) {
                DOM.masterStatusText.textContent = '当前使用空密码（明文存储）';
                DOM.masterDot.className = 'status-dot empty';
                DOM.masterDot.style.background = '#17a2b8';
            } else {
                DOM.masterStatusText.textContent = '已设置主密码';
                DOM.masterDot.className = 'status-dot set';
                DOM.masterDot.style.background = '#28a745';
            }
        },

        async handleSetMaster() {
            if (!DOM.masterInput) return;
            const password = DOM.masterInput.value;

            try {
                const storage = await StorageManager.get([STORAGE_KEYS.MASTER, STORAGE_KEYS.PASSWORDS]);
                const master = storage.master;

                if (!master) {
                    await this.firstTimeSetup(password);
                } else {
                    await this.changePassword(password, master, storage.passwords);
                }

                DOM.masterInput.value = '';
                PasswordStrength.render('', DOM.passwordStrengthContainer);
                await this.loadStatus();
                SettingsManager.showStatus('主密码设置成功', 'success');
            } catch (error) {
                if (error.message !== '已取消') {
                    SettingsManager.showStatus(error.message || '操作失败', 'error');
                }
            }
        },

        async firstTimeSetup(password) {
            // 首次设置主密码
            if (password === '') {
                if (!confirm('⚠️ 确定不设置主密码？\n密码将以明文存储，不再加密。')) {
                    throw new Error('已取消');
                }
                // 设置空密码模式
                await StorageManager.set({ [STORAGE_KEYS.MASTER]: { empty: true } });
                return;
            }

            // 验证密码长度
            if (password.length < DEFAULT_SETTINGS.minPasswordLength) {
                throw new Error(`密码长度不能少于 ${DEFAULT_SETTINGS.minPasswordLength} 个字符`);
            }

            // 确认密码
            const confirmPassword = prompt('请再次输入主密码以确认:');
            if (confirmPassword === null) throw new Error('已取消');
            if (confirmPassword !== password) throw new Error('两次输入的密码不一致');

            // 密码强度检查
            const strength = PasswordStrength.check(password);
            if (strength.score < 40) {
                if (!confirm(`密码强度为"${strength.level}"，仍要继续吗？`)) {
                    throw new Error('已取消');
                }
            }

            // 创建主密码
            const salt = crypto.getRandomValues(new Uint8Array(16));
            const key = await CryptoService.deriveKey(password, salt);
            const verifier = await CryptoService.encrypt(key, 'verifier');

            await StorageManager.set({
                [STORAGE_KEYS.MASTER]: {
                    salt: Base64.fromBuffer(salt),
                    iterations: DEFAULT_SETTINGS.pbkdf2Iterations,
                    verifier,
                    empty: false
                }
            });
        },

        async changePassword(oldPassword, masterInfo, passwords) {
            // 验证旧密码
            const isValid = masterInfo.empty ? true : await CryptoService.verifyMaster(oldPassword, masterInfo);
            if (!isValid) throw new Error('当前主密码错误');

            // 获取新密码
            const newPassword = prompt('请输入新主密码（留空以移除主密码）:');
            if (newPassword === null) throw new Error('已取消');

            // 处理移除主密码
            if (newPassword === '') {
                if (!masterInfo.empty) {
                    const confirmRemove = confirm(
                        '⚠️ 您正在**完全移除**主密码！\n\n' +
                        '此操作将：\n' +
                        '• 所有已保存的密码转为明文存储\n' +
                        '• 不再需要密码验证即可填充\n' +
                        '• 安全性显著降低\n\n' +
                        '是否继续？'
                    );
                    if (!confirmRemove) throw new Error('已取消');
                }
            } else {
                // 验证新密码长度
                if (newPassword.length < DEFAULT_SETTINGS.minPasswordLength) {
                    throw new Error(`密码长度不能少于 ${DEFAULT_SETTINGS.minPasswordLength} 个字符`);
                }

                // 确认新密码
                const confirmPassword = prompt('请再次输入新主密码以确认:');
                if (confirmPassword === null) throw new Error('已取消');
                if (confirmPassword !== newPassword) throw new Error('两次输入的密码不一致');

                // 密码强度检查
                const strength = PasswordStrength.check(newPassword);
                if (strength.score < 40) {
                    if (!confirm(`密码强度为"${strength.level}"，仍要继续吗？`)) {
                        throw new Error('已取消');
                    }
                }
            }

            // 重新加密所有密码
            if (Object.keys(passwords || {}).length > 0) {
                const results = await CryptoService.reencryptAll(
                    passwords,
                    masterInfo.empty ? '' : oldPassword,
                    newPassword || '',
                    masterInfo
                );
                await StorageManager.set({ [STORAGE_KEYS.PASSWORDS]: passwords });
                Logger.log(`重新加密完成: ${results.success}/${results.total}`);
            }

            // 更新主密码存储
            if (newPassword === '' && !masterInfo.empty) {
                // 移除主密码
                await StorageManager.set({ [STORAGE_KEYS.MASTER]: { empty: true } });
            } else if (newPassword !== '') {
                // 设置新主密码
                const salt = crypto.getRandomValues(new Uint8Array(16));
                const key = await CryptoService.deriveKey(newPassword, salt);
                const verifier = await CryptoService.encrypt(key, 'verifier');

                await StorageManager.set({
                    [STORAGE_KEYS.MASTER]: {
                        salt: Base64.fromBuffer(salt),
                        iterations: DEFAULT_SETTINGS.pbkdf2Iterations,
                        verifier,
                        empty: false
                    }
                });
            }
        }
    };

    // ==================== 设置管理 ====================
    const SettingsManager = {
        current: { ...DEFAULT_SETTINGS },

        async load() {
            const storage = await StorageManager.get([STORAGE_KEYS.SETTINGS]);
            this.current = { ...DEFAULT_SETTINGS, ...(storage.settings || {}) };
            this.updateUI();
            Logger.log('设置已加载', this.current);
        },

        updateUI() {
            Object.entries(this.current).forEach(([key, value]) => {
                const el = DOM[key];
                if (el) {
                    if (el.type === 'checkbox') {
                        el.checked = value;
                    } else {
                        el.value = value;
                    }
                }
            });
        },

        collectFromUI() {
            const settings = {};

            ['clickCount', 'clickInterval', 'maxClickCount', 'pbkdf2Iterations',
                'minPasswordLength', 'panelMaxHeight', 'panelWidth'].forEach(key => {
                    const el = DOM[key];
                    if (el) {
                        const val = parseInt(el.value);
                        settings[key] = isNaN(val) ? DEFAULT_SETTINGS[key] : val;
                    }
                });

            ['autoClosePanel', 'showSuccessNotifications', 'masterPasswordWarning'].forEach(key => {
                const el = DOM[key];
                if (el) settings[key] = el.checked;
            });

            return settings;
        },

        validate(settings) {
            for (const [key, value] of Object.entries(settings)) {
                const rule = VALIDATION[key];
                if (rule && typeof value === 'number') {
                    if (value < rule.min || value > rule.max) {
                        return { valid: false, field: key, message: rule.message };
                    }
                }
            }
            return { valid: true };
        },

        async save() {
            const settings = this.collectFromUI();
            const validation = this.validate(settings);

            if (!validation.valid) {
                this.showStatus(validation.message, 'error');
                if (validation.field && DOM[validation.field]) {
                    DOM[validation.field].focus();
                    DOM[validation.field].style.borderColor = '#dc3545';
                    setTimeout(() => {
                        if (DOM[validation.field]) {
                            DOM[validation.field].style.borderColor = '';
                        }
                    }, 2000);
                }
                return;
            }

            try {
                await StorageManager.set({ [STORAGE_KEYS.SETTINGS]: settings });
                this.current = settings;

                try {
                    await chrome.runtime.sendMessage({
                        action: 'settingsUpdated',
                        settings
                    });
                } catch (error) {
                    Logger.warn('通知扩展失败', error);
                }

                this.showStatus('设置已保存', 'success');
            } catch (error) {
                Logger.error('保存设置失败', error);
                this.showStatus('保存失败', 'error');
            }
        },

        async reset() {
            if (!confirm('确定恢复所有默认设置吗？')) return;

            await StorageManager.set({ [STORAGE_KEYS.SETTINGS]: DEFAULT_SETTINGS });
            this.current = { ...DEFAULT_SETTINGS };
            this.updateUI();

            try {
                await chrome.runtime.sendMessage({
                    action: 'settingsUpdated',
                    settings: DEFAULT_SETTINGS
                });
            } catch (error) {
                Logger.warn('通知扩展失败', error);
            }

            this.showStatus('已恢复默认设置', 'success');
        },

        showStatus(message, type = 'info') {
            if (!DOM.status) return;
            DOM.status.textContent = type === 'success' ? `✓ ${message}` : `✗ ${message}`;
            DOM.status.className = type;
            setTimeout(() => {
                DOM.status.textContent = '';
                DOM.status.className = '';
            }, 3000);
        }
    };

    // ==================== 验证监听 ====================
    const initValidationListeners = () => {
        Object.keys(VALIDATION).forEach(key => {
            const el = DOM[key];
            if (el) {
                el.addEventListener('input', function () {
                    const rule = VALIDATION[key];
                    const val = parseInt(this.value);
                    const isValid = !isNaN(val) && val >= rule.min && val <= rule.max;
                    this.style.borderColor = isValid ? '' : '#dc3545';
                });
            }
        });
    };

    // ==================== 快捷键 ====================
    const initShortcuts = () => {
        document.addEventListener('keydown', (e) => {
            if (e.ctrlKey && e.key === 's') {
                e.preventDefault();
                SettingsManager.save();
            }
        });
    };

    // ==================== 初始化 ====================
    const init = async () => {
        Logger.log('初始化设置页面...');

        await SettingsManager.load();
        await MasterManager.loadStatus();
        initValidationListeners();
        initShortcuts();

        if (DOM.saveButton) {
            DOM.saveButton.addEventListener('click', () => SettingsManager.save());
        }
        if (DOM.resetButton) {
            DOM.resetButton.addEventListener('click', () => SettingsManager.reset());
        }

        // 主密码管理事件
        if (DOM.masterInput && DOM.passwordStrengthContainer) {
            DOM.masterInput.addEventListener('input', () => {
                PasswordStrength.render(DOM.masterInput.value, DOM.passwordStrengthContainer);
            });
        }
        if (DOM.setMasterBtn) {
            DOM.setMasterBtn.addEventListener('click', () => MasterManager.handleSetMaster());
        }

        // 存储变化监听
        chrome.storage.onChanged.addListener((changes, area) => {
            if (area === 'local') {
                if (changes.master) {
                    MasterManager.loadStatus();
                }
            }
        });

        Logger.log('设置页面初始化完成');
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();