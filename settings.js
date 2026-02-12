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
        status: document.getElementById('status')
    };

    // ==================== 常量 ====================
    const STORAGE_KEYS = {
        SETTINGS: 'settings'
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
        initValidationListeners();
        initShortcuts();

        if (DOM.saveButton) {
            DOM.saveButton.addEventListener('click', () => SettingsManager.save());
        }
        if (DOM.resetButton) {
            DOM.resetButton.addEventListener('click', () => SettingsManager.reset());
        }

        Logger.log('设置页面初始化完成');
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();