/**
 * LocalPass - Background Service Worker
 * 版本：2.0.0
 */

const CONSTANTS = {
    STORAGE_KEYS: {
        PASSWORDS: 'passwords',
        MASTER: 'master',
        SETTINGS: 'settings'
    },
    DEFAULT_SETTINGS: {
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
    },
    MESSAGES: {
        PING: 'ping',
        SETTINGS_UPDATED: 'settingsUpdated',
        FILL_PASSWORD: 'fillPassword',
        EXTENSION_READY: 'extensionReady',
        OPEN_SETTINGS: 'openSettings'
    },
    REGEX: {
        CHROME_PROTOCOL: /^chrome:\/\//
    }
};

const Logger = {
    log(...args) { console.log('[LocalPass:Background]', ...args); },
    warn(...args) { console.warn('[LocalPass:Background] ⚠️', ...args); },
    error(...args) { console.error('[LocalPass:Background] ❌', ...args); },
    debug(...args) { console.debug('[LocalPass:Background] 🔍', ...args); }
};

const StorageManager = {
    async get(keys) {
        try {
            return await chrome.storage.local.get(keys);
        } catch (error) {
            Logger.error('读取存储失败', error);
            return {};
        }
    },
    async set(data) {
        try {
            await chrome.storage.local.set(data);
        } catch (error) {
            Logger.error('写入存储失败', error);
        }
    }
};

// 初始化设置
chrome.runtime.onInstalled.addListener(async (details) => {
    Logger.log('扩展已安装/更新', details.reason);

    if (details.reason === 'install') {
        const storage = await StorageManager.get([CONSTANTS.STORAGE_KEYS.SETTINGS]);
        if (!storage.settings) {
            await StorageManager.set({ [CONSTANTS.STORAGE_KEYS.SETTINGS]: CONSTANTS.DEFAULT_SETTINGS });
        }
    }
});

// 消息监听
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    const action = message?.action;
    Logger.debug('收到消息:', action);

    switch (action) {
        case CONSTANTS.MESSAGES.PING:
            sendResponse({
                ok: true,
                timestamp: Date.now(),
                version: chrome.runtime.getManifest().version
            });
            break;

        case CONSTANTS.MESSAGES.OPEN_SETTINGS:
            chrome.runtime.openOptionsPage(() => {
                if (chrome.runtime.lastError) {
                    chrome.tabs.create({ url: 'settings.html' });
                }
            });
            sendResponse({ ok: true });
            break;

        case CONSTANTS.MESSAGES.SETTINGS_UPDATED:
            chrome.tabs.query({}, (tabs) => {
                tabs.forEach(tab => {
                    if (tab.url && !CONSTANTS.REGEX.CHROME_PROTOCOL.test(tab.url)) {
                        chrome.tabs.sendMessage(tab.id, message).catch(() => { });
                    }
                });
            });
            sendResponse({ ok: true });
            break;

        default:
            return false;
    }
    return true;
});

// 标签页更新时通知内容脚本
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' &&
        tab.url &&
        !CONSTANTS.REGEX.CHROME_PROTOCOL.test(tab.url)) {
        setTimeout(() => {
            chrome.tabs.sendMessage(tabId, {
                action: CONSTANTS.MESSAGES.EXTENSION_READY
            }).catch(() => { });
        }, 500);
    }
});

Logger.log('Background Service Worker 已启动');