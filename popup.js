/**
 * LocalPass - 弹出窗口脚本
 * 版本：2.0.0
 */

(function () {
  'use strict';

  // ==================== DOM 元素 ====================
  const DOM = {
    masterInput: document.getElementById('masterInput'),
    setMasterBtn: document.getElementById('setMaster'),
    extensionText: document.getElementById('extensionText'),
    extensionDot: document.getElementById('extensionDot'),
    masterText: document.getElementById('masterText'),
    masterDot: document.getElementById('masterDot'),
    entriesCard: document.getElementById('entriesCard'),
    entriesList: document.getElementById('entriesList'),
    entriesCount: document.getElementById('entriesCount'),
    exportBtn: document.getElementById('exportBtn'),
    importBtn: document.getElementById('importBtn'),
    importFile: document.getElementById('importFile'),
    settingsBtn: document.getElementById('settingsBtn'),
    helpBtn: document.getElementById('helpBtn'),
    clickCountDisplay: document.getElementById('clickCountDisplay'),
    strengthContainer: document.getElementById('passwordStrengthContainer')
  };

  // ==================== 常量 ====================
  const STORAGE_KEYS = {
    PASSWORDS: 'passwords',
    MASTER: 'master',
    SETTINGS: 'settings'
  };

  const DEFAULT_SETTINGS = {
    clickCount: 5,
    pbkdf2Iterations: 200000,
    minPasswordLength: 4,
    masterPasswordWarning: true
  };

  // ==================== 工具函数 ====================
  const Logger = {
    log(...args) { console.log('[LocalPass:Popup]', ...args); },
    error(...args) { console.error('[LocalPass:Popup] ❌', ...args); }
  };

  const Base64 = {
    fromBuffer(buf) {
      return btoa(String.fromCharCode(...new Uint8Array(buf)));
    },
    toBuffer(s) {
      return Uint8Array.from(atob(s), c => c.charCodeAt(0));
    }
  };

  const ErrorHandler = {
    showNotification(message, type = 'error') {
      alert(`${type === 'success' ? '✅' : '❌'} ${message}`);
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

  // ==================== 扩展状态（修复空指针）====================
  const ExtensionManager = {
    async checkStatus() {
      try {
        if (!chrome.runtime?.id) throw new Error('扩展未加载');
        const response = await chrome.runtime.sendMessage({ action: 'ping' });

        if (response?.ok) {
          if (DOM.extensionText) {
            DOM.extensionText.textContent = `已连接 v${response.version || ''}`;
          }
          if (DOM.extensionDot) {
            DOM.extensionDot.className = 'status-dot connected';
          }
          return true;
        }
      } catch {
        if (DOM.extensionText) {
          DOM.extensionText.textContent = '未连接';
        }
        if (DOM.extensionDot) {
          DOM.extensionDot.className = 'status-dot';
        }
      }
      return false;
    }
  };

  // ==================== 主密码管理（修复空指针）====================
  const MasterManager = {
    async loadStatus() {
      const storage = await StorageManager.get([STORAGE_KEYS.MASTER]);
      const master = storage.master;

      if (!DOM.masterText || !DOM.masterDot) return;

      if (!master) {
        DOM.masterText.textContent = '未设置';
        DOM.masterDot.className = 'status-dot';
        DOM.masterDot.style.background = '';
      } else if (master.empty) {
        DOM.masterText.textContent = '空密码';
        DOM.masterDot.className = 'status-dot connected';
        DOM.masterDot.style.background = '#17a2b8';
      } else {
        DOM.masterText.textContent = '已设置';
        DOM.masterDot.className = 'status-dot connected';
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
        await this.loadStatus();
        await CredentialManager.renderEntries();
        ErrorHandler.showNotification('操作成功', 'success');
      } catch (error) {
        ErrorHandler.showNotification(error.message || '操作失败', 'error');
      }
    },

    async firstTimeSetup(password) {
      // 首次设置主密码
      if (password === '') {
        if (!confirm('⚠️ 确定不设置主密码？\n密码将以明文存储，不再加密。')) {
          throw new Error('已取消');
        }
        // 设置空密码模式
        await StorageManager.set({ [STORAGE_KEYS.MASTER]: null });
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
        await StorageManager.set({ [STORAGE_KEYS.MASTER]: null });
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

  // ==================== 凭据管理 ====================
  const CredentialManager = {
    currentOrigin: null,

    async getCurrentOrigin() {
      try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        this.currentOrigin = tab?.url ? new URL(tab.url).origin : null;
      } catch {
        this.currentOrigin = null;
      }
    },

    async renderEntries() {
      await this.getCurrentOrigin();
      if (!this.currentOrigin) return;

      const storage = await StorageManager.get([STORAGE_KEYS.PASSWORDS]);
      const entries = storage.passwords?.[this.currentOrigin] || [];

      if (DOM.entriesCard) {
        DOM.entriesCard.style.display = entries.length ? 'block' : 'none';
      }
      if (DOM.entriesCount) {
        DOM.entriesCount.textContent = entries.length;
      }

      if (entries.length === 0) {
        if (DOM.entriesList) {
          DOM.entriesList.innerHTML = '<div class="empty-state"><span style="font-size: 36px;">🔍</span><p>当前站点无保存的凭据</p></div>';
        }
        return;
      }

      const sorted = [...entries].sort((a, b) =>
        (b.lastUsed || b.createdAt || 0) - (a.lastUsed || a.createdAt || 0)
      );

      if (DOM.entriesList) {
        DOM.entriesList.innerHTML = '';
        sorted.forEach(entry => {
          DOM.entriesList.appendChild(this.renderEntry(entry));
        });
      }
    },

    renderEntry(entry) {
      const item = document.createElement('div');
      item.className = 'entry-item';
      item.innerHTML = `
        <div class="entry-info">
          <div class="entry-label">${this.escapeHtml(entry.label || '无标签')}</div>
          <div class="entry-username">${this.escapeHtml(entry.username || '无账号')}</div>
        </div>
        <div class="entry-actions">
          <button class="btn btn-sm btn-outline fill-btn">🔓 填充</button>
          <button class="btn btn-sm btn-outline delete-btn" style="border-color: #fc8181; color: #c53030;">🗑️</button>
        </div>
      `;

      item.querySelector('.fill-btn').onclick = async () => {
        try {
          const master = await StorageManager.get([STORAGE_KEYS.MASTER]);
          const masterInfo = master.master;

          let password;

          if (entry.plain !== undefined) {
            password = entry.plain;
          } else if (masterInfo) {
            const masterPassword = prompt('请输入主密码:');
            if (!masterPassword) return;

            const isValid = await CryptoService.verifyMaster(masterPassword, masterInfo);
            if (!isValid) throw new Error('密码错误');

            const saltBytes = entry.salt ? Base64.toBuffer(entry.salt) : Base64.toBuffer(masterInfo.salt);
            const key = await CryptoService.deriveKey(masterPassword, saltBytes, masterInfo.iterations);
            password = await CryptoService.decrypt(key, entry.iv, entry.data);
          }

          if (password) {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            await chrome.tabs.sendMessage(tab.id, {
              action: 'fillPassword',
              username: entry.username,
              password
            });
            ErrorHandler.showNotification('已填充', 'success');
          }
        } catch (error) {
          ErrorHandler.showNotification(error.message || '填充失败', 'error');
        }
      };

      item.querySelector('.delete-btn').onclick = async () => {
        if (!confirm('确定删除此凭据？')) return;

        const storage = await StorageManager.get([STORAGE_KEYS.PASSWORDS]);
        const passwords = storage.passwords || {};
        if (passwords[this.currentOrigin]) {
          passwords[this.currentOrigin] = passwords[this.currentOrigin].filter(e => e.id !== entry.id);
          if (passwords[this.currentOrigin].length === 0) delete passwords[this.currentOrigin];
          await StorageManager.set({ [STORAGE_KEYS.PASSWORDS]: passwords });
          this.renderEntries();
          ErrorHandler.showNotification('已删除', 'success');
        }
      };

      return item;
    },

    escapeHtml(text) {
      if (!text) return '';
      const div = document.createElement('div');
      div.textContent = text;
      return div.innerHTML;
    }
  };

  // ==================== 备份管理 ====================
  const BackupManager = {
    async exportBackup() {
      const storage = await StorageManager.get();
      const data = {
        passwords: storage.passwords || {},
        master: storage.master || null,
        exportedAt: new Date().toISOString(),
        version: 2
      };

      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `localpass-backup-${new Date().toISOString().split('T')[0]}.json`;
      a.click();
      URL.revokeObjectURL(url);

      ErrorHandler.showNotification('导出成功', 'success');
    },

    async importBackup(file) {
      const text = await file.text();
      const data = JSON.parse(text);

      const merge = confirm('合并现有条目？\n确定-合并  取消-替换');
      const current = await StorageManager.get([STORAGE_KEYS.PASSWORDS]);
      let newPasswords;

      if (merge) {
        newPasswords = current.passwords || {};
        for (const [origin, entries] of Object.entries(data.passwords || {})) {
          newPasswords[origin] = [...(newPasswords[origin] || []), ...entries];
        }
      } else {
        newPasswords = data.passwords || {};
      }

      await StorageManager.set({ [STORAGE_KEYS.PASSWORDS]: newPasswords });

      if (!current.master && data.master && confirm('是否同时导入备份中的主密码？')) {
        await StorageManager.set({ [STORAGE_KEYS.MASTER]: data.master });
      }

      await MasterManager.loadStatus();
      await CredentialManager.renderEntries();
      ErrorHandler.showNotification('导入完成', 'success');
    }
  };

  // ==================== 设置管理 ====================
  const SettingsManager = {
    async loadClickCount() {
      const storage = await StorageManager.get([STORAGE_KEYS.SETTINGS]);
      const settings = storage.settings || DEFAULT_SETTINGS;
      if (DOM.clickCountDisplay) {
        DOM.clickCountDisplay.textContent = settings.clickCount || 5;
      }
    }
  };

  // ==================== 初始化 ====================
  const init = async () => {
    await ExtensionManager.checkStatus();
    await MasterManager.loadStatus();
    await CredentialManager.renderEntries();
    await SettingsManager.loadClickCount();

    // 密码强度检测
    if (DOM.masterInput && DOM.strengthContainer) {
      DOM.masterInput.addEventListener('input', () => {
        PasswordStrength.render(DOM.masterInput.value, DOM.strengthContainer);
      });
    }

    // 主密码按钮
    if (DOM.setMasterBtn) {
      DOM.setMasterBtn.addEventListener('click', () => MasterManager.handleSetMaster());
    }

    // 备份恢复
    if (DOM.exportBtn) {
      DOM.exportBtn.addEventListener('click', () => BackupManager.exportBackup());
    }
    if (DOM.importBtn) {
      DOM.importBtn.addEventListener('click', () => DOM.importFile.click());
    }
    if (DOM.importFile) {
      DOM.importFile.addEventListener('change', async (e) => {
        if (e.target.files?.[0]) {
          await BackupManager.importBackup(e.target.files[0]);
          DOM.importFile.value = '';
        }
      });
    }

    // 设置页面
    if (DOM.settingsBtn) {
      DOM.settingsBtn.addEventListener('click', () => {
        chrome.runtime.openOptionsPage?.() || chrome.tabs.create({ url: 'settings.html' });
      });
    }

    // 帮助按钮
    if (DOM.helpBtn) {
      DOM.helpBtn.addEventListener('click', () => {
        chrome.tabs.create({ url: 'https://github.com/localpass/localpass/wiki' });
      });
    }

    // 存储变化监听
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area === 'local') {
        if (changes.passwords || changes.master) {
          CredentialManager.renderEntries();
          MasterManager.loadStatus();
        }
        if (changes.settings) SettingsManager.loadClickCount();
      }
    });

    // 定期检查连接
    setInterval(() => ExtensionManager.checkStatus(), 30000);

    Logger.log('弹出窗口初始化完成');
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();