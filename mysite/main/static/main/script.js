// main/static/main/script.js

// === DOM UTILITIES (Helper Functions) ===

/**
 * Коротка функція для document.querySelector.
 * @param {string} selector - CSS селектор.
 * @returns {HTMLElement | null}
 */
const $ = (selector) => document.querySelector(selector);

/**
 * Коротка функція для document.querySelectorAll.
 * @param {string} selector - CSS селектор.
 * @returns {NodeListOf<HTMLElement>}
 */
const $$ = (selector) => document.querySelectorAll(selector);

// === STATE MANAGEMENT (Internal State Object) ===
// Централізоване сховище для всіх даних застосунку
const state = {
    settings: {
        theme: 'dark',
        auto_clear: true,
        secure_wipe: true,
        audit_trail: false,
        encryption_algorithm: 'aes-256',
        key_derivation: 'pbkdf2',
        font_size: 'medium',
        language: 'en'
    },
    encryptionHistory: [],
    isAuthenticated: typeof isAuthenticated !== 'undefined' ? isAuthenticated : false,
};


// === API & UTILITY FUNCTIONS ===

const getCSRFToken = () => {
    // Шукаємо токен в прихованому полі, доданому в home.html
    return $('#csrfToken')?.value;
};

/**
 * Асинхронний виклик до API з обробкою CSRF та помилок.
 */
const apiCall = async (url, data, method = 'POST') => {
    const requiresToken = method !== 'GET';
    let token = null;

    if (requiresToken) {
        token = getCSRFToken();
        if (!token) {
            console.error("CSRF token not found. Required for method:", method);
            EncryptorApp.showModal('Error', 'Security error: CSRF token missing.', 'error');
            throw new Error('CSRF token missing');
        }
    }
    
    const headers = {
        'Content-Type': 'application/json',
    };
    
    // ВИПРАВЛЕНО: Використовуємо стандартний заголовок Django
    if (token) {
        headers['X-CSRFToken'] = token;
    }
    
    const config = {
        method: method,
        headers: headers,
        body: data ? JSON.stringify(data) : undefined,
    };

    if (method === 'GET') {
        delete config.body;
        delete config.headers['Content-Type']; 
    }

    try {
        const response = await fetch(url, config);
         if (response.status === 403) {
            console.error(`API Call failed with 403 Forbidden for ${url}.`);
            EncryptorApp.showModal('Error', 'Security error: API request forbidden (403). Session or CSRF issue.', 'error');
            throw new Error('API Request Forbidden (403)'); 
        }
        return await response.json();
    } catch (error) {
        console.error(`API Call failed for ${url}:`, error);
        if (!error.message.includes('CSRF token missing') && !error.message.includes('API Request Forbidden')) {
            EncryptorApp.showModal('Error', `Network error during API call to ${url}.`, 'error');
        }
        throw error;
    }
};

// ===============================================================
// === MAIN APPLICATION MODULE (Singleton Object) ===
// ===============================================================

const EncryptorApp = {

    // === CORE INIT ===

    init() {
        console.log('EncryptorApp initialized. Authenticated:', state.isAuthenticated);
        this.loadSettings();
        this.loadHistory();
        this.bindEvents();
        this.applySettings();
        this.checkCookies();
    },

    // -------------------------------------------------------------------------------------------------
    // === MODAL AND LOADING ===

    showLoading(message) {
        let loadingOverlay = $('#loadingOverlay');
        if (!loadingOverlay) {
            loadingOverlay = document.createElement('div');
            loadingOverlay.id = 'loadingOverlay'; 
            loadingOverlay.className = 'fixed inset-0 bg-primary/80 backdrop-blur-sm z-[1001] flex items-center justify-center';
            document.body.appendChild(loadingOverlay);
        }
        loadingOverlay.innerHTML = `
            <div class="bg-card border border-toxic/50 p-6 rounded-xl flex items-center space-x-4">
                <i class="fas fa-spinner fa-spin text-toxic text-2xl"></i>
                <span class="text-white font-medium">${message}</span>
            </div>
        `;
    },

    hideLoading() {
        $('#loadingOverlay')?.remove();
    },
    
    showModal(title, message, type) {
        const modal = $('#modal');
        const iconContainer = $('#modal-icon');
        const titleEl = $('#modal-title');
        const messageEl = $('#modal-message');
        const buttonsContainer = $('#modal-buttons');

        if (!modal) return;

        let iconHtml = '';
        let buttonHtml = `<button class="modal-close bg-toxic text-black py-2 px-4 rounded-lg font-bold hover:bg-toxic/90 transition-colors">Close</button>`;

        switch (type) {
            case 'success':
                iconHtml = '<i class="fas fa-check-circle text-toxic text-4xl"></i>';
                break;
            case 'error':
                iconHtml = '<i class="fas fa-times-circle text-red-500 text-4xl"></i>';
                break;
            case 'info':
                iconHtml = '<i class="fas fa-info-circle text-accent text-4xl"></i>';
                break;
            default:
                iconHtml = '<i class="fas fa-bell text-steel text-4xl"></i>';
        }

        iconContainer.innerHTML = iconHtml;
        titleEl.textContent = title;
        messageEl.textContent = message;
        buttonsContainer.innerHTML = buttonHtml;

        buttonsContainer.querySelector('.modal-close').addEventListener('click', () => this.hideModal());

        modal.classList.add('show');
    },
    
    showConfirmModal(title, message, onConfirm) {
        const modal = $('#modal');
        const iconContainer = $('#modal-icon');
        const titleEl = $('#modal-title');
        const messageEl = $('#modal-message');
        const buttonsContainer = $('#modal-buttons');

        if (!modal) return;

        iconContainer.innerHTML = '<i class="fas fa-exclamation-triangle text-red-500 text-4xl"></i>';
        titleEl.textContent = title;
        messageEl.textContent = message;
        
        const buttonHtml = `
            <button id="confirmBtn" class="bg-red-500 text-white py-2 px-4 rounded-lg font-bold hover:bg-red-600 transition-colors">Confirm</button>
            <button id="cancelBtn" class="bg-secondary border border-steel/30 text-white py-2 px-4 rounded-lg font-bold hover:border-toxic transition-colors">Cancel</button>
        `;
        buttonsContainer.innerHTML = buttonHtml;

        $('#confirmBtn').addEventListener('click', () => {
            onConfirm();
            this.hideModal();
        });
        $('#cancelBtn').addEventListener('click', () => this.hideModal());

        modal.classList.add('show');
    },

    hideModal() {
        $('#modal')?.classList.remove('show');
    },

    // -------------------------------------------------------------------------------------------------
    // === COOKIE MANAGEMENT ===

    checkCookies() {
        const cookiesAccepted = localStorage.getItem('cookies_accepted');
        if (!cookiesAccepted) {
            this.showCookieBar();
        }
    },

    showCookieBar() {
        const cookieBar = $('#cookieBar');
        if (cookieBar) {
            cookieBar.style.display = 'block';
        }
    },

    hideCookieBar() {
        const cookieBar = $('#cookieBar');
        if (cookieBar) {
            cookieBar.style.display = 'none';
        }
    },

    // -------------------------------------------------------------------------------------------------
    // === SETTINGS MANAGEMENT ===

    loadSettings() {
        try {
            const saved = localStorage.getItem('encryptor_settings');
            if (saved) {
                const parsedSettings = JSON.parse(saved);
                Object.assign(state.settings, parsedSettings);
            }
        } catch (e) {
            console.error('Error loading settings from localStorage:', e);
        }

        if (state.isAuthenticated) {
            this.loadSettingsFromAPI();
        } else {
            this.applySettings(); 
        }
    },

    async loadSettingsFromAPI() {
        try {
            const response = await apiCall('/api/get-settings/', null, 'GET'); 
            
            if (response.success) {
                Object.assign(state.settings, response.settings);
                this.saveSettingsToLocalStorage(); 
                
                if ($('#saveSettings')) { 
                    this.updateSettingsUI();
                }
                this.applySettings();
            } else {
                console.warn('Failed to load settings from server. Using local settings.');
                this.applySettings();
            }
        } catch (e) {
            console.error('Error loading settings from API:', e);
            this.applySettings(); 
        }
    },

    saveSettingsToLocalStorage() {
         try {
            localStorage.setItem('encryptor_settings', JSON.stringify(state.settings));
        } catch (e) {
            console.error('Error saving settings to localStorage:', e);
        }
    },

    async saveSettings() {
        this.saveSettingsToLocalStorage();
        
        if (state.isAuthenticated) {
            await this.saveSettingsToAPI();
        } else {
            this.showModal('Success', 'Налаштування збережено локально. Увійдіть, щоб синхронізувати з сервером.', 'success');
        }
        
        this.updateActiveThemeButtons(); 
        this.applySettings(); 
    },

    async saveSettingsToAPI() {
        this.showLoading('Збереження налаштувань на сервері...');
        try {
            const data = {
                theme: state.settings.theme,
                auto_clear: state.settings.auto_clear,
                secure_wipe: state.settings.secure_wipe,
                audit_trail: state.settings.audit_trail,
                encryption_algorithm: state.settings.encryption_algorithm,
                key_derivation: state.settings.key_derivation,
                font_size: state.settings.font_size,
                language: state.settings.language,
            };

            const response = await apiCall('/api/update-settings/', data, 'POST');

            if (response.success) {
                this.showModal('Success', response.message, 'success');
            } else {
                this.showModal('Error', 'Помилка збереження: ' + response.error, 'error');
            }
        } catch (e) {
            // Error handled by apiCall
        } finally {
            this.hideLoading();
        }
    },

    updateSettingsUI() {
        if ($('#auto-clear')) {
            $('#auto-clear').checked = state.settings.auto_clear;
            $('#secure-wipe').checked = state.settings.secure_wipe;
            $('#audit-trail').checked = state.settings.audit_trail;
            $('#encryption-algorithm').value = state.settings.encryption_algorithm;
            $('#key-derivation').value = state.settings.key_derivation;
            $('#language').value = state.settings.language;
            this.updateActiveThemeButtons();
        }
    },

    applySettings() {
        document.body.setAttribute('data-theme', state.settings.theme);
        this.applyFontSize();
        this.updateActiveThemeButtons();
    },

    applyFontSize() {
        const root = document.documentElement;
        switch(state.settings.font_size) {
            case 'small':
                root.style.fontSize = '14px';
                break;
            case 'medium':
                root.style.fontSize = '16px';
                break;
            case 'large':
                root.style.fontSize = '18px';
                break;
            default:
                root.style.fontSize = '16px';
        }
    },
    
    updateActiveThemeButtons() {
        $$('.theme-btn').forEach(btn => {
            if (btn.dataset.theme === state.settings.theme) {
                btn.classList.add('bg-toxic', 'text-black', 'border-toxic');
                btn.classList.remove('bg-secondary', 'text-steel', 'border-steel/30', 'hover:border-toxic', 'hover:text-white');
            } else {
                btn.classList.remove('bg-toxic', 'text-black', 'border-toxic');
                btn.classList.add('bg-secondary', 'text-steel', 'border-steel/30', 'hover:border-toxic', 'hover:text-white');
            }
        });
        
        $$('.font-size-btn').forEach(btn => {
            if (btn.dataset.fontSize === state.settings.font_size) {
                btn.classList.add('bg-toxic', 'text-black', 'font-bold');
                btn.classList.remove('bg-secondary', 'text-steel', 'hover:border-toxic', 'hover:text-white');
            } else {
                 btn.classList.remove('bg-toxic', 'text-black', 'font-bold');
                 btn.classList.add('bg-secondary', 'text-steel', 'hover:border-toxic', 'hover:text-white');
            }
        });
    },

    // -------------------------------------------------------------------------------------------------
    // === HISTORY MANAGEMENT ===
    
    loadHistory() {
        if (state.isAuthenticated) {
            this.loadHistoryFromAPI();
        } else {
            try {
                const savedHistory = localStorage.getItem('encryption_history');
                if (savedHistory) {
                    state.encryptionHistory = JSON.parse(savedHistory);
                }
            } catch (e) {
                console.error('Error loading history from localStorage:', e);
            }
            this.renderHistory();
        }
    },

    async loadHistoryFromAPI() {
        try {
            const response = await apiCall('/api/get-history/', null, 'GET');
            if (response.success) {
                state.encryptionHistory = response.history;
            } else {
                console.warn('Failed to load history from server. Using local history.');
                this.loadHistoryFromLocalStorage();
            }
        } catch (e) {
            this.loadHistoryFromLocalStorage();
        }
        this.renderHistory();
    },
    
    loadHistoryFromLocalStorage() {
         try {
            const savedHistory = localStorage.getItem('encryption_history');
            if (savedHistory) {
                state.encryptionHistory = JSON.parse(savedHistory);
            }
        } catch (e) {
            console.error('Error loading history from localStorage:', e);
        }
    },

    saveHistory() {
        try {
            localStorage.setItem('encryption_history', JSON.stringify(state.encryptionHistory));
        } catch (e) {
            console.error('Error saving history to localStorage:', e);
        }
    },
    
    async addToHistory(operation_type, input_text, output_text) {
        const historyItem = {
            id: Date.now(), 
            operation_type: operation_type,
            input_text: input_text,
            output_text: output_text,
            timestamp: new Date().toISOString()
        };
        
        state.encryptionHistory.unshift(historyItem);
        this.saveHistory();
        this.renderHistory();
    },

    async clearHistory(clearOnServer = false) {
        state.encryptionHistory = [];
        this.saveHistory(); 
        this.renderHistory();
        
        if (clearOnServer && state.isAuthenticated) {
            this.showLoading('Очищення історії на сервері...');
            try {
                const response = await apiCall('/api/clear-history/', {}, 'POST');
                if (response.success) {
                    this.showModal('Success', response.message, 'success');
                } else {
                    this.showModal('Warning', 'Локальна історія очищена, але не вдалося очистити на сервері: ' + response.error, 'warning');
                }
            } catch (e) {
                 // Error handled by apiCall
            } finally {
                this.hideLoading();
            }
        } else {
            this.showModal('Success', 'Історія очищена успішно', 'success');
        }
    },

    renderHistory() {
        const historyList = $('#historyList'); 
        const placeholder = $('#historyPlaceholder'); 
        if (!historyList) return;

        historyList.innerHTML = '';
        
        if (state.encryptionHistory.length === 0) {
            if (placeholder) {
                 historyList.appendChild(placeholder);
                 placeholder.classList.remove('hidden');
            } else {
                 historyList.innerHTML = '<p class="text-steel text-center py-8">No recent activity</p>';
            }
            return;
        }
        
        if (placeholder) {
            // Placeholder повинен бути у home.html або відображатися, якщо немає історії
             placeholder.classList.add('hidden');
        }

        state.encryptionHistory.forEach(item => {
            const date = new Date(item.timestamp);
            const formattedTime = date.toLocaleTimeString('uk-UA', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
            const formattedDate = date.toLocaleDateString('uk-UA', { day: '2-digit', month: 'short' });
            
            const itemElement = document.createElement('div');
            itemElement.className = 'history-item bg-secondary p-4 rounded-lg border border-steel/20 cursor-pointer hover:border-toxic transition-colors';
            itemElement.dataset.id = item.id;
            itemElement.dataset.type = item.operation_type;
            itemElement.innerHTML = `
                <div class="flex items-center justify-between">
                    <div class="flex items-center space-x-3">
                        <i class="fas fa-${item.operation_type === 'encrypt' ? 'lock' : 'unlock'} text-${item.operation_type === 'encrypt' ? 'toxic' : 'accent'}"></i>
                        <span class="font-bold text-white capitalize">${item.operation_type}</span>
                    </div>
                    <span class="text-steel text-xs">${formattedTime} ${formattedDate}</span>
                </div>
                <p class="text-steel text-sm mt-2 truncate">Input: ${item.input_preview || (item.input_text || '').slice(0, 30)}...</p>
            `;
            
            itemElement.addEventListener('click', () => this.handleHistoryClick(item));
            historyList.appendChild(itemElement);
        });
    },
    
    handleHistoryClick(item) {
        this.showModal(
            'History Details',
            `Operation: ${item.operation_type}\nInput: ${item.full_input}\nOutput: ${item.full_output}`, 
            'info'
        );
    },


    // -------------------------------------------------------------------------------------------------
    // === ENCRYPTION/DECRYPTION ===

    async encrypt() {
        // ВИПРАВЛЕННЯ ID: Використовуємо ID з home.html
        const key = $('#encrypt-key')?.value || '';
        const text = $('#encrypt-text')?.value || '';
        const outputField = $('#encrypt-output'); 

        // Перевірка, чи існує outputField
        if (!outputField) {
            console.error("Output field #encrypt-output not found.");
            return;
        }

        if (!key || key.length < 8) {
            this.showModal('Input Error', 'Encryption key must be at least 8 characters long.', 'error');
            return;
        }
        
        if (!text) {
            this.showModal('Input Error', 'Input text cannot be empty.', 'error');
            return;
        }

        this.showLoading('Encrypting...');

        try {
            const data = { key: key, text: text };
            // Припускаємо, що API поверне { success: true, encrypted: '...' }
            const response = await apiCall('/api/encrypt/', data, 'POST');

            if (response.success) {
                // ВИПРАВЛЕННЯ: Записуємо результат у відповідний DIV
                outputField.innerHTML = response.encrypted;
                outputField.classList.add('mono-font', 'text-white');
                
                this.addToHistory('encrypt', text, response.encrypted);
                
                if (state.settings.auto_clear) {
                    $('#encrypt-text').value = ''; 
                    // Не очищаємо ключ
                }
                
                this.showModal('Success', `Encryption completed. Result copied to output.`, 'success');
            } else {
                // ВИПРАВЛЕННЯ: Відображаємо помилку у полі виводу
                outputField.innerHTML = `<span class="text-red-400">Error: ${response.error || 'Unknown error occurred.'}</span>`;
                this.showModal('Encryption Failed', response.error || 'Unknown error occurred.', 'error');
            }
        } catch (e) {
            outputField.innerHTML = `<span class="text-red-400">API Error.</span>`;
        } finally {
            this.hideLoading();
        }
    },

    async decrypt() {
        // ВИПРАВЛЕННЯ ID: Використовуємо ID з home.html
        const key = $('#decrypt-key')?.value || '';
        const encrypted_data = $('#decrypt-text')?.value || '';
        const outputField = $('#decrypt-output'); // Отримуємо поле виводу

        // Перевірка, чи існує outputField
        if (!outputField) {
            console.error("Output field #decrypt-output not found.");
            return;
        }

        if (!key || key.length < 8) {
            this.showModal('Input Error', 'Decryption key must be at least 8 characters long.', 'error');
            return;
        }
        
        if (!encrypted_data) {
            this.showModal('Input Error', 'Encrypted data cannot be empty.', 'error');
            return;
        }

        this.showLoading('Decrypting...');

        try {
            const data = { key: key, encrypted_data: encrypted_data };
             // Припускаємо, що API поверне { success: true, decrypted: '...' }
            const response = await apiCall('/api/decrypt/', data, 'POST');

            if (response.success) {
                 // ВИПРАВЛЕННЯ: Записуємо результат у відповідний DIV
                outputField.innerHTML = response.decrypted;
                outputField.classList.add('text-white');
                outputField.classList.remove('text-steel', 'mono-font');

                this.addToHistory('decrypt', encrypted_data, response.decrypted);
                
                if (state.settings.auto_clear) {
                    $('#decrypt-text').value = ''; 
                }

                this.showModal('Success', 'Decryption completed. Result copied to output.', 'success');
            } else {
                 // ВИПРАВЛЕННЯ: Відображаємо помилку у полі виводу
                outputField.innerHTML = `<span class="text-red-400">Error: ${response.error || 'Unknown error occurred.'}</span>`;
                this.showModal('Decryption Failed', response.error || 'Unknown error occurred.', 'error');
            }
        } catch (e) {
             outputField.innerHTML = `<span class="text-red-400">API Error.</span>`;
        } finally {
            this.hideLoading();
        }
    },
    
    quickDemo() {
        const encryptKeyInput = $('#encrypt-key');
        const encryptTextInput = $('#encrypt-text');
        
        if (encryptKeyInput) encryptKeyInput.value = 'MyStrongDemoKey123';
        if (encryptTextInput) encryptTextInput.value = 'This is a test message to demonstrate quick encryption.';
        
        this.showModal('Demo Ready', 'Key and text set for quick demonstration.', 'info');
    },

    // Оновлена функція для копіювання з DIV
    copyOutput(targetId) {
        const outputEl = $(`#${targetId}`);
        if (!outputEl) return;

        // Витягуємо текст з елемента, ігноруючи внутрішні теги помилок
        const textToCopy = outputEl.innerText.trim();
        
        if (textToCopy && !textToCopy.startsWith('Error:')) {
            navigator.clipboard.writeText(textToCopy).then(() => {
                this.showModal('Success', 'Text copied to clipboard', 'success');
            }).catch(() => {
                this.showModal('Error', 'Failed to copy text', 'error');
            });
        } else {
            this.showModal('Info', 'Output field is empty or contains an error message.', 'info');
        }
    },


    clearAllInputs(clearKey = true, clearOutput = true) {
        // Очищаємо обидва поля ключів
        const encryptKeyInput = $('#encrypt-key');
        const decryptKeyInput = $('#decrypt-key');
        // Очищаємо поля вводу/виводу
        const encryptTextInput = $('#encrypt-text');
        const decryptTextInput = $('#decrypt-text');
        const encryptOutput = $('#encrypt-output');
        const decryptOutput = $('#decrypt-output');
        
        if (clearKey) {
            if (encryptKeyInput) encryptKeyInput.value = '';
            if (decryptKeyInput) decryptKeyInput.value = '';
        }
        
        if (encryptTextInput) encryptTextInput.value = '';
        if (decryptTextInput) decryptTextInput.value = '';
        
        if (clearOutput) {
            if (encryptOutput) encryptOutput.innerHTML = '<span class="opacity-50">Encrypted data will appear here...</span>';
            if (decryptOutput) decryptOutput.innerHTML = '<span class="opacity-50">Decrypted text will appear here...</span>';
        }
        
        if (state.settings.secure_wipe) {
            console.log('Secure memory wipe simulated.');
        }
    },

    // -------------------------------------------------------------------------------------------------
    // === EVENT BINDING ===

    bindEvents() {
        this.bindCookieEvents();
        this.bindModalEvents();
        this.bindEncryptionEvents();
        this.bindSettingsEvents();
        this.bindMobileEvents();
        this.bindPasswordToggleEvents();
        this.bindCopyEvents();
        this.bindNavigationEvents(); 
    },

    // ВИПРАВЛЕНО: Додано пропущену функцію
    bindCookieEvents() {
        $('#acceptCookiesBtn')?.addEventListener('click', () => {
            localStorage.setItem('cookies_accepted', 'true');
            this.hideCookieBar();
        });
    },

    // ВИПРАВЛЕНО: Додано пропущену функцію
    bindModalEvents() {
        $('#modal')?.addEventListener('click', (e) => {
            if (e.target.id === 'modal') {
                this.hideModal();
            }
        });
    },

    bindNavigationEvents() {
        // Змінено селектор, щоб бути більш загальним і працювати з home.html
        const headerSettingsLink = document.querySelector('nav.lg\\:flex a[href$="settings_page/"]');
        if (headerSettingsLink) {
            headerSettingsLink.addEventListener('click', (e) => {
                // Цей обробник вже не потрібен, якщо HTML-посилання правильне, але залишаємо
                // його, якщо URL в HTML все ще вказує на api_get_settings, хоча ми його виправили.
                // Припускаємо, що href="{% url 'settings_page' %}" вже коректний.
                // Видаляємо цей обробник, оскільки він конфліктує з правильним HTML.
            });
        }
    },
    
    bindEncryptionEvents() {
        $('#encrypt-btn')?.addEventListener('click', () => this.encrypt());
        $('#decrypt-btn')?.addEventListener('click', () => this.decrypt());
        $('#quick-demo')?.addEventListener('click', () => this.quickDemo());
        $('#clear-history-btn')?.addEventListener('click', () => {
             this.showConfirmModal(
                'Clear History',
                'Are you sure you want to clear your local history?',
                () => this.clearHistory(state.isAuthenticated) 
            );
        });
    },

    bindSettingsEvents() {
        $$('.theme-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const theme = e.currentTarget.dataset.theme;
                state.settings.theme = theme; 
                this.updateActiveThemeButtons();
                this.applySettings();
            });
        });

        $$('.font-size-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const fontSize = e.currentTarget.dataset.fontSize;
                state.settings.font_size = fontSize; 
                this.updateActiveThemeButtons();
                this.applySettings();
            });
        });

        $('#auto-clear')?.addEventListener('change', (e) => {
            state.settings.auto_clear = e.target.checked;
        });
        $('#secure-wipe')?.addEventListener('change', (e) => {
            state.settings.secure_wipe = e.target.checked;
        });
        $('#audit-trail')?.addEventListener('change', (e) => {
            state.settings.audit_trail = e.target.checked;
        });
        $('#encryption-algorithm')?.addEventListener('change', (e) => {
            state.settings.encryption_algorithm = e.target.value;
        });
        $('#key-derivation')?.addEventListener('change', (e) => {
            state.settings.key_derivation = e.target.value;
        });
        $('#language')?.addEventListener('change', (e) => {
            state.settings.language = e.target.value;
        });

        $('#saveSettings')?.addEventListener('click', () => {
            this.saveSettings();
        });

        $('#clearHistorySettings')?.addEventListener('click', () => {
            this.showConfirmModal(
                'Очистити всю історію',
                'Це назавжди видалить усі ваші записи історії шифрування. Цю дію не можна скасувати.',
                () => this.clearHistory(true) 
            );
        });

        $('#exportData')?.addEventListener('click', () => {
            this.exportData();
        });
    },

    bindPasswordToggleEvents() {
        // Обробка всіх кнопок перемикання пароля на сторінці
        $$('.password-input-wrapper').forEach(wrapper => {
            const toggleBtn = wrapper.querySelector('.password-toggle');
            const keyInput = wrapper.querySelector('input[type="password"], input[type="text"]');
            const icon = toggleBtn?.querySelector('i');

            if (toggleBtn && keyInput && icon) {
                toggleBtn.addEventListener('click', (e) => {
                    e.preventDefault();
                    if (keyInput.type === 'password') {
                        keyInput.type = 'text';
                        icon.classList.replace('fa-eye', 'fa-eye-slash');
                    } else {
                        keyInput.type = 'password';
                        icon.classList.replace('fa-eye-slash', 'fa-eye');
                    }
                });
            }
        });
    },
    
    // Обробка копіювання для всіх кнопок
    bindCopyEvents() {
        $$('.copy-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const targetId = btn.dataset.copyTarget;
                this.copyOutput(targetId);
            });
        });
    },
    
    bindMobileEvents() {
        $('#mobileMenuBtn')?.addEventListener('click', () => {
            console.log('Mobile menu toggled (UI not implemented)');
        });
    },

    // -------------------------------------------------------------------------------------------------
    // === EXPORT ===

    exportData() {
        const data = {
            settings: state.settings,
            history: state.encryptionHistory,
            exportDate: new Date().toISOString()
        };
        
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `encryptor-backup-${new Date().toISOString().split('T')[0]}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        this.showModal('Success', 'Дані успішно експортовано', 'success');
    }
};

// Initialize the app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.encryptorApp = EncryptorApp; 
    EncryptorApp.init();
});