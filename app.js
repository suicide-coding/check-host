const { createApp } = Vue;

createApp({
    data() {
        return {
            hostInput: '',
            isChecking: false,
            currentHost: '',
            results: [],
            targetInfo: null,
            notifications: [],
            notificationId: 0,
            isCopying: false,
            checkTypes: {
                http: true,
                ping: true,
                dns: true,
                traceroute: false
            },
            locationData: {
                'Хельсинки, Финляндия': { icon: 'fas fa-flag', region: 'finland' }
            }
        }
    },
    methods: {
        async checkHost() {
            if (!this.hostInput.trim()) {
                this.showNotification('error', 'Ошибка', 'Пожалуйста, введите домен или IP-адрес');
                return;
            }
            this.isChecking = true;
            this.currentHost = this.hostInput.trim();
            this.results = [];
            this.showNotification('info', 'Проверка началась', `Начинаем проверку ${this.currentHost} из Хельсинки...`);
            const selectedCheckTypes = this.getSelectedCheckTypes();
            if (selectedCheckTypes.length === 0) {
                this.showNotification('error', 'Ошибка', 'Пожалуйста, выберите хотя бы один тип проверки');
                this.isChecking = false;
                return;
            }
            try {
                const response = await fetch('check_host.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        host: this.currentHost,
                        checkTypes: this.checkTypes
                    })
                });
                const data = await response.json();
                if (!response.ok) {
                    throw new Error(data.message || 'Ошибка сервера');
                }
                if (!data.success) {
                    throw new Error(data.message || 'Ошибка при выполнении проверки');
                }
                this.results = data.data.results;
                this.targetInfo = data.data.target_info;
                this.isChecking = false;
                const successCount = this.getSummaryCount('success');
                const totalCount = this.results.length;
                if (successCount === totalCount) {
                    this.showNotification('success', 'Проверка завершена', `Все ${totalCount} проверок из Хельсинки прошли успешно!`);
                } else if (successCount > totalCount / 2) {
                    this.showNotification('warning', 'Проверка завершена', `${successCount} из ${totalCount} проверок из Хельсинки прошли успешно`);
                } else {
                    this.showNotification('error', 'Проверка завершена', `Только ${successCount} из ${totalCount} проверок из Хельсинки прошли успешно`);
                }
            } catch (error) {
                this.isChecking = false;
                this.showNotification('error', 'Ошибка', error.message);
            }
        },
        getSelectedLocations() {
            return ['Хельсинки, Финляндия'];
        },
        getSelectedCheckTypes() {
            const types = [];
            if (this.checkTypes.http) types.push('http');
            if (this.checkTypes.ping) types.push('ping');
            if (this.checkTypes.dns) types.push('dns');
            if (this.checkTypes.traceroute) types.push('traceroute');
            return types;
        },
        showNotification(type, title, message, duration = 5000) {
            const notification = {
                id: ++this.notificationId,
                type: type,
                title: title,
                message: message,
                delay: duration
            };
            this.notifications.push(notification);
            setTimeout(() => {
                this.removeNotification(notification.id);
            }, duration);
        },
        removeNotification(id) {
            const index = this.notifications.findIndex(n => n.id === id);
            if (index !== -1) {
                this.notifications[index].removing = true;
                setTimeout(() => {
                    this.notifications.splice(index, 1);
                }, 300);
            }
        },
        getNotificationIcon(type) {
            const icons = {
                success: 'fas fa-check-circle',
                warning: 'fas fa-exclamation-triangle',
                error: 'fas fa-times-circle',
                info: 'fas fa-info-circle'
            };
            return icons[type] || 'fas fa-bell';
        },
        getResultsByType(type) {
            return this.results.filter(result => result.type === type);
        },
        getStatusClass(status) {
            const classes = {
                success: 'status-success',
                warning: 'status-warning',
                error: 'status-error',
                info: 'status-info'
            };
            return classes[status] || 'status-info';
        },
        getExplanationClass(status) {
            const classes = {
                success: 'text-success',
                warning: 'text-warning',
                error: 'text-danger',
                info: 'text-info'
            };
            return classes[status] || 'text-muted';
        },
        getLocationIcon(location) {
            if (location.includes('Хельсинки') || location.includes('Финляндия')) {
                return 'fas fa-flag';
            }
            return 'fas fa-map-marker-alt';
        },
        getSummaryCount(status) {
            return this.results.filter(result => result.status === status).length;
        },
        delay(ms) {
            return new Promise(resolve => setTimeout(resolve, ms));
        },
        showTracerouteDetails(result) {
            let details = `Traceroute для ${this.currentHost}\n\n`;
            if (result.hops && result.hops.length > 0) {
                details += 'Маршрут:\n';
                result.hops.forEach(hop => {
                    if (hop.times) {
                        const times = hop.times.map(t => t === 'timeout' ? '*' : t + 'ms').join(' ');
                        details += `${hop.hop}. ${hop.ip} - ${times}\n`;
                    } else {
                        details += `${hop.hop}. ${hop.hostname} (${hop.ip}) - ${hop.time}ms\n`;
                    }
                });
            } else {
                details += 'Детали маршрута недоступны\n';
            }
            if (result.rawOutput) {
                details += `\nСырой вывод:\n${result.rawOutput}`;
            }
            alert(details);
        },
        copyTargetInfo() {
            if (!this.targetInfo) {
                this.showNotification('error', 'Ошибка', 'Информация о хосте недоступна');
                return;
            }
            this.isCopying = true;
            let infoText = `Информация о целевом хосте: ${this.currentHost}\n`;
            infoText += `Проверка из: Хельсинки, Финляндия\n`;
            infoText += `Дата проверки: ${new Date().toLocaleString('ru-RU')}\n\n`;
            infoText += `IP адрес: ${this.targetInfo.ip}\n`;
            infoText += `Страна: ${this.targetInfo.country}\n`;
            infoText += `Город: ${this.targetInfo.city}\n`;
            infoText += `Регион: ${this.targetInfo.region}\n`;
            infoText += `Провайдер: ${this.targetInfo.isp}\n`;
            infoText += `Организация: ${this.targetInfo.org}\n`;
            infoText += `ASN: ${this.targetInfo.asn}\n`;
            infoText += `Часовой пояс: ${this.targetInfo.timezone}\n`;
            let connectionTypes = [];
            if (this.targetInfo.mobile) connectionTypes.push('Мобильное');
            if (this.targetInfo.proxy) connectionTypes.push('Прокси');
            if (this.targetInfo.hosting) connectionTypes.push('Хостинг');
            if (connectionTypes.length === 0) connectionTypes.push('Обычное');
            infoText += `Тип соединения: ${connectionTypes.join(', ')}\n`;
            if (this.targetInfo.coordinates && this.targetInfo.coordinates.lat && this.targetInfo.coordinates.lon) {
                infoText += `Координаты: ${this.targetInfo.coordinates.lat}, ${this.targetInfo.coordinates.lon}\n`;
            }
            if (navigator.clipboard && window.isSecureContext) {
                navigator.clipboard.writeText(infoText).then(() => {
                    this.showNotification('success', 'Скопировано!', 'Информация о хосте скопирована в буфер обмена');
                    this.resetCopyButton();
                }).catch(() => {
                    this.fallbackCopyTextToClipboard(infoText);
                });
            } else {
                this.fallbackCopyTextToClipboard(infoText);
            }
        },
        fallbackCopyTextToClipboard(text) {
            const textArea = document.createElement('textarea');
            textArea.value = text;
            textArea.style.position = 'fixed';
            textArea.style.left = '-999999px';
            textArea.style.top = '-999999px';
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();
            try {
                const successful = document.execCommand('copy');
                if (successful) {
                    this.showNotification('success', 'Скопировано!', 'Информация о хосте скопирована в буфер обмена');
                    this.resetCopyButton();
                } else {
                    this.showNotification('error', 'Ошибка', 'Не удалось скопировать информацию');
                    this.resetCopyButton();
                }
            } catch (err) {
                this.showNotification('error', 'Ошибка', 'Не удалось скопировать информацию');
                this.resetCopyButton();
            }
            document.body.removeChild(textArea);
        },
        resetCopyButton() {
            setTimeout(() => {
                this.isCopying = false;
            }, 2000);
        }
    },
    mounted() {
        this.checkTypes = {
            http: true,
            ping: true,
            dns: true,
            traceroute: false
        };
        setTimeout(() => {
            this.showNotification('info', 'Добро пожаловать!', 'Введите домен или IP-адрес для проверки доступности из Хельсинки, Финляндия', 4000);
        }, 1000);
    }
}).mount('#app'); 