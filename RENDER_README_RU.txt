SERKOVTOOLS — ПАНЕЛЬ С АВТОРИЗАЦИЕЙ TELEGRAM

1. Render Environment
Добавьте:

PANEL_BRIDGE_SECRET=тот_же_секрет_что_на_Wispbyte
SESSION_SECRET=длинный_случайный_секрет
TELEGRAM_CLIENT_ID=Client_ID_из_BotFather
TELEGRAM_CLIENT_SECRET=Client_Secret_из_BotFather
TELEGRAM_REDIRECT_URI=https://serkovtools-panel.onrender.com/auth/telegram/callback
TELEGRAM_BOOTSTRAP_ID=ваш_Telegram_ID
TELEGRAM_BOOTSTRAP_DISCORD_ID=ваш_Discord_ID

Старые VK_CLIENT_ID, VK_CLIENT_SECRET, VK_REDIRECT_URI для этой версии не нужны.

2. Telegram / BotFather
Используйте Telegram-бота, который будет представлять приложение.
В @BotFather откройте настройки бота и раздел Login / Web Login (название может отличаться в интерфейсе).
Добавьте Allowed URL / Redirect URL:
https://serkovtools-panel.onrender.com/auth/telegram/callback

BotFather выдаст Client ID и Client Secret. Секрет храните только в Render.

3. Авторизация
Кнопка «Войти через Telegram» открывает официальный Telegram OAuth OIDC.
После согласия Telegram возвращает code на callback. Сервер обменивает code на ID token, проверяет подпись Telegram и только после этого создаёт сессию.

4. Bootstrap-владелец
TELEGRAM_BOOTSTRAP_ID — ваш числовой Telegram ID.
Если такого администратора ещё нет, при первом успешном входе он автоматически создаётся с уровнем 8 и ролью «Владелец».

5. Добавление других администраторов
В панели: Администрация → Добавить.
Поля:
- Telegram ID
- Discord ID
- причина назначения
- уровень 1–8
- должность

Обычный пользователь без созданного профиля в панель не попадёт.

6. Render
Build Command: npm install
Start Command: npm start

Официальная документация Telegram Login:
https://core.telegram.org/bots/telegram-login


ИСПРАВЛЕНИЕ v14
- В запрос Telegram OIDC добавлен обязательный параметр bot_id.
- Для текущей конфигурации bot_id передаётся тем же числовым значением, что и TELEGRAM_CLIENT_ID (8805088937).
- Redirect URI остаётся https://serkovtools-panel.onrender.com/auth/telegram/callback.
