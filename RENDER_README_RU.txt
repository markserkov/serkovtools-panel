SerkovTools — панель v11 (VK Mini App auth)

Render Start Command:
npm start

Environment variables:
PANEL_BRIDGE_SECRET=<тот же секрет, что на Wispbyte>
SESSION_SECRET=<длинный случайный секрет>
VK_CLIENT_ID=<ID приложения VK Mini App>
VK_CLIENT_SECRET=<защищённый ключ приложения VK Mini App>
VK_BOOTSTRAP_ID=<VK ID владельца, который получит первый доступ>
VK_BOOTSTRAP_DISCORD_ID=<Discord ID владельца>

ВАЖНО:
Авторизация теперь выполняется через подписанные launch-параметры VK Mini Apps.
VK_REDIRECT_URI больше НЕ нужен. Переменную можно удалить из Render.

В настройках VK Mini App → Размещение укажите:
https://serkovtools-panel.onrender.com

При запуске Mini App VK добавляет к URL параметры вида vk_app_id, vk_user_id, vk_ts и sign.
Панель на сервере проверяет подпись sign с помощью VK_CLIENT_SECRET и только после успешной проверки создаёт сессию.
Это соответствует серверной проверке launch params VK Mini Apps.

Первый владелец создаётся автоматически при первом запуске, если его VK ID совпадает с VK_BOOTSTRAP_ID.
После входа владелец может создавать профили администрации: VK ID, Discord ID, причина назначения, уровень 1–8 и должность.
Обычный пользователь без созданного профиля получает отказ в доступе.

Статистика сообщений Discord считается ботом по Discord ID зарегистрированных администраторов.
Неделя: понедельник 00:00 — воскресенье 23:59 по МСК.
Снимок статистики обновляется каждые 6 часов по МСК.

Защищённый ключ VK никогда не размещайте в клиентском JavaScript и не отправляйте в чат.
