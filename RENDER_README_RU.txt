SerkovTools — панель v10

Render Start Command:
npm start

Environment variables:
PANEL_BRIDGE_SECRET=<тот же секрет, что на Wispbyte>
SESSION_SECRET=<длинный случайный секрет>
VK_CLIENT_ID=<ID приложения VK>
VK_CLIENT_SECRET=<секрет приложения VK>
VK_REDIRECT_URI=https://serkovtools-panel.onrender.com/auth/vk/callback
VK_BOOTSTRAP_ID=<VK ID владельца, который получит первый доступ>
VK_BOOTSTRAP_DISCORD_ID=<Discord ID владельца>

Авторизация теперь ТОЛЬКО через VK. Логин/пароль больше не используются.
Первый владелец создаётся автоматически при первом входе, если его VK ID совпадает с VK_BOOTSTRAP_ID.

После входа владелец может создавать профили администрации: VK ID, Discord ID, причина назначения, уровень 1–8 и должность.
Обычный пользователь без созданного профиля получает отказ в доступе.

Статистика сообщений Discord считается ботом по Discord ID зарегистрированных администраторов.
Неделя: понедельник 00:00 — воскресенье 23:59 по МСК.
Снимок статистики обновляется каждые 6 часов по МСК.

Важно: URL OAuth в настройках VK должен точно совпадать с VK_REDIRECT_URI.


ИСПРАВЛЕНИЕ VK OAuth: удалён scope=email, из-за которого VK мог возвращать invalid_request / invalid scope для текущей конфигурации приложения. Авторизация запрашивает только базовую идентификацию пользователя.
