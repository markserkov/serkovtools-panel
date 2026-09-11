RENDER WEB PANEL + WISPBYYTE BOT

Architecture:
- Wispbyte runs index.js (Discord/VK/Telegram bot).
- Render runs panel.js (web admin panel).
- The bot polls Render every 3 seconds over outbound HTTPS, so Wispbyte does not need an open inbound port.

Render environment:
ADMIN_USERNAME=admin
ADMIN_PASSWORD=...
SESSION_SECRET=...
PANEL_BRIDGE_SECRET=...
PORT=10000

Wispbyte environment (add to existing variables):
PANEL_BRIDGE_URL=https://YOUR-SERVICE.onrender.com
PANEL_BRIDGE_SECRET=the_same_secret

Important: set PANEL_BRIDGE_URL to the final Render URL.
