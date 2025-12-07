# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

HF Space Manager is a monitoring dashboard for HuggingFace Spaces instances. It provides real-time metrics, status monitoring, and management controls (restart/rebuild) for HuggingFace Spaces. Includes scheduled auto-restart and keep-alive features to prevent spaces from sleeping.

## Commands

```bash
# Install dependencies
npm install

# Run the server (default port 8080)
npm start

# Build Docker image
docker build -t hf-space-manager .

# Run with Docker
docker run -d -p 8080:8080 \
  -e HF_USER="user1:token1,user2:token2" \
  -e API_KEY="your_api_key" \
  -e USER_NAME="admin" \
  -e USER_PASSWORD="password" \
  hf-space-manager
```

## Architecture

This is a single-file Node.js/Express application with an embedded frontend:

### Backend (`server.js`)
- **Express server** serving static files from `public/` and API endpoints
- **Session management**: In-memory Map storing auth tokens (24h expiry)
- **SpaceCache class**: Caches HuggingFace API responses (5-minute expiry)
- **MetricsConnectionManager class**: Manages SSE connections to HuggingFace live-metrics endpoints, multiplexes to browser clients
- **Scheduled Restart**: In-memory Map storing per-instance restart schedules with setInterval timers
- **Keep-Alive System**: Global and per-instance HTTP pings to prevent HuggingFace spaces from sleeping (48h inactivity limit)
- **Two API layers**:
  - Internal APIs (`/api/*`): Used by the frontend (login, spaces list, restart/rebuild, schedules)
  - External APIs (`/api/v1/*`): RESTful API for third-party apps, requires `API_KEY` auth

### Frontend (`public/index.html`)
- Single HTML file with embedded CSS and JavaScript (no build step)
- Uses Chart.js for real-time metrics visualization
- SSE-based live updates via `MetricsStreamManager` class
- Modern minimalist UI with Inter font
- Light/Dark/System theme support with CSS variables

### Key Data Flow
1. Frontend fetches spaces list from `/api/proxy/spaces`
2. Backend fetches from HuggingFace API, caches results
3. Frontend establishes SSE connection to `/api/proxy/live-metrics-stream`
4. Backend maintains upstream SSE connections to HuggingFace live-metrics
5. Metrics are multiplexed from HuggingFace to all subscribed browser clients

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `HF_USER` | Format: `username:token,username2:token2` - HuggingFace users and their API tokens | Yes |
| `API_KEY` | Key for external API authentication | No |
| `USER_NAME` | Dashboard login username (default: `admin`) | No |
| `USER_PASSWORD` | Dashboard login password (default: `password`) | No |
| `PORT` | Server port (default: `8080`) | No |
| `SHOW_PRIVATE` | Show private spaces when not logged in (default: `false`) | No |

## API Endpoints

### Internal (Frontend)
- `GET /api/config` - Get configured usernames
- `POST /api/login` - Login with username/password
- `POST /api/verify-token` - Verify session token
- `POST /api/logout` - Logout
- `GET /api/proxy/spaces` - Get all spaces (filtered by auth status)
- `POST /api/proxy/restart/:repoId` - Restart a space (requires auth)
- `POST /api/proxy/rebuild/:repoId` - Rebuild a space (requires auth)
- `GET /api/proxy/live-metrics-stream` - SSE endpoint for live metrics

### Schedule Management (requires auth)
- `GET /api/schedule/restart/:repoId` - Get scheduled restart config
- `POST /api/schedule/restart/:repoId` - Set scheduled restart (body: `{enabled, intervalHours}`)
- `GET /api/keepalive/:repoId` - Get keep-alive config for instance
- `POST /api/keepalive/:repoId` - Set keep-alive (body: `{enabled, intervalMinutes}`)
- `GET /api/keepalive-global` - Get global keep-alive config
- `POST /api/keepalive-global` - Set global keep-alive (body: `{enabled, intervalMinutes}`)
- `GET /api/schedule/status` - Get all scheduled tasks status

### External (Third-party)
- `GET /api/v1/info/:token` - Get user's spaces list
- `GET /api/v1/info/:token/:spaceId` - Get space details
- `POST /api/v1/action/:token/:spaceId/restart` - Restart space
- `POST /api/v1/action/:token/:spaceId/rebuild` - Rebuild space

All external APIs require `Authorization: Bearer <API_KEY>` header.
