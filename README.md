# CookieCrumbs

A Chrome extension that analyzes cookies on websites, scores site privacy, and protects you while you browse. Everything runs locally in your browser.

## Features

### Detection and classification

- **Cookie detection:** Sees first-party, third-party, session, persistent, JavaScript-set, and partitioned cookies.
- **Cookie classification:** Sorts cookies into five categories by purpose: Strict, Performance, Functionality, Advertising, and Unknown.
- **Full cookie table:** Lists each cookie by name, party, lifespan, and security flags. Select a row for details about that cookie.
- **Privacy score:** Shows a score from 0 to 100 with a plain-English label, based on cookie category, party, persistence, and known-tracker status.

### Protection

- **Tracking Protection:** Blocks tracking cookies as you browse and stops tracker-domain requests at the network level. Authentication and site-essential cookies are always preserved. Tracking Protection is always on by design and has no off switch.
- **Session Guard:** Removes weak session cookies after you leave a site. These cookies are missing Secure or HttpOnly and could be hijacked later. You can turn Session Guard on or off at any time.
- **Consent Transparency:** Before you accept a cookie banner, CookieCrumbs pauses and shows what data will be collected and which companies will receive it.

### Controls

- **Per-site exemptions:** Maintain separate whitelists for Tracking Protection and Session Guard. If a site breaks, select **Exempt this site**.
- **Settings page:** Open it using the gear icon in the panel.

## Install

1. Download or clone the project.
2. Open `chrome://extensions` in Chrome.
3. Enable **Developer mode**.
4. Select **Load unpacked** and choose the `cookiecrumbs-v2` folder.

## Requirements

Chrome or another Chromium-based browser with Manifest V3 support.
