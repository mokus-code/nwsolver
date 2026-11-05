# nwsolver — a friendly internet doctor for your Linux computer

**A small, friendly desktop app that tells you why the internet isn't working —
and what to do about it — in plain words.**

It's made for everyday use, and especially for travel: hotel, café and airport
Wi-Fi, coworking spaces, mobile hotspots.

## What it does

Open it like any other app. Within a few seconds it explains one of three things:

- **"I have no internet."** It shows where the connection breaks — from your
  Wi-Fi or cable, through your router and your provider, all the way to the
  website — and points at the first thing that's wrong.
- **"The internet is very slow."** It checks your Wi-Fi, your local network,
  your provider and the real speed, then says what is slowing you down.
- **"This website won't open."** It tells you whether the problem is on your
  side, blocked somewhere along the way, or the site itself is down.

Every result comes with a short **"what to do"** hint.

## Perfect for travel

- Hotel or café Wi-Fi that asks you to sign in — the app notices the login page
  instead of pretending you're online.
- Wi-Fi says "connected" but nothing loads — you see exactly which step fails.
- A VPN or proxy left on from your last country.
- Slow hotel Wi-Fi — it says whether the Wi-Fi, the hotel network or your
  provider is to blame.
- A booking, airline or bank site that won't open — it tells you why.
- A wrong clock after changing time zones — it explains the strange security
  warnings.

## Install — three steps

1. **Download the installer** from the
   [latest release](https://github.com/mokus-code/nwsolver/releases/latest)
   (the file named `nwsolver_…_amd64.deb`).
2. **Open the downloaded file.** Your software installer will offer to install
   it — press **Install** and enter your password when asked.
3. **Find nwsolver** in the application menu (search for "nwsolver") and open
   it. That's it.

If you prefer the terminal, this one line does the same:

```sh
sudo apt install ./nwsolver_0.2.0_amd64.deb
```

Works on Ubuntu, Linux Mint, Debian and most other modern Linux desktops.

## Using it

- The check starts by itself. Read the cards from top to bottom — the first red
  one is usually the cause.
- "Details" shows what was measured.
- You can copy a short summary with one click and paste it into an AI chat or
  send it to a friend who can help.
- Wanting a second opinion? You can optionally connect your own AI assistant
  in the Tools menu.
- If the text is too small, use **View → Larger text**.

## Privacy

Everything is checked on your own computer. Nothing is sent anywhere unless you
choose to ask an AI assistant.
