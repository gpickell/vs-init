# vs-init

Sets up a Windows machine to manage a VertiGIS Studio Docker deployment running on a remote
Linux host, using VS Code's Remote-SSH as the day-to-day interface. No Linux command-line
experience required -- the tool handles that side for you.

## What it does

Run it once per machine, and once per remote host you want to manage. It installs whatever's
missing (VS Code, the Remote-SSH extension pack, an SSH key, a small companion extension), sets
up an SSH profile for your host, provisions the host itself (Docker, permissions), and opens VS
Code connected to it. Everything after that happens inside VS Code -- look for the **Guidance**
button in the side panel for a full walkthrough of what you're looking at and what each thing
does.

A reusable shortcut gets created automatically along the way, so you won't need to run this tool
again just to get back into a deployment you've already set up.

## Requirements

- Windows 10/11
- [uv](https://docs.astral.sh/uv/getting-started/installation/) -- if you don't have it yet:
  ```powershell
  winget install uv
  ```

## Run it

```powershell
uvx --from git+https://github.com/gpickell/vs-init vs-init
```

You'll be walked through everything from there, with an explanation of what's happening and why
at each step.
