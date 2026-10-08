# Install

Download the package for the machine you are sitting at from the [0.2.8 release](https://github.com/danieldejager/mcparser/releases/tag/v0.2.8). A version tag builds these. You do not pack them by hand.

On a Mac with Apple silicon, open `McParser-0.2.8-arm64.dmg` and drag McParser to Applications. The image is not signed. Chrome marks the download, and Gatekeeper then says the app is damaged. That message is the missing signature, not a broken file. After you have dragged the app across, clear the mark and open it.

```bash
xattr -cr /Applications/McParser.app
open /Applications/McParser.app
```

Signing waits until the product is ready for it. Until then, that pair of commands is the way in.

On Windows 11 for ARM, run `McParser Setup 0.2.8.exe`. This installer does not run on an Intel PC. If the laptop is Intel, stop here. There is no Intel package yet.

On Ubuntu, the Intel and AMD package is `mcparser-ui_0.2.8_amd64.deb`. The ARM package is `mcparser-ui_0.2.8_arm64.deb`.

```bash
wget https://github.com/danieldejager/mcparser/releases/download/v0.2.8/mcparser-ui_0.2.8_amd64.deb
sudo apt install ./mcparser-ui_0.2.8_amd64.deb
```

`apt` may warn that the package is unsigned. That is the same gap as the Mac image. To remove it later, `sudo apt remove mcparser-ui`.

The first window you see is empty. That is expected. McParser does not ship a sample case. The next chapter is how you give it a log.
