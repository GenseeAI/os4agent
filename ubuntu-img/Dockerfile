FROM ghcr.io/linuxserver/baseimage-selkies:ubuntunoble

# set version label
ARG BUILD_DATE
ARG VERSION
LABEL build_version="Linuxserver.io version:- ${VERSION} Build-date:- ${BUILD_DATE}"
LABEL maintainer="thelamer"
ARG DEBIAN_FRONTEND="noninteractive"

# title
ENV TITLE="Ubuntu KDE" \
    NO_GAMEPAD=true

# Disable libuv io_uring backend container-wide so VSCode's bundled
# Electron/Node runtime (and anything else libuv-based) falls back to
# epoll. CRIU can't dump anon_inode:[io_uring] fds, so leaving this on
# breaks checkpoint of any process that ends up using the io_uring path
# (libuv >=1.49 enables it by default for fs ops).
ENV UV_USE_IO_URING=0

# Force en_US.UTF-8 so Chromium picks up its full prepopulated search-
# engine list (Google, Bing, Yahoo, DuckDuckGo, Ecosia). The base
# image's C.UTF-8 default makes Chromium seed only DuckDuckGo, which
# breaks agent flows like "set Bing as the default search engine".
# Generated below in the apt install layer; declaring here so every
# child process inherits it.
ENV LANG=en_US.UTF-8 \
    LANGUAGE=en_US:en \
    LC_ALL=en_US.UTF-8

RUN \
  echo "**** locale ****" && \
  apt-get update && \
  DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y locales && \
  locale-gen en_US.UTF-8 && \
  update-locale LANG=en_US.UTF-8 && \
  echo "**** add icon ****" && \
  curl -o \
    /usr/share/selkies/www/icon.png \
    https://raw.githubusercontent.com/linuxserver/docker-templates/master/linuxserver.io/img/webtop-logo.png && \
  echo "**** install packages ****" && \
  add-apt-repository ppa:xtradeb/apps && \
  apt-get update && \
  DEBIAN_FRONTEND=noninteractive \
  apt-get install --no-install-recommends -y \
    chromium \
    dolphin \
    gwenview \
    kde-config-gtk-style \
    kdialog \
    kfind \
    khotkeys \
    kio-extras \
    knewstuff-dialog \
    konsole \
    ksystemstats \
    kubuntu-settings-desktop \
    kubuntu-wallpapers \
    kubuntu-web-shortcuts \
    kwin-addons \
    kwin-x11 \
    kwrite \
    plasma-desktop \
    plasma-workspace \
    qml-module-qt-labs-platform \
    systemsettings && \
  echo "**** application tweaks ****" && \
  sed -i \
    's#^Exec=.*#Exec=/usr/local/bin/wrapped-chromium#g' \
    /usr/share/applications/chromium.desktop && \
  echo "**** kde tweaks ****" && \
  sed -i \
    's/applications:org.kde.discover.desktop,/applications:org.kde.konsole.desktop,/g' \
    /usr/share/plasma/plasmoids/org.kde.plasma.taskmanager/contents/config/main.xml && \
  echo "**** cleanup ****" && \
  apt-get autoclean && \
  rm -rf \
    /config/.cache \
    /config/.launchpadlib \
    /var/lib/apt/lists/* \
    /var/tmp/* \
    /tmp/*

# ==== custom packages ====
ENV SAL_USE_VCLPLUGIN=qt5
RUN \
  echo "**** add microsoft repo for vscode ****" && \
  curl -fsSL https://packages.microsoft.com/keys/microsoft.asc \
    | gpg --dearmor -o /usr/share/keyrings/packages.microsoft.gpg && \
  echo "deb [arch=amd64 signed-by=/usr/share/keyrings/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main" \
    > /etc/apt/sources.list.d/vscode.list && \
  echo "**** add mozilla ppa for thunderbird (avoid snap shim) ****" && \
  add-apt-repository -y ppa:mozillateam/ppa && \
  printf 'Package: *\nPin: release o=LP-PPA-mozillateam\nPin-Priority: 1001\n' \
    > /etc/apt/preferences.d/mozilla-ppa && \
  echo "**** install custom apps ****" && \
  apt-get update && \
  DEBIAN_FRONTEND=noninteractive \
  apt-get install --no-install-recommends -y \
    adwaita-icon-theme \
    breeze-icon-theme \
    code \
    fonts-liberation \
    fonts-noto-cjk \
    fonts-noto-color-emoji \
    fonts-noto-core \
    gimp \
    gimp-data-extras \
    gtk2-engines-pixbuf \
    hicolor-icon-theme \
    libaa1 \
    libqt6svg6 \
    librsvg2-common \
    libwmf-0.2-7 \
    mypaint-brushes \
    libreoffice-calc \
    libreoffice-impress \
    libreoffice-qt5 \
    libreoffice-style-breeze \
    libreoffice-writer \
    thunderbird \
    ubuntu-wallpapers \
    ubuntu-wallpapers-jammy \
    vlc && \
  echo "**** wire up CRIU-friendly wrappers for vscode + thunderbird ****" && \
  sed -i \
    's#^Exec=/usr/share/code/code#Exec=/usr/local/bin/wrapped-code#g' \
    /usr/share/applications/code.desktop && \
  sed -i \
    's#^Exec=thunderbird #Exec=/usr/local/bin/wrapped-thunderbird #g' \
    /usr/share/applications/thunderbird.desktop && \
  echo "**** suppress autostarts that derail OSWorld tasks ****" && \
  # Thunderbird's package ships /etc/xdg/autostart/thunderbird.desktop
  # that fires on KDE login, then on first run pops the privacy
  # notice + opens Chromium to its donation URL. Both steal focus
  # from whatever the agent is doing. Drop the autostart entry but
  # keep the desktop icon (10-seed-desktop still copies it to
  # /config/Desktop), so Thunderbird-specific tasks still work — the
  # agent just has to launch it explicitly.
  rm -f /etc/xdg/autostart/thunderbird*.desktop \
        /etc/xdg/autostart/org.mozilla.thunderbird*.desktop && \
  echo "**** cleanup ****" && \
  apt-get autoclean && \
  rm -rf \
    /var/lib/apt/lists/* \
    /var/tmp/* \
    /tmp/*
# ==== end custom packages ====

# ==== xdotool for the bench (Agent-S / OSWorld actions) ====
# pyautogui imports tkinter (~50MB) and the bench's stub workarounds
# were brittle. The image runs kwin_x11 + Xvfb (an X11 session, not
# Wayland), so we replace pyautogui with a tiny shim
# (root/usr/lib/python3/dist-packages/pyautogui.py) that drives
# xdotool. xdotool talks to the X server via XTest — needs no
# /dev/uinput, no daemon, no device passthrough.
RUN \
  apt-get update && \
  DEBIAN_FRONTEND=noninteractive \
  apt-get install --no-install-recommends -y \
    xdotool && \
  apt-get autoclean && \
  rm -rf /var/lib/apt/lists/* /var/tmp/* /tmp/*

# ==== seed desktop shortcuts (mimics common Ubuntu VM layout) ====
# /config is a VOLUME, so anything we write at build time is shadowed
# by user-mounted volumes. Drop a custom-cont-init.d script instead —
# linuxserver's s6 stack runs everything in /custom-cont-init.d/ at
# every boot, so the desktop is seeded into /config/Desktop after the
# volume is mounted.
RUN \
  mkdir -p /custom-cont-init.d && \
  printf '%s\n' \
    '#!/usr/bin/with-contenv bash' \
    'mkdir -p /config/Desktop' \
    'for app in chromium code dolphin firefox gimp konsole \
                libreoffice-calc libreoffice-impress libreoffice-writer \
                org.kde.kwrite systemsettings thunderbird vlc; do' \
    '  src="/usr/share/applications/${app}.desktop"' \
    '  dst="/config/Desktop/${app}.desktop"' \
    '  if [ -f "$src" ] && [ ! -f "$dst" ]; then' \
    '    cp "$src" "$dst"' \
    '    chmod +x "$dst"' \
    '  fi' \
    'done' \
    'chown -R abc:abc /config/Desktop' \
    > /custom-cont-init.d/10-seed-desktop && \
  chmod +x /custom-cont-init.d/10-seed-desktop

# add local files
COPY /root /

# ports and volumes
EXPOSE 3000
VOLUME /config
