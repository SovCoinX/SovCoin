
Debian
====================
This directory contains files used to package sovd/sov-qt
for Debian-based Linux systems. If you compile sovd/sov-qt yourself, there are some useful files here.

## sov: URI support ##


sov-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install sov-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your sov-qt binary to `/usr/bin`
and the `../../share/pixmaps/sov128.png` to `/usr/share/pixmaps`

sov-qt.protocol (KDE)

