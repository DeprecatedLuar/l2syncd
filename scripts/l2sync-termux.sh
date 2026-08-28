#!/data/data/com.termux/files/usr/bin/sh
# termux-services run script for l2sync.
#
# Install:
#   mkdir -p ~/.config/termux-services/l2sync/log
#   cp scripts/l2sync-termux.sh ~/.config/termux-services/l2sync/run
#   chmod +x ~/.config/termux-services/l2sync/run
#   printf '#!/data/data/com.termux/files/usr/bin/sh\nexec svlogd -tt ./log\n' \
#       > ~/.config/termux-services/l2sync/log/run
#   chmod +x ~/.config/termux-services/l2sync/log/run
#   sv-enable l2sync
#   sv up l2sync
#
# Adjust the binary path below if l2sync is not on Termux's default PATH.
exec l2sync run
