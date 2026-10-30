# EmailZit appliance: the setup menu starts when ezadmin signs in on the
# server's own screen (not over SSH). Leave it for a command line; open it
# again with: sudo emailzit-setup
case "$(tty 2>/dev/null)" in
/dev/tty[0-9]*)
    if [ "$(id -un)" = ezadmin ] && [ -z "${EZ_MENU_SHOWN:-}" ]; then
        export EZ_MENU_SHOWN=1
        sudo -n /usr/local/sbin/emailzit-setup
    fi
    ;;
esac
