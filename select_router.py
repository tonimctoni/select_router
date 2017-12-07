#!/usr/bin/env python

# Assumtions:
# Desired IP ends with 47
# Mask is always 255.255.255.0
# Interface is eth0

from scapy.all import *
import curses
from os import system


def get_option(screen, options_text, option_list):
    if len(option_list)<1: return -1
    active_element=0
    while True:
        screen.clear()
        screen.border(0)

        screen.addstr(2, 2, options_text, curses.A_BOLD)
        for i, option in enumerate(option_list):
            attribute=curses.A_REVERSE if i==active_element else curses.A_NORMAL
            screen.addstr(4+i, 4, option, attribute)

        screen.refresh()

        pressed_key=screen.getch()
        if pressed_key==ord(' ') or pressed_key==curses.KEY_ENTER or pressed_key==ord('\n'):
            return active_element
        elif pressed_key==curses.KEY_DOWN:
            active_element=(active_element+1)%len(option_list)
        elif pressed_key==curses.KEY_UP:
            active_element=(active_element+len(option_list)-1)%len(option_list)
        elif pressed_key==27:
            return 0

def get_dhcp_response_addresses(attempts, timeout):
    addresses=list()
    for _ in xrange(attempts):
        try:
            conf.checkIPaddr = False
            fam,hw = get_if_raw_hwaddr(conf.iface)
            dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=hw)/DHCP(options=[("message-type","discover"),"end"])
            ans, unans = srp(dhcp_discover, multi=True, timeout=timeout)
        except:
            pass

        for p in ans:
            address=(p[1][Ether].src, p[1][IP].src)
            if not address in addresses:
                addresses.append(address)
    return addresses

def display_commands_return_bool(screen, commands):
    ret=False
    while True:
        screen.clear()
        screen.border(0)

        screen.addstr(2, 2, "Commands: ", curses.A_BOLD)
        for i, command in enumerate(commands):
            screen.addstr(4+i, 4, command)

        screen.addstr(6+len(commands), 6, "NO", curses.A_REVERSE if ret==False else curses.A_NORMAL)
        screen.addstr(6+len(commands), 12, "YES", curses.A_REVERSE if ret==True else curses.A_NORMAL)

        screen.refresh()

        pressed_key=screen.getch()
        if pressed_key==ord(' ') or pressed_key==curses.KEY_ENTER or pressed_key==ord('\n'):
            return ret
        elif pressed_key==curses.KEY_LEFT or pressed_key==curses.KEY_RIGHT:
            ret=not ret
        elif pressed_key==27:
            return False

def display_messages(screen, messages):
    screen.clear()
    screen.border(0)

    for i,message in enumerate(messages):
        screen.addstr(2+i, 2, message, curses.A_NORMAL)
    screen.getch()

def set_router(screen, address):
    router_mac, router_ip=address
    my_ip=router_ip.split(".")
    assert len(my_ip)==4
    my_ip[3]="47"
    my_ip=".".join(my_ip)

    commands=[
        "ip r flush all",
        "ip a flush dev eth0",
        # "ip n flush all",
        # "ip n flush nud all",
        # "ip n replace %s lladdr %s dev eth0"%(router_ip, router_mac),
        "ip a add %s/24 brd + dev eth0"%my_ip,
        "ip r add default via %s"%router_ip,
        "echo \"nameserver %s\" > /etc/resolv.conf"%router_ip,
        "iptables -F",
        "iptables -t nat -F",
        "iptables -P OUTPUT ACCEPT",
        "iptables -P INPUT DROP",
        "iptables -A INPUT --in-interface lo -j ACCEPT",
        "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
    ]

    ok=display_commands_return_bool(screen, commands)
    if not ok:
        display_messages(screen, ["No changes were made.", "Press any key to exit."])
        return

    for command in commands:
        ret=system(command)
        if ret!=0:
            display_messages(screen, ["Error when executing [%s]."%command, "Press any key to exit."])
            return
    
    display_messages(screen, ["Commands executed !!!", "Press any key to exit."])


def main(screen):
    curses.curs_set(0)

    addresses=get_dhcp_response_addresses(2, 2)
    option=get_option(screen, "Select router: ", ["None"]+list(map(lambda x: "%s %s" % x, addresses)))
    if option==0:
        display_messages(screen, ["No changes were made.", "Press any key to exit."])
        return
    set_router(screen, addresses[option-1])



curses.wrapper(main)
