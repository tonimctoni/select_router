#!/usr/bin/env python

""" Sends DHCP request and lets user decide which response to use to confugure IP.

Assumptions:
    Network interface is eth0
"""

from scapy.all import *
import curses
from os import system


def get_option(screen, options_text, option_list):
    """ Shows options from `option_list` and lets the user pick one.

    Args:
        screen (_curses.curses window): Window object that represents the screen.
        options_text (str): Options caption.
        option_list (list<str>): List of options to be presented to the user.

    Returns:
        int: Index of the selected option. Default is 0. On error -1.
    """
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

def get_dhcp_responses(attempts, timeout):
    """ Send `attempts` number of dhcp requests and returns response data.

    Args:
        attempts (int): Number of times the dhcp packet should be sent.
        timeout (int): Timeout for response.

    Returns:
        str: Source MAC address from response.
        str: Source IP address from response.
        str: Destination IP address from response.
        str: Yiaddr in BOOTP header.
        str: Router IP option in DHCP package.
        str: Name server IP option in DHCP package.
        str: Broadcast address option in DHCP package.
        str: Subnet mask option in DHCP package.
        str: Domain option in DHCP package.
    """
    def get_field(options, field):
        filtered=filter(lambda x: x[0]==field, options)
        return filtered[0][1] if len(filtered)>0 else ""

    responses=list()
    for _ in xrange(attempts):
        try:
            conf.checkIPaddr = False
            fam,hw = get_if_raw_hwaddr(conf.iface)
            dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=hw)/DHCP(options=[("message-type","discover"),"end"])
            ans, unans = srp(dhcp_discover, multi=True, timeout=timeout)
        except:
            pass

        for p in ans:
            response=(
                p[1][Ether].src,
                p[1][IP].src,
                p[1][IP].dst,
                ans[0][1][BOOTP].yiaddr,
                get_field(p[1][DHCP].options, "router"),
                get_field(p[1][DHCP].options, "name_server"),
                get_field(p[1][DHCP].options, "broadcast_address"),
                get_field(p[1][DHCP].options, "subnet_mask"),
                get_field(p[1][DHCP].options, "domain"),
                )
            if not response in responses:
                responses.append(response)
    return responses

def display_dhcp_response_and_commands(screen, dhcp_response, commands):
    """ Displays dhcp response data and commands to be executed. Gives the user a [cancel|accept] option.

    Args:
        screen (_curses.curses window): Window object that represents the screen.
        dhcp_response (str,str,str,str,str,str,str,str,str): DHCP response data.
        commands: (list<str>): List of commands to be executed.

    Returns:
        bool: True if user picked `accept`, False if user picked `cancel`. Default is False (if escape is pressed).
    """
    ret=False
    while True:
        screen.clear()
        screen.border(0)

        screen.addstr(2, 2, "DHCP Response: ", curses.A_BOLD)
        screen.addstr(4+0, 4, "MAC Source Address:\t\t"+dhcp_response[0])
        screen.addstr(4+1, 4, "Source IP Address:\t\t"+dhcp_response[1])
        screen.addstr(4+2, 4, "Destination IP Address:\t"+dhcp_response[2])
        screen.addstr(4+3, 4, "BOOTP Your Ip:\t\t"+dhcp_response[3])
        screen.addstr(4+4, 4, "Router IP Address:\t\t"+dhcp_response[4])
        screen.addstr(4+5, 4, "Name Server Address:\t"+dhcp_response[5])
        screen.addstr(4+6, 4, "Broadcast Address:\t\t"+dhcp_response[6])
        screen.addstr(4+7, 4, "Subnet Mask:\t\t"+dhcp_response[7])
        screen.addstr(4+8, 4, "Domain:\t\t\t"+dhcp_response[8])

        screen.addstr(14, 2, "Commands: ", curses.A_BOLD)
        for i, command in enumerate(commands):
            screen.addstr(16+i, 4, command)

        screen.addstr(18+len(commands), 6, "CANCEL", curses.A_REVERSE if ret==False else curses.A_NORMAL)
        screen.addstr(18+len(commands), 15, "ACCEPT", curses.A_REVERSE if ret==True else curses.A_NORMAL)

        screen.refresh()

        pressed_key=screen.getch()
        if pressed_key==ord(' ') or pressed_key==curses.KEY_ENTER or pressed_key==ord('\n'):
            return ret
        elif pressed_key==curses.KEY_LEFT or pressed_key==curses.KEY_RIGHT:
            ret=not ret
        elif pressed_key==27:
            return False

def display_messages(screen, messages):
    """ Displays messages on screen until a key is pressed.

    Args:
        screen (_curses.curses window): Window object that represents the screen.
        messages: (list<str>): List of messages to be displayed.

    Returns:
        None
    """
    screen.clear()
    screen.border(0)

    for i,message in enumerate(messages):
        screen.addstr(2+i, 2, message, curses.A_NORMAL)
    screen.getch()

def configure_ip_according_to_dhcp_response(screen, dhcp_response):
    """ Sets IP address, subnet mask, broadcast address, default gateway, and name server according to `dhcp_response`.
    Only if uses agrees.

    Args:
        screen (_curses.curses window): Window object that represents the screen.
        dhcp_response (str,str,str,str,str,str,str,str,str): DHCP response data.

    Returns:
        bool: True if ip gets configured. False otherwise (user stops it or there is an error).
    """
    def get_mask_bits(mask):
        return sum(map(lambda x: bin(int(x)).count("1"), mask.split(".")))

    commands=[
        "ip r flush all",
        "ip a flush dev eth0",
        "ip n flush all",
        "ip n flush nud all",
        "ip n replace %s lladdr %s dev eth0"%(dhcp_response[1], dhcp_response[0]),
        "ip a add %s/%i brd %s dev eth0"%(dhcp_response[2], get_mask_bits(dhcp_response[7]), dhcp_response[6]),
        "ip r add default via %s"%dhcp_response[4],
        "echo \"nameserver %s\" > /etc/resolv.conf"%dhcp_response[5],
        "iptables -F",
        "iptables -t nat -F",
        "iptables -P OUTPUT ACCEPT",
        "iptables -P INPUT DROP",
        "iptables -A INPUT --in-interface lo -j ACCEPT",
        "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
    ]

    ok=display_dhcp_response_and_commands(screen, dhcp_response, commands)
    if not ok:
        # display_messages(screen, ["No changes were made.", "Press any key to continue."])
        return False

    for command in commands:
        ret=system(command)
        if ret!=0:
            display_messages(screen, ["Error when executing [%s]."%command, "Press any key to continue."])
            return False
    
    display_messages(screen, ["Commands executed !!!", "Press any key to exit."])
    return True

def main(screen):
    curses.curs_set(0)

    dhcp_responses=get_dhcp_responses(2, 2)
    while True:
        option=get_option(screen, "Select router: ", ["None"]+list(map(lambda x: "%s %s" % x[:2], dhcp_responses)))
        if option<=0:
            display_messages(screen, ["Press any key to exit."])
            break
        if configure_ip_according_to_dhcp_response(screen, dhcp_responses[option-1]): break

curses.wrapper(main)