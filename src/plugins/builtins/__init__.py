"""
Built-in OSINT tool plugins for Ghost Identity Hunter.

This directory contains the default plugin implementations
for various OSINT tools.
"""

from .username_search_plugin import UsernameSearchPlugin
from .email_breach_plugin import EmailBreachPlugin
from .phone_validation_plugin import PhoneValidationPlugin
from .sherlock_plugin import SherlockPlugin
from .theharvester_plugin import TheHarvesterPlugin
from .shodan_plugin import ShodanPlugin
from .whois_plugin import WhoisPlugin
from .dig_plugin import DigPlugin
from .google_dorks_plugin import GoogleDorksPlugin
from .profile_image_plugin import ProfileImagePlugin
from .maigret_plugin import MaigretPlugin
from .holehe_plugin import HolehePlugin
from .subfinder_plugin import SubfinderPlugin
from .sublist3r_plugin import Sublist3rPlugin
from .amass_plugin import AmassPlugin
from .whatweb_plugin import WhatWebPlugin
from .nmap_plugin import NmapPlugin
from .exiftool_plugin import ExifToolPlugin
from .wayback_plugin import WaybackMachinePlugin
from .osrframework_plugin import OsrframeworkPlugin

__all__ = [
    'UsernameSearchPlugin',
    'EmailBreachPlugin',
    'PhoneValidationPlugin',
    'SherlockPlugin',
    'TheHarvesterPlugin',
    'ShodanPlugin',
    'WhoisPlugin',
    'DigPlugin',
    'GoogleDorksPlugin',
    'ProfileImagePlugin',
    'MaigretPlugin',
    'HolehePlugin',
    'SubfinderPlugin',
    'Sublist3rPlugin',
    'AmassPlugin',
    'WhatWebPlugin',
    'NmapPlugin',
    'ExifToolPlugin',
    'WaybackMachinePlugin',
    'OsrframeworkPlugin',
]
