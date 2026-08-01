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
]
