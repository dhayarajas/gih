"""Tests for the per-tool output parsers.

Every fixture below reproduces the shape of a real run of the tool -- the
maigret NDJSON row, the whatweb plugin map, the nmap XML element tree, the
whois key repetition -- with the personal detail replaced, so a regression in
a parser shows up as a lost field rather than as a report that looks fine.
"""

import json

from src.modules import tool_parsers

# One NDJSON row per checked site, as `maigret -J ndjson` writes them.
MAIGRET_NDJSON = "\n".join(json.dumps(row) for row in [
    {
        "username": "octocat",
        "sitename": "Twitter",
        "site": {"tags": ["messaging", "social"]},
        "status": {
            "site_name": "Twitter",
            "url": "https://twitter.com/octocat",
            "status": "Claimed",
            "ids": {
                "uid": "44196397",
                "fullname": "Octo Cat",
                "bio": "engineer",
                "location": "San Francisco",
                "image": "https://pbs.twimg.com/profile/octocat.jpg",
                "created_at": "2009-06-02 20:12:29+00:00",
                "follower_count": "241196304",
                "_extractor": "Twitter GraphQL API",
            },
        },
    },
    {
        "username": "octocat",
        "sitename": "Pinterest",
        "status": {
            "site_name": "Pinterest",
            "url": "https://www.pinterest.com/octocat/",
            "status": "Claimed",
            "ids": {"uid": "426364427130898868", "fullname": "Octo Cat",
                    "posts_count": "36"},
        },
    },
    {
        "username": "octocat",
        "sitename": "Facebook",
        "status": {"site_name": "Facebook", "url": "https://facebook.com/octocat",
                   "status": "Available"},
    },
    {"username": "octocat", "sitename": "Broken"},
])

MAIGRET_TREE = """[+] Twitter: https://twitter.com/octocat
 \u251c\u2500fullname: Octo Cat
 \u2514\u2500_extractor: Twitter GraphQL API
"""

HOLEHE_CSV = """name,domain,method,frequent_rate_limit,rateLimit,exists,emailrecovery,phoneNumber,others
adobe,adobe.com,password recovery,False,True,False,,,
twitter,twitter.com,register,False,False,True,,,
instagram,instagram.com,register,False,False,True,o****t@gm***.com,+1******89,
spotify,spotify.com,login,False,False,False,,,
"""

THEHARVESTER_JSON = json.dumps({
    "cmd": "-d example.com -b duckduckgo",
    "emails": ["press@example.com", "abuse@example.com"],
    "hosts": ["www.example.com:93.184.216.34", "mail.example.com", "example.com"],
    "ips": ["93.184.216.34"],
    "interesting_urls": ["https://example.com/.git/config"],
    "linkedin_people": ["Octo Cat"],
    "asns": ["AS15133"],
    "shodan": {},
})

SUBFINDER_JSON = """{"host":"www.example.com","input":"example.com","source":"hackertarget"}
{"host":"www.example.com","input":"example.com","source":"crtsh"}
{"host":"example.com","input":"example.com","source":"alienvault"}
not json
"""

WHOIS_OUTPUT = """% IANA WHOIS server
   Domain Name: EXAMPLE.COM
   Registrar: RESERVED-Internet Assigned Numbers Authority
   Registrar URL: http://res-dom.iana.org
   Updated Date: 2026-01-16T18:26:50Z
   Creation Date: 1995-08-14T04:00:00Z
   Registry Expiry Date: 2026-08-13T04:00:00Z
   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
   Name Server: ELLIOTT.NS.CLOUDFLARE.COM
   Name Server: HERA.NS.CLOUDFLARE.COM
   Registrant Name: Octo Cat
   Registrant Email: registrant@example.com
   Registrar Abuse Contact Email: abuse@example.com
   DNSSEC: signedDelegation
"""

WHATWEB_JSON = json.dumps([{
    "target": "http://example.com",
    "http_status": 200,
    "plugins": {
        "Country": {"string": ["UNITED STATES"], "module": ["US"]},
        "HTML5": {},
        "HTTPServer": {"string": ["cloudflare"]},
        "IP": {"string": ["104.20.23.154"]},
        "Title": {"string": ["Example Domain"]},
        "Email": {"string": ["webmaster@example.com"]},
    },
}])

WHATWEB_SUMMARY = (
    "http://example.com [200 OK] Country[UNITED STATES][US], HTML5, "
    "HTTPServer[cloudflare], IP[104.20.23.154], Title[Example Domain]\n"
)

NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap">
<host><status state="up" reason="user-set"/>
<address addr="45.33.32.156" addrtype="ipv4"/>
<hostnames><hostname name="scanme.nmap.org" type="user"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>
<service name="ssh" method="table" conf="3"/></port>
<port protocol="tcp" portid="25"><state state="filtered" reason="no-response"/>
<service name="smtp" method="table" conf="3"/></port>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>
<service name="http" product="Apache httpd" version="2.4.7" extrainfo="Ubuntu"/></port>
</ports></host></nmaprun>
"""

NMAP_TEXT = """PORT   STATE    SERVICE VERSION
22/tcp open     ssh
25/tcp filtered smtp
80/tcp open     http    Apache httpd 2.4.7
"""

EXIFTOOL_JSON = json.dumps([{
    "SourceFile": "/tmp/photo.jpg",
    "FileType": "JPEG",
    "Make": "Canon",
    "Model": "EOS 80D",
    "LensModel": "EF-S18-135mm",
    "SerialNumber": "0123456789",
    "Software": "Adobe Photoshop 24.0",
    "Artist": "Octo Cat",
    "CreateDate": "2023:07:14 09:11:02",
    "GPSLatitude": "37 deg 46' 30.00\" N",
    "GPSLongitude": "122 deg 25' 9.00\" W",
    "GPSAltitude": "12 m",
}])

SHODAN_TEXT = """45.33.32.156
Hostnames: scanme.nmap.org
City:                    Fremont
Country:                 United States
Organization:            Linode
Operating System:        Linux

Ports:
     22/tcp
     80/tcp
"""


class TestMaigret:
    """maigret's report carries the account holder, not only the account."""

    def test_claimed_accounts_become_presences(self):
        artifacts = tool_parsers.parse_maigret_ndjson(MAIGRET_NDJSON, "octocat")
        presences = [a for a in artifacts if a["type"] == "username_presence"]

        assert [a["value"] for a in presences] == [
            "https://twitter.com/octocat",
            "https://www.pinterest.com/octocat/",
        ]
        assert presences[0]["platform"] == "Twitter"
        assert presences[0]["source"] == "maigret"
        assert presences[0]["tags"] == ["messaging", "social"]

    def test_extracted_detail_survives(self):
        artifacts = tool_parsers.parse_maigret_ndjson(MAIGRET_NDJSON, "octocat")
        twitter = next(a for a in artifacts if a["value"] == "https://twitter.com/octocat")

        assert twitter["metadata"]["fullname"] == "Octo Cat"
        assert twitter["metadata"]["follower_count"] == "241196304"
        assert twitter["metadata"]["bio"] == "engineer"
        assert "_extractor" not in twitter["metadata"]

    def test_identifying_fields_become_their_own_artifacts(self):
        artifacts = tool_parsers.parse_maigret_ndjson(MAIGRET_NDJSON, "octocat")
        by_type = {a["type"]: a for a in artifacts if a["type"] != "username_presence"}

        assert by_type["fullname"]["value"] == "Octo Cat"
        assert by_type["fullname"]["metadata"]["found_on"] == "https://twitter.com/octocat"
        assert by_type["location"]["value"] == "San Francisco"
        assert by_type["image_url"]["value"].endswith("octocat.jpg")

    def test_same_person_is_not_repeated_per_account(self):
        artifacts = tool_parsers.parse_maigret_ndjson(MAIGRET_NDJSON, "octocat")
        names = [a for a in artifacts if a["type"] == "fullname"]
        assert len(names) == 1

    def test_unclaimed_and_unparsable_rows_are_ignored(self):
        artifacts = tool_parsers.parse_maigret_ndjson(MAIGRET_NDJSON, "octocat")
        assert not any("facebook" in a["value"] for a in artifacts)
        assert tool_parsers.parse_maigret_ndjson("not json\n", "octocat") == []

    def test_printed_tree_still_names_the_accounts(self):
        artifacts = tool_parsers.parse_sherlock(MAIGRET_TREE, "octocat")
        assert [a["value"] for a in artifacts] == ["https://twitter.com/octocat"]


class TestSherlock:

    def test_summary_lines_are_not_accounts(self):
        output = ("[+] GitHub: https://github.com/octocat\n"
                  "[*] Search completed with 151 results\n")
        artifacts = tool_parsers.parse_sherlock(output, "octocat")
        assert [a["value"] for a in artifacts] == ["https://github.com/octocat"]


class TestHolehe:
    """The CSV report answers what the terminal output cannot."""

    def test_only_registered_accounts_are_kept(self):
        artifacts = tool_parsers.parse_holehe_csv(HOLEHE_CSV, "octo@example.com")
        assert [a["platform"] for a in artifacts] == ["twitter.com", "instagram.com"]
        assert artifacts[0]["value"] == "twitter.com:octo@example.com"

    def test_recovery_hints_are_kept(self):
        artifacts = tool_parsers.parse_holehe_csv(HOLEHE_CSV, "octo@example.com")
        instagram = next(a for a in artifacts if a["platform"] == "instagram.com")

        assert instagram["metadata"]["recovery_email"] == "o****t@gm***.com"
        assert instagram["metadata"]["recovery_phone"] == "+1******89"

    def test_text_legend_line_is_not_an_account(self):
        output = "[+] twitter.com\n[+] Email used, [-] Email not used\n"
        artifacts = tool_parsers.parse_holehe_text(output, "octo@example.com")
        assert [a["platform"] for a in artifacts] == ["twitter.com"]


class TestTheHarvester:

    def test_report_separates_what_the_summary_conflates(self):
        artifacts = tool_parsers.parse_theharvester_json(THEHARVESTER_JSON, "example.com")
        by_type: dict[str, list[str]] = {}
        for artifact in artifacts:
            by_type.setdefault(artifact["type"], []).append(artifact["value"])

        assert by_type["email"] == ["press@example.com", "abuse@example.com"]
        assert by_type["subdomain"] == ["www.example.com", "mail.example.com"]
        assert by_type["ip_address"] == ["93.184.216.34"]
        assert by_type["fullname"] == ["Octo Cat"]
        assert by_type["asn"] == ["AS15133"]
        assert by_type["url"] == ["https://example.com/.git/config"]

    def test_resolved_address_stays_attached_to_its_host(self):
        artifacts = tool_parsers.parse_theharvester_json(THEHARVESTER_JSON, "example.com")
        host = next(a for a in artifacts if a["value"] == "www.example.com")
        assert host["metadata"] == {"resolved_ip": "93.184.216.34"}

    def test_non_json_report_yields_nothing(self):
        assert tool_parsers.parse_theharvester_json("Emails found:\n", "example.com") == []

    def test_a_crowded_address_book_does_not_hide_the_hosts(self):
        """One run feeds two analyses, so the cap cannot be shared between them."""
        report = json.dumps({
            "emails": [f"user{n}@example.com" for n in range(40)],
            "hosts": ["www.example.com", "mail.example.com"],
        })
        artifacts = tool_parsers.parse_theharvester_json(report, "example.com")

        assert [a["value"] for a in artifacts if a["type"] == "subdomain"] == [
            "www.example.com", "mail.example.com",
        ]
        assert len([a for a in artifacts if a["type"] == "email"]) == \
            tool_parsers.MAX_ARTIFACTS_PER_TOOL


class TestSubfinder:

    def test_source_behind_each_name_is_kept(self):
        artifacts = tool_parsers.parse_subfinder_json(SUBFINDER_JSON, "example.com")
        assert [a["value"] for a in artifacts] == ["www.example.com"]
        assert artifacts[0]["metadata"] == {"discovered_by": "hackertarget"}

    def test_plain_output_still_parses(self):
        assert tool_parsers.parse_subfinder_json("www.example.com\n", "example.com") == []
        assert tool_parsers.parse_subdomains(
            "www.example.com\n", "example.com", "subfinder")[0]["value"] == "www.example.com"


class TestWhois:
    """A whois answer repeats its labels; taking the first loses the rest."""

    def test_every_nameserver_and_status_is_kept(self):
        record, artifacts = tool_parsers.parse_whois(WHOIS_OUTPUT, "example.com")

        assert record["name_servers"] == ["elliott.ns.cloudflare.com", "hera.ns.cloudflare.com"]
        assert record["status"] == ["clientDeleteProhibited", "clientTransferProhibited"]
        assert len([a for a in artifacts if a["type"] == "name_server"]) == 2

    def test_registration_dates_and_registrar_are_named(self):
        record, _ = tool_parsers.parse_whois(WHOIS_OUTPUT, "example.com")

        assert record["creation_date"] == "1995-08-14T04:00:00Z"
        assert record["expiration_date"] == "2026-08-13T04:00:00Z"
        assert record["updated_date"] == "2026-01-16T18:26:50Z"
        assert record["registrar_url"] == "http://res-dom.iana.org"
        assert record["dnssec"] == "signedDelegation"

    def test_contacts_become_artifacts(self):
        record, artifacts = tool_parsers.parse_whois(WHOIS_OUTPUT, "example.com")
        emails = [a["value"] for a in artifacts if a["type"] == "email"]

        # The registrant is the subject; the registrar's abuse mailbox belongs
        # to the registrar, so it stays a field of the record.
        assert emails == ["registrant@example.com"]
        assert record["abuse_email"] == "abuse@example.com"
        assert any(a["type"] == "fullname" and a["value"] == "Octo Cat" for a in artifacts)

    def test_comment_lines_are_not_fields(self):
        record, _ = tool_parsers.parse_whois(WHOIS_OUTPUT, "example.com")
        assert not any("iana whois server" in str(v).lower() for v in record.values())

    def test_the_registrant_s_address_becomes_a_location(self):
        output = WHOIS_OUTPUT + "   Registrant City: Los Angeles\n" \
                               "   Registrant Country: US\n"
        _, artifacts = tool_parsers.parse_whois(output, "example.com")
        places = [a for a in artifacts if a["type"] == "location"]

        assert [a["value"] for a in places] == ["Los Angeles, US"]
        # A privacy proxy's address is the proxy's, not the registrant's.
        assert places[0]["confidence"] < 0.5

    def test_a_domain_with_many_name_servers_keeps_its_place(self):
        output = (WHOIS_OUTPUT
                  + "   Registrant Country: US\n"
                  + "".join(f"   Name Server: NS{i}.EXAMPLE.COM\n" for i in range(30)))
        _, artifacts = tool_parsers.parse_whois(output, "example.com")

        assert len(artifacts) == tool_parsers.MAX_ARTIFACTS_PER_TOOL
        assert [a["value"] for a in artifacts if a["type"] == "location"] == ["US"]

    def test_a_redacted_registrant_claims_no_place(self):
        _, artifacts = tool_parsers.parse_whois(WHOIS_OUTPUT, "example.com")
        assert not [a for a in artifacts if a["type"] == "location"]


class TestWhatWeb:

    def test_plugins_are_read_as_fields_not_as_one_string(self):
        parsed, artifacts = tool_parsers.parse_whatweb_json(WHATWEB_JSON, "example.com")

        assert parsed["title"] == "Example Domain"
        assert parsed["country"] == "UNITED STATES, US"
        assert parsed["http_status"] == 200
        assert parsed["addresses"] == ["104.20.23.154"]
        assert "HTTPServer[cloudflare]" in parsed["technologies"]
        assert "Title[Example Domain]" not in parsed["technologies"]

    def test_addresses_and_addresses_found_in_pages_become_artifacts(self):
        _, artifacts = tool_parsers.parse_whatweb_json(WHATWEB_JSON, "example.com")
        by_type = {a["type"] for a in artifacts}

        assert by_type == {"ip_address", "web_technology", "email"}
        assert any(a["value"] == "webmaster@example.com" for a in artifacts)

    def test_summary_fallback_still_finds_the_address(self):
        parsed, artifacts = tool_parsers.parse_whatweb_summary(WHATWEB_SUMMARY, "example.com")
        assert parsed["addresses"] == ["104.20.23.154"]
        assert any(a["type"] == "ip_address" for a in artifacts)


class TestNmap:

    def test_ports_without_a_version_are_not_dropped(self):
        _, artifacts = tool_parsers.parse_nmap_xml(NMAP_XML, "scanme.nmap.org")
        ports = [a["value"] for a in artifacts if a["type"] == "open_port"]

        assert ports == ["scanme.nmap.org:22", "scanme.nmap.org:80"]

    def test_service_and_version_stay_separate(self):
        _, artifacts = tool_parsers.parse_nmap_xml(NMAP_XML, "scanme.nmap.org")
        http = next(a for a in artifacts if a["value"].endswith(":80"))

        assert http["service"] == "http"
        assert http["version"] == "Apache httpd 2.4.7"
        assert http["metadata"]["extra_info"] == "Ubuntu"

    def test_host_state_and_hostname_are_recorded(self):
        parsed, artifacts = tool_parsers.parse_nmap_xml(NMAP_XML, "45.33.32.156")

        assert parsed["hosts"][0]["state"] == "up"
        assert parsed["hosts"][0]["address"] == "45.33.32.156"
        assert any(a["type"] == "hostname" and a["value"] == "scanme.nmap.org"
                   for a in artifacts)

    def test_text_fallback_keeps_version_less_ports(self):
        artifacts = tool_parsers.parse_nmap_text(NMAP_TEXT, "scanme.nmap.org")

        assert [a["value"] for a in artifacts] == [
            "scanme.nmap.org:22", "scanme.nmap.org:80",
        ]
        assert artifacts[0]["version"] is None
        assert artifacts[1]["version"] == "Apache httpd 2.4.7"

    def test_non_xml_is_not_read_as_a_scan(self):
        assert tool_parsers.parse_nmap_xml("Starting Nmap 7.80", "host") == ({}, [])


class TestExifTool:

    def test_owner_serial_and_software_are_findings(self):
        _, artifacts = tool_parsers.parse_exiftool_json(EXIFTOOL_JSON, "/tmp/photo.jpg")
        by_type = {a["type"]: a["value"] for a in artifacts}

        assert by_type["fullname"] == "Octo Cat"
        assert by_type["device_serial"] == "0123456789"
        assert by_type["software"] == "Adobe Photoshop 24.0"
        assert by_type["camera_info"] == "Canon EOS 80D"
        assert by_type["creation_date"] == "2023:07:14 09:11:02"

    def test_coordinates_are_combined_once(self):
        _, artifacts = tool_parsers.parse_exiftool_json(EXIFTOOL_JSON, "/tmp/photo.jpg")
        gps = [a for a in artifacts if a["type"] == "gps_coordinates"]

        assert len(gps) == 1
        assert gps[0]["value"].startswith("37 deg 46'")
        assert gps[0]["metadata"]["altitude"] == "12 m"

    def test_full_metadata_is_returned_for_the_report(self):
        metadata, _ = tool_parsers.parse_exiftool_json(EXIFTOOL_JSON, "/tmp/photo.jpg")
        assert metadata["FileType"] == "JPEG"
        assert metadata["LensModel"] == "EF-S18-135mm"


class TestShodan:

    def test_human_readable_output_is_understood(self):
        parsed, artifacts = tool_parsers.parse_shodan_host(SHODAN_TEXT, "45.33.32.156")

        assert parsed["organization"] == "Linode"
        assert parsed["city"] == "Fremont"
        assert [a["value"] for a in artifacts if a["type"] == "open_port"] == [
            "45.33.32.156:22", "45.33.32.156:80",
        ]
        assert any(a["type"] == "hostname" and a["value"] == "scanme.nmap.org"
                   for a in artifacts)

    def test_json_output_is_understood(self):
        report = json.dumps({"org": "Linode", "ports": [22, 80], "os": "Linux"})
        parsed, artifacts = tool_parsers.parse_shodan_host(report, "45.33.32.156")

        assert parsed["org"] == "Linode"
        assert len([a for a in artifacts if a["type"] == "open_port"]) == 2

    def test_json_host_names_arrive_as_a_list(self):
        """The JSON answer lists them; the printed one runs them together."""
        report = json.dumps({"hostnames": ["scanme.nmap.org", "li982-156.example"]})
        _, artifacts = tool_parsers.parse_shodan_host(report, "45.33.32.156")

        assert [a["value"] for a in artifacts if a["type"] == "hostname"] == [
            "scanme.nmap.org", "li982-156.example",
        ]

    def test_empty_answer_yields_nothing(self):
        assert tool_parsers.parse_shodan_host("", "45.33.32.156") == ({}, [])

    def test_the_host_s_city_becomes_a_location(self):
        """Otherwise an address investigation never has anything to map."""
        _, artifacts = tool_parsers.parse_shodan_host(SHODAN_TEXT, "45.33.32.156")
        places = [a for a in artifacts if a["type"] == "location"]

        assert [a["value"] for a in places] == ["Fremont, United States"]
        # A host's city is not its owner's city.
        assert places[0]["confidence"] < 0.5

    def test_a_json_answer_nests_the_place(self):
        report = json.dumps({"location": {"city": "Fremont", "region_name": "California",
                                          "country_name": "United States"}})
        _, artifacts = tool_parsers.parse_shodan_host(report, "45.33.32.156")

        assert [a["value"] for a in artifacts if a["type"] == "location"] == [
            "Fremont, United States",
        ]

    def test_a_country_alone_is_still_a_place(self):
        report = json.dumps({"location": {"city": None, "country_name": "Germany"}})
        _, artifacts = tool_parsers.parse_shodan_host(report, "1.2.3.4")

        assert [a["value"] for a in artifacts if a["type"] == "location"] == ["Germany"]

    def test_a_busy_host_keeps_its_place(self):
        """The per-tool cap must not spend the one place on the many ports."""
        report = json.dumps({
            "ports": list(range(1, 100)),
            "location": {"city": "Fremont", "country_name": "United States"},
        })
        _, artifacts = tool_parsers.parse_shodan_host(report, "45.33.32.156")

        assert len(artifacts) == tool_parsers.MAX_ARTIFACTS_PER_TOOL
        assert [a["value"] for a in artifacts if a["type"] == "location"] == [
            "Fremont, United States",
        ]

    def test_a_host_with_no_place_claims_none(self):
        report = json.dumps({"org": "Linode", "ports": [22]})
        _, artifacts = tool_parsers.parse_shodan_host(report, "45.33.32.156")

        assert not [a for a in artifacts if a["type"] == "location"]


class TestMaigretPlaces:
    """A profile names where somebody is under whichever key its site uses."""

    def test_a_city_key_is_a_location(self):
        report = json.dumps({
            "username": "octocat", "sitename": "Site",
            "status": {"site_name": "Site", "url": "https://site/octocat",
                       "status": "Claimed",
                       "ids": {"city": "Bengaluru", "region": "Karnataka"}},
        })
        artifacts = tool_parsers.parse_maigret_ndjson(report, "octocat")

        assert sorted(a["value"] for a in artifacts if a["type"] == "location") == [
            "Bengaluru", "Karnataka",
        ]


class TestWayback:

    def test_header_row_is_not_a_finding(self):
        rows = [
            ["timestamp", "original", "statuscode", "mimetype"],
            ["20200101000000", "http://example.com/", "200", "text/html"],
            ["short"],
        ]
        artifacts = tool_parsers.parse_wayback_cdx(rows, "example.com")

        assert len(artifacts) == 1
        assert artifacts[0]["timestamp"] == "20200101000000"
        assert artifacts[0]["mime_type"] == "text/html"
