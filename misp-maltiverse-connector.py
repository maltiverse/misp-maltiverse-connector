#!/usr/bin/python3

# -----------------------------------------------------------
# Python client that retrieves events from MISP
# Stores results into Maltiverse Intelligence Platform
#
# (C) 2024 Maltiverse
# Released under GNU Public License (GPL)
# -----------------------------------------------------------

import argparse
import requests
import json
import hashlib
import datetime
from pymisp import PyMISP
from validators import ip_address
from urlextract import URLExtract


class MispMaltiverseHandler:
    def __init__(self, maltiverse_api_key, misp_api_key, misp_url):
        self.maltiverse_api_key = maltiverse_api_key
        self.maltiverse_base_url = "https://api.maltiverse.com"
        self.maltiverse_headers = {"Authorization": f"Bearer {self.maltiverse_api_key}"}

        self.misp_api_key = misp_api_key
        self.misp_base_url = misp_url

        self.misp = PyMISP(self.misp_base_url, self.misp_api_key, False, debug=True)
        self.organizations = self.get_misp_organizations()

    def get_misp_organizations(self):
        result = {}
        for org in self.misp.organisations():
            result[org["Organisation"]["id"]] = org["Organisation"]["name"]
        return result

    def get_organization_name_from_org_id(self, org_id):
        return self.organizations[str(org_id)]

    def get_misp_attributes(
        self, publish_timestamp="1h", to_ids=None, org=None, event_id=None, tags=None
    ):
        t = None
        if tags:
            t = tags.split(",")
        attributes = self.misp.search(
            controller="attributes",
            pythonify=True,
            include_context=True,
            enforce_warninglist=True,
            to_ids=to_ids,
            org=org,
            eventid=event_id,
            tags=t,
            publish_timestamp=publish_timestamp,
        )
        return attributes

    def convert_misp_attribute_to_maltiverse_ioc(self, attribute, tag_maltiverse=None):
        ret = None
        tag = []
        description = attribute.comment

        if tag_maltiverse:
            for t in tag_maltiverse.split(","):
                tag.append(t)

        misp_event = attribute.Event
        tag.append(misp_event.info)
        if "to_ids" in attribute and attribute["to_ids"]:
            tag.append("to_ids")

        if not description:
            description = misp_event.info

        # building blacklist
        blacklist = {
            "description": description,
            "source": self.get_organization_name_from_org_id(misp_event.org_id),
        }

        if "publish_timestamp" in misp_event:
            if int(misp_event["publish_timestamp"]) > 0:
                blacklist["first_seen"] = misp_event["publish_timestamp"].strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            else:
                blacklist["first_seen"] = datetime.datetime.now(datetime.timezone.utc)
            blacklist["last_seen"] = blacklist["first_seen"]

        print("################# attribute #################")
        print(attribute.to_dict())
        print("################# event #################")
        print(misp_event.to_dict())

        # processing tag
        if "Tag" in misp_event:
            print(misp_event["Tag"])
            for t in misp_event["Tag"]:
                tag.append(t.name)

        extractor = URLExtract()
        for url in extractor.gen_urls(description):
            if not "external_references" in blacklist:
                blacklist["external_references"] = []
            external_reference = {
                "url": url,
                "source_name": "MISP",
            }
            blacklist["external_references"].append(external_reference)
            # remove urls from description
            blacklist["description"] = blacklist["description"].replace(url, "").strip()

        if attribute.type == "ip-dst":
            # check if IPv4 or IPv6
            if ip_address.ipv4(attribute.value):
                ret = {
                    "type": "ip",
                    "classification": "malicious",
                    "ip_addr": attribute.value,
                    "blacklist": [blacklist],
                    "tag": tag,
                }
        elif attribute.type == "ip-dst|port":
            ip_addr = attribute.value.split("|")[0]
            port = attribute.value.split("|")[1]
            tag.append("port:" + port)
            # check if IPv4 or IPv6
            if ip_address.ipv4(ip_addr):
                ret = {
                    "type": "ip",
                    "classification": "malicious",
                    "ip_addr": ip_addr,
                    "blacklist": [blacklist],
                    "tag": tag,
                }
        elif attribute.type == "domain" or attribute.type == "hostname":
            ret = {
                "type": "hostname",
                "classification": "malicious",
                "hostname": attribute.value,
                "blacklist": [blacklist],
                "tag": tag,
            }
        elif attribute.type == "url":
            ret = {
                "type": "url",
                "classification": "malicious",
                "url": attribute.value,
                "urlchecksum": hashlib.sha256(
                    attribute.value.encode("utf-8")
                ).hexdigest(),
                "blacklist": [blacklist],
                "tag": tag,
            }

        elif attribute.type == "sha256":
            ret = {
                "type": "sample",
                "classification": "malicious",
                "sha256": attribute.value,
                "blacklist": [blacklist],
                "tag": tag,
            }
        elif attribute.type == "filename|sha256":
            filename = attribute.value.split("|")[0]
            sha256 = attribute.value.split("|")[1]
            ret = {
                "type": "sample",
                "classification": "malicious",
                "sha256": sha256,
                "filename": filename,
                "blacklist": [blacklist],
                "tag": tag,
            }

        if ret and "publish_timestamp" in misp_event:
            if int(misp_event["publish_timestamp"]) > 0:
                ret["creation_time"] = str(
                    misp_event["publish_timestamp"].strftime("%Y-%m-%d %H:%M:%S")
                )
            else:
                ret["creation_time"] = datetime.datetime.now(datetime.timezone.utc)
            ret["modification_time"] = ret["creation_time"]

        return ret

    def upload_last_attributes_to_maltiverse(
        self,
        publish_timestamp="1h",
        upload=False,
        tag_maltiverse=None,
        to_ids=None,
        org=None,
        event_id=None,
        tags=None,
    ):
        result = []
        attributes = self.get_misp_attributes(
            publish_timestamp=publish_timestamp,
            to_ids=to_ids,
            org=org,
            event_id=event_id,
            tags=tags,
        )
        for attribute in attributes:
            maltiverse_obj = self.convert_misp_attribute_to_maltiverse_ioc(
                attribute, tag_maltiverse=tag_maltiverse
            )
            if maltiverse_obj and upload:
                res = self.upload_object_to_maltiverse(maltiverse_obj)
        return result

    def upload_object_to_maltiverse(self, object):
        url = None
        if object["type"] == "ip":
            url = self.maltiverse_base_url + "/ip/" + object["ip_addr"]
        if object["type"] == "hostname":
            url = self.maltiverse_base_url + "/hostname/" + object["hostname"]
        if object["type"] == "url":
            url = self.maltiverse_base_url + "/url/" + object["urlchecksum"]
        if object["type"] == "sample":
            url = self.maltiverse_base_url + "/sample/" + object["sha256"]
        if url:

            # Upload
            try:
                response = requests.put(
                    url, headers=self.maltiverse_headers, json=object
                )
                response.raise_for_status()  # Raise an error for bad responses
                result = response.json()
                print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
                print(json.dumps(object, indent=4))
                print("Upload successful. Result:", result)
            except requests.exceptions.HTTPError as errh:
                print(f"HTTP Error: {errh}")
            except requests.exceptions.ConnectionError as errc:
                print(f"Error Connecting: {errc}")
            except requests.exceptions.Timeout as errt:
                print(f"Timeout Error: {errt}")
            except requests.exceptions.RequestException as err:
                print(f"Something went wrong: {err}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--maltiverse-api-key",
        dest="maltiverse_api_key",
        required=True,
        help="Specifies Maltiverse APIKEY. Required",
    )
    parser.add_argument(
        "--misp-api-key",
        dest="misp_api_key",
        required=True,
        help="Specifies the MISP APIKEY to retrieve events from.",
    )
    parser.add_argument(
        "--misp-url",
        dest="misp_url",
        required=True,
        help="Specifies the MISP URL to retrieve events from.",
    )
    parser.add_argument(
        "--publish-timestamp",
        dest="publish_timestamp",
        default="1h",
        help="Specifies the time window of events retrieved from MISP. Default 1h",
    )
    parser.add_argument(
        "--add-tag-maltiverse",
        dest="add_tag_maltiverse",
        default=None,
        help="Specifies a list of comma separated tags to add to Maltiverse IoCs",
    )
    parser.add_argument(
        "--filter-to-ids",
        dest="to_ids",
        default=None,
        help="Select if you want to filter only to_ids attributes. (0 | 1 | None)",
    )
    parser.add_argument(
        "--filter-org",
        dest="org",
        default=None,
        help="Filter events by Organization ID",
    )
    parser.add_argument(
        "--filter-eventid",
        dest="eventid",
        default=None,
        help="Filter events by Event ID",
    )
    parser.add_argument(
        "--filter-tags",
        dest="filter_tags",
        default=None,
        help="Filter events by MISP Tags. You can specify a list of comma separated tags to filter by",
    )

    arguments = parser.parse_args()

    handler = MispMaltiverseHandler(
        arguments.maltiverse_api_key,
        arguments.misp_api_key,
        arguments.misp_url,
    )

    handler.upload_last_attributes_to_maltiverse(
        publish_timestamp=arguments.publish_timestamp,
        upload=True,
        tag_maltiverse=arguments.add_tag_maltiverse,
        to_ids=arguments.to_ids,
        org=arguments.eventid,
        event_id=arguments.eventid,
        tags=arguments.filter_tags,
    )
