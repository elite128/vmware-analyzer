from pathlib import Path
from typing import Any
from html import escape

import re
import yaml
import pprint
import textwrap
import argparse
import textwrap



def load_help(
    filename: str | Path
) -> dict[str, Any]:

    with open(
        filename,
        mode="r",
        encoding="utf-8"
    ) as file:

        help_data = yaml.safe_load(file)

    if not isinstance(help_data, dict):
        raise ValueError(
            "Help file must contain a YAML dictionary."
        )

    help_topics = help_data.get("help")

    if not isinstance(help_topics, dict):
        raise ValueError(
            "Help file must contain a 'help' section."
        )

    return help_topics


def validate_recommendation_help_topics(
    recommendations: list[dict[str, Any]],
    help_topics: dict[str, Any]
) -> None:

    missing_topics = sorted({
        recommendation["help_topic"]
        for recommendation in recommendations
        if recommendation.get("help_topic")
        and recommendation["help_topic"] not in help_topics
    })

    if missing_topics:
        raise ValueError(
            "Unknown help topic(s) referenced by recommendations: "
            + ", ".join(missing_topics)
        )




def load_config(filename: str | Path) -> dict[str, Any]:
    path = Path(filename)

    if not path.is_file():
        raise FileNotFoundError(
            f"Konfigurationsdatei wurde nicht gefunden: {path.resolve()}"
        )

    try:
        with open(path, mode="r", encoding="utf-8") as file:
            config = yaml.safe_load(file)

        if config is None:
            return {}

        if not isinstance(config, dict):
            raise ValueError(
                "YAML-Wurzel muss ein Mapping/Dictionary sein, "
                f"erhalten: {type(config).__name__}"
            )

        return config

    except yaml.YAMLError as exc:
        raise ValueError(
            f"Fehler beim Parsen der YAML-Datei '{path.name}': {exc}"
        ) from exc


def load_rules(filename: str | Path) -> dict[str, Any]:

    path = Path(filename)

    if not path.is_file():
        raise FileNotFoundError(
            f"Rules-Datei wurde nicht gefunden: {path.resolve()}"
        )

    try:
        with open(path, mode="r", encoding="utf-8") as file:
            rules = yaml.safe_load(file)

        if rules is None:
            return {}

        if not isinstance(rules, dict):
            raise ValueError(
                "YAML-Wurzel der Rules-Datei muss ein Mapping/Dictionary sein, "
                f"erhalten: {type(rules).__name__}"
            )

        return rules

    except yaml.YAMLError as exc:
        raise ValueError(
            f"Fehler beim Parsen der Rules-Datei '{path.name}': {exc}"
        ) from exc



def validate_config(config: dict[str, Any]) -> None:

    allowed_formats = ["text", "json", "yaml", "html"]

    if "analysis" not in config:
        raise ValueError("Sektion 'analysis' fehlt in der Konfiguration")

    if "migration" not in config:
        raise ValueError("Sektion 'migration' fehlt in der Konfiguration")

    if "output" not in config:
        raise ValueError("Sektion 'output' fehlt in der Konfiguration")

    analyze_all = config["analysis"].get("analyze_all")

    if not isinstance(analyze_all, bool):
        raise ValueError("'analysis.analyze_all' muss true oder false sein")

    migration = config["migration"]

    required_migration_values = [
        "target",
        "preferred_storage",
        "preferred_disk_bus",
        "preferred_controller",
        "preferred_nic"
    ]

    for key in required_migration_values:
        if key not in migration:
            raise ValueError(
                f"'migration.{key}' fehlt in der Konfiguration"
            )

        if not isinstance(migration[key], str) or not migration[key].strip():
            raise ValueError(
                f"'migration.{key}' muss ein nicht-leerer String sein"
            )

    output_format = config["output"].get("format")

    if output_format not in allowed_formats:
        raise ValueError(
            f"Ungültiges output.format: {output_format}. "
            f"Erlaubt sind: {', '.join(allowed_formats)}"
        )



def parse_vmx(
    filename: str | Path
) -> tuple[dict[str, str], list[dict[str, str]]]:
    # liefert einmal ein dict mit daten sowie eine list mit findings (doppelte eintraege usw)
    mydict = {}
    findings = []

    with open(filename, mode="r", encoding="utf-8") as file:
        
        for line_number, line in enumerate(file, start=1):

            try:
                key, value = line.split("=", 1)

                key = key.strip()
                value = value.strip().strip('"\'')

                if key in mydict:
                    findings.append({
                        "type": "duplicate_key",
                        "key": key,
                        "message": f"Doppelter VMX-Key gefunden: {key}",
                        "line": str(line_number),
                        "original_value": mydict[key],
                        "duplicate_value": value
                    })
                    continue

                mydict[key] = value

            except ValueError:
                continue

    return mydict, findings


def is_duplicate_key(key: str, data: dict[str, str]) -> bool:
    return key in data



def analyze_hardware(vmx_data: dict[str, str]) -> dict[str, Any]:
    hard_dict={}
    if 'displayName' not in vmx_data:
        raise ValueError("Entrag 'displayName' fehlt in der Konfiguration")

    if "guestOS" not in vmx_data:
        raise ValueError("Eintrag 'guestOS' fehlt in der Konfiguration")
    
    if "firmware" not in vmx_data:
        raise ValueError("Eintrag 'firmware' fehlt in der Konfiguration")

    if "numvcpus" not in vmx_data:
        raise ValueError("Eintrag 'numvcpus' fehlt in der Konfiguration")
    
    if "memSize" not in vmx_data:
        raise ValueError("memory_mb '' fehlt in der Konfiguration")

    hard_dict.update({"name" : {"value":vmx_data["displayName"], "source": "displayName"}})
    hard_dict.update({"guest_os" : {"value":vmx_data["guestOS"], "source": "guestOS"}})
    hard_dict.update({"firmware" : {"value":vmx_data["firmware"], "source": "firmware"}})
    hard_dict.update({"cpu_count" : {"value":int(vmx_data["numvcpus"]), "source": "numvcpus"}})
    hard_dict.update({"memory_mb" : {"value":int(vmx_data["memSize"]), "source": "memSize"}})
    
    return hard_dict


def analyze_storage(vmx_data: dict[str, str]) -> dict[str, Any]:

    stor_dict = {"controllers": [], "devices": []}

    for k in vmx_data:

        if not k.startswith(("scsi", "sata", "ide", "nvme")):
            continue

        object_id = k.split(".", 1)[0]

        # -----------------------------------
        # Device?
        # Example:
        # scsi0:0.present
        # sata0:1.fileName
        # -----------------------------------
        if ":" in object_id:

            device_id = object_id
            controller_id, device_number = device_id.split(":", 1)

            # Device only once
            if not id_exists(device_id, stor_dict["devices"]):

                present_key = device_id + ".present"
                file_key = device_id + ".fileName"
                device_type_key = device_id + ".deviceType"

                device = {"id": device_id}

                if present_key in vmx_data:
                    device["present"] = {"value": vmx_data[present_key].upper() == "TRUE", "source": present_key}

                if file_key in vmx_data:
                    device["file"] = {"value": vmx_data[file_key], "source": file_key}

                if device_type_key in vmx_data:
                    device["device_type"] = {"value": vmx_data[device_type_key], "source": device_type_key}

                stor_dict["devices"].append(device)

            # Controller derived from device
            if not id_exists(controller_id, stor_dict["controllers"]):

                controller_present_key = controller_id + ".present"
                controller_type_key = controller_id + ".virtualDev"

                controller = {"id": controller_id}

                if controller_present_key in vmx_data:
                    controller["present"] = {"value": vmx_data[controller_present_key].upper() == "TRUE", "source": controller_present_key}

                if controller_type_key in vmx_data:
                    controller["type"] = {"value": vmx_data[controller_type_key], "source": controller_type_key}

                stor_dict["controllers"].append(controller)

        # -----------------------------------
        # Controller?
        # Example:
        # scsi0.present
        # scsi0.virtualDev
        # -----------------------------------
        else:

            controller_id = object_id

            if not id_exists(controller_id, stor_dict["controllers"]):

                controller_present_key = controller_id + ".present"
                controller_type_key = controller_id + ".virtualDev"

                controller = {"id": controller_id}

                if controller_present_key in vmx_data:
                    controller["present"] = {"value": vmx_data[controller_present_key].upper() == "TRUE", "source": controller_present_key}

                if controller_type_key in vmx_data:
                    controller["type"] = {"value": vmx_data[controller_type_key], "source": controller_type_key}

                stor_dict["controllers"].append(controller)

    return stor_dict



def analyze_network(vmx_data: dict[str, str]) -> dict[str, Any]:

    net_dict = {"interfaces": []}

    for k in vmx_data:

        # only interested in VMware ethernet devices
        if not k.startswith("ethernet"):
            continue

        # example: ethernet0.virtualDev -> ethernet0
        interface_id = k.split(".", 1)[0]

        # interface already analyzed?
        if id_exists(interface_id, net_dict["interfaces"]):
            continue

        present_key = interface_id + ".present"
        virtual_dev_key = interface_id + ".virtualDev"
        address_type_key = interface_id + ".addressType"
        address_key = interface_id + ".address"
        network_name_key = interface_id + ".networkName"
        start_connected_key = interface_id + ".startConnected"

        interface = {"id": interface_id}

        if present_key in vmx_data:
            interface["present"] = {"value": vmx_data[present_key].upper() == "TRUE", "source": present_key}

        if virtual_dev_key in vmx_data:
            interface["type"] = {"value": vmx_data[virtual_dev_key], "source": virtual_dev_key}

        if address_type_key in vmx_data:
            interface["address_type"] = {"value": vmx_data[address_type_key], "source": address_type_key}

        if address_key in vmx_data:
            interface["mac"] = {"value": vmx_data[address_key], "source": address_key}

        if network_name_key in vmx_data:
            interface["network"] = {"value": vmx_data[network_name_key], "source": network_name_key}

        if start_connected_key in vmx_data:
            interface["start_connected"] = {"value": vmx_data[start_connected_key].upper() == "TRUE", "source": start_connected_key}

        net_dict["interfaces"].append(interface)

    return net_dict


def analyze_misc(vmx_data: dict[str, str]) -> dict[str, Any]:

    misc_dict = {"miscellaneous": []}

    for k in vmx_data:

        # Only interested in selected miscellaneous VMware settings
        if not k.startswith(("tools", "efi", "usb", "sound")):
            continue

        # Example: tools.syncTime -> tools
        misc_id = k.split(".", 1)[0]

        # Misc object already analyzed?
        if id_exists(misc_id, misc_dict["miscellaneous"]):
            continue

        present_key = misc_id + ".present"
        toolssyncTime_key = misc_id + ".syncTime"
        toolsupgradePolicy_key = misc_id + ".upgrade.policy"
        efi_secureBoot_key = misc_id + ".secureBoot.enabled"

        misc = {"id": misc_id}

        if present_key in vmx_data:
            misc["present"] = {"value": vmx_data[present_key].upper() == "TRUE", "source": present_key}

        if toolssyncTime_key in vmx_data:
            misc["tools_sync_time"] = {"value": vmx_data[toolssyncTime_key].upper() == "TRUE", "source": toolssyncTime_key}

        if toolsupgradePolicy_key in vmx_data:
            misc["tools_upgrade_policy"] = {"value": vmx_data[toolsupgradePolicy_key], "source": toolsupgradePolicy_key}

        if efi_secureBoot_key in vmx_data:
            misc["efi_secure_boot"] = {"value": vmx_data[efi_secureBoot_key].upper() == "TRUE", "source": efi_secureBoot_key}

        # Normalize VMware Tools-specific VMX settings into one fact.
        vmware_tools_sources = []

        if toolssyncTime_key in vmx_data:
            vmware_tools_sources.append(toolssyncTime_key)

        if toolsupgradePolicy_key in vmx_data:
            vmware_tools_sources.append(toolsupgradePolicy_key)

        if vmware_tools_sources:
            misc["vmware_tools"] = {"value": True, "source": vmware_tools_sources}

        # Normalize USB presence into an explicit fact.
        if misc_id == "usb" and present_key in vmx_data:
            misc["usb_present"] = {"value": vmx_data[present_key].upper() == "TRUE", "source": present_key}

        misc_dict["miscellaneous"].append(misc)

    return misc_dict





def id_exists(search_id: str, entries: list[dict[str, Any]]) -> bool:

    for entry in entries:

        if entry["id"] == search_id:
            return True

    return False

def analyze_vm(vmx_data: dict[str, str]) -> dict[str, Any]:

    return {
        "hardware": analyze_hardware(vmx_data),
        "storage": analyze_storage(vmx_data),
        "network": analyze_network(vmx_data),
        "misc": analyze_misc(vmx_data)
    }


def generate_recommendations(
    analysis: dict[str, Any],
    rules: dict[str, Any],
    config: dict[str, Any]
) -> list[dict[str, Any]]:

    recommendations = []

    rule_groups = rules.get("rules", {})

    # -------------------------------------------------
    # Pass 1: Simple fact rules
    # -------------------------------------------------

    for category, category_rules in rule_groups.items():

        if category not in analysis:
            continue

        category_analysis = analysis[category]

        for fact_name, fact_rules in category_rules.items():

            if fact_name not in category_analysis:
                continue

            fact = category_analysis[fact_name]

            if not isinstance(fact, dict) or "value" not in fact:
                continue

            value = fact["value"]

            rule_selector = str(value).lower()
            selected_rule = fact_rules.get(rule_selector)

            if selected_rule is None:
                rule_selector = "default"
                selected_rule = fact_rules.get("default")

            if selected_rule is None:
                continue

            for index, recommendation_rule in enumerate(
                selected_rule.get("recommendations", []),
                start=1
            ):

                rule_id = recommendation_rule.get(
                    "id",
                    f"{category}.{fact_name}.{rule_selector}.{index}"
                )

                recommendation = {
                    "id": rule_id,
                    "category": category,
                    "type": recommendation_rule.get("type", "migration"),
                    "severity": recommendation_rule.get("severity", "info"),
                    "message": recommendation_rule.get("message", "").format(value=value),
                    "reason": recommendation_rule.get("reason", "").format(value=value),
                    "source": fact.get("source"),
                    "source_value": value,
                    "help_topic": recommendation_rule.get("help_topic")
                }

                recommendations.append(recommendation)

    # -------------------------------------------------
    # Pass 2: Cross-fact dependency rules
    # -------------------------------------------------

    dependency_rules = rules.get("dependencies", [])

    for dependency in dependency_rules:

        when = dependency.get("when", {})
        requires = dependency.get("requires", {})

        when_fact = get_fact(analysis, when.get("fact"))

        required_fact = get_fact(analysis, requires.get("fact"))

        if when_fact is None or required_fact is None:
            continue

        if when_fact["value"] != when.get("equals"):
            continue

        if required_fact["value"] == requires.get("equals"):
            continue

        recommendation_rule = dependency.get("recommendation", {})

        recommendation = {
            "id": recommendation_rule.get(
                "id",
                f"dependency.{when.get('fact')}.{requires.get('fact')}"
            ),
            "category": "dependency",
            "type": recommendation_rule.get("type", "migration"),
            "severity": recommendation_rule.get("severity", "warning"),
            "message": recommendation_rule.get("message", ""),
            "reason": recommendation_rule.get("reason", ""),
            "source": {
                "when": when_fact.get("source"),
                "requires": required_fact.get("source")
            },
            "source_value": {
                "when": when_fact.get("value"),
                "requires": required_fact.get("value")
            },
            "help_topic": recommendation_rule.get("help_topic")
        }

        recommendations.append(recommendation)

    # -------------------------------------------------
    # Pass 3: Storage controller recommendations
    # -------------------------------------------------

    storage = analysis.get("storage", {})
    controllers = storage.get("controllers", [])

    migration_config = config.get("migration", {})
    preferred_controller = migration_config.get("preferred_controller")

    storage_rules = rule_groups.get("storage", {})
    controller_rules = storage_rules.get("controller_type", {})

    for controller in controllers:

        controller_type = controller.get("type")

        if controller_type is None:
            continue

        controller_value = controller_type["value"]
        selected_rule = controller_rules.get(controller_value)

        if selected_rule is None:
            continue

        for index, recommendation_rule in enumerate(
            selected_rule.get("recommendations", []),
            start=1
        ):

            recommendation = {
                "id": f"storage.controller.{controller['id']}.{controller_value}.{index}",
                "category": "storage",
                "type": recommendation_rule.get("type", "migration"),
                "severity": recommendation_rule.get("severity", "info"),
                "message": recommendation_rule.get("message", "").format(
                    preferred_controller=preferred_controller
                ),
                "reason": recommendation_rule.get("reason", "").format(
                    preferred_controller=preferred_controller
                ),
                "source": controller_type.get("source"),
                "source_value": controller_value,
                "help_topic": recommendation_rule.get("help_topic")
            }

            recommendations.append(recommendation)

    # -------------------------------------------------
    # Pass 4: Storage device / VMDK recommendations
    # -------------------------------------------------

    devices = storage.get("devices", [])
    preferred_storage = migration_config.get("preferred_storage")

    disk_format_rules = storage_rules.get("disk_format", {})
    device_validation_rules = storage_rules.get("device_validation", {})

    for device in devices:

        present = device.get("present")

        if present is not None and present["value"] is False:
            continue

        file_fact = device.get("file")

        # Present device without backing file
        if file_fact is None:

            if present is not None and present["value"] is True:

                missing_file_rule = device_validation_rules.get("missing_file")

                if missing_file_rule is not None:

                    for index, recommendation_rule in enumerate(
                        missing_file_rule.get("recommendations", []),
                        start=1
                    ):

                        recommendation = {
                            "id": f"storage.disk.{device['id']}.missing_file.{index}",
                            "category": "storage",
                            "type": recommendation_rule.get("type", "validation"),
                            "severity": recommendation_rule.get("severity", "warning"),
                            "message": recommendation_rule.get("message", "").format(
                                device_id=device["id"]
                            ),
                            "reason": recommendation_rule.get("reason", "").format(
                                device_id=device["id"]
                            ),
                            "source": present.get("source"),
                            "source_value": present.get("value"),
                            "help_topic": recommendation_rule.get("help_topic")
                        }

                        recommendations.append(recommendation)

            continue

        source_file = file_fact["value"]

        if not source_file.lower().endswith(".vmdk"):
            continue

        source_format = "vmdk"
        format_rules = disk_format_rules.get(source_format, {})

        # General VMDK inspection
        general_rule = format_rules.get("general")

        if general_rule is not None:

            for index, recommendation_rule in enumerate(
                general_rule.get("recommendations", []),
                start=1
            ):

                recommendation = {
                    "id": f"storage.disk.{device['id']}.vmdk.general.{index}",
                    "category": "storage",
                    "type": recommendation_rule.get("type", "validation"),
                    "severity": recommendation_rule.get("severity", "info"),
                    "message": recommendation_rule.get("message", "").format(
                        source_file=source_file
                    ),
                    "reason": recommendation_rule.get("reason", "").format(
                        source_file=source_file
                    ),
                    "source": file_fact.get("source"),
                    "source_value": source_file,
                    "help_topic": recommendation_rule.get("help_topic")
                }

                recommendations.append(recommendation)

        # Snapshot filename candidate
        snapshot_pattern = r"-\d{6}\.vmdk$"

        if re.search(snapshot_pattern, source_file, re.IGNORECASE):

            snapshot_rule = format_rules.get("snapshot_candidate")

            if snapshot_rule is not None:

                for index, recommendation_rule in enumerate(
                    snapshot_rule.get("recommendations", []),
                    start=1
                ):

                    recommendation = {
                        "id": f"storage.disk.{device['id']}.vmdk.snapshot_candidate.{index}",
                        "category": "storage",
                        "type": recommendation_rule.get("type", "validation"),
                        "severity": recommendation_rule.get("severity", "warning"),
                        "message": recommendation_rule.get("message", "").format(
                            source_file=source_file
                        ),
                        "reason": recommendation_rule.get("reason", "").format(
                            source_file=source_file
                        ),
                        "source": file_fact.get("source"),
                        "source_value": source_file,
                        "help_topic": recommendation_rule.get("help_topic")
                    }

                    recommendations.append(recommendation)

        # Target storage recommendation
        selected_rule = format_rules.get(preferred_storage)

        if selected_rule is None:
            continue

        for index, recommendation_rule in enumerate(
            selected_rule.get("recommendations", []),
            start=1
        ):

            recommendation = {
                "id": f"storage.disk.{device['id']}.{source_format}.{preferred_storage}.{index}",
                "category": "storage",
                "type": recommendation_rule.get("type", "migration"),
                "severity": recommendation_rule.get("severity", "info"),
                "message": recommendation_rule.get("message", "").format(
                    source_file=source_file,
                    preferred_storage=preferred_storage
                ),
                "reason": recommendation_rule.get("reason", "").format(
                    source_file=source_file,
                    preferred_storage=preferred_storage
                ),
                "source": file_fact.get("source"),
                "source_value": source_file,
                "help_topic": recommendation_rule.get("help_topic")
            }

            recommendations.append(recommendation)

    # -------------------------------------------------
    # Pass 5: Network recommendations
    # -------------------------------------------------

    network = analysis.get("network", {})
    interfaces = network.get("interfaces", [])

    network_rules = rule_groups.get("network", {})
    nic_type_rules = network_rules.get("nic_type", {})
    static_mac_rule = network_rules.get("static_mac")
    network_mapping_rule = network_rules.get("network_mapping")

    preferred_nic = migration_config.get("preferred_nic")

    for interface in interfaces:

        present = interface.get("present")

        if present is not None and present["value"] is False:
            continue

        # NIC type
        nic_type = interface.get("type")

        if nic_type is not None:

            nic_value = nic_type["value"]
            selected_rule = nic_type_rules.get(nic_value)

            if selected_rule is not None:

                for index, recommendation_rule in enumerate(
                    selected_rule.get("recommendations", []),
                    start=1
                ):

                    recommendation = {
                        "id": f"network.interface.{interface['id']}.type.{nic_value}.{index}",
                        "category": "network",
                        "type": recommendation_rule.get("type", "migration"),
                        "severity": recommendation_rule.get("severity", "info"),
                        "message": recommendation_rule.get("message", "").format(
                            preferred_nic=preferred_nic
                        ),
                        "reason": recommendation_rule.get("reason", "").format(
                            preferred_nic=preferred_nic
                        ),
                        "source": nic_type.get("source"),
                        "source_value": nic_value,
                        "help_topic": recommendation_rule.get("help_topic")
                    }

                    recommendations.append(recommendation)

        # Static MAC
        address_type = interface.get("address_type")
        mac = interface.get("mac")

        if (
            address_type is not None
            and address_type["value"].lower() == "static"
            and mac is not None
            and static_mac_rule is not None
        ):

            for index, recommendation_rule in enumerate(
                static_mac_rule.get("recommendations", []),
                start=1
            ):

                recommendation = {
                    "id": f"network.interface.{interface['id']}.static_mac.{index}",
                    "category": "network",
                    "type": recommendation_rule.get("type", "migration"),
                    "severity": recommendation_rule.get("severity", "info"),
                    "message": recommendation_rule.get("message", "").format(
                        mac=mac["value"]
                    ),
                    "reason": recommendation_rule.get("reason", "").format(
                        mac=mac["value"]
                    ),
                    "source": {
                        "address_type": address_type.get("source"),
                        "mac": mac.get("source")
                    },
                    "source_value": {
                        "address_type": address_type.get("value"),
                        "mac": mac.get("value")
                    },
                    "help_topic": recommendation_rule.get("help_topic")
                }

                recommendations.append(recommendation)

        # VMware network mapping
        network_name = interface.get("network")

        if network_name is not None and network_mapping_rule is not None:

            for index, recommendation_rule in enumerate(
                network_mapping_rule.get("recommendations", []),
                start=1
            ):

                recommendation = {
                    "id": f"network.interface.{interface['id']}.mapping.{index}",
                    "category": "network",
                    "type": recommendation_rule.get("type", "validation"),
                    "severity": recommendation_rule.get("severity", "warning"),
                    "message": recommendation_rule.get("message", "").format(
                        network_name=network_name["value"]
                    ),
                    "reason": recommendation_rule.get("reason", "").format(
                        network_name=network_name["value"]
                    ),
                    "source": network_name.get("source"),
                    "source_value": network_name.get("value"),
                    "help_topic": recommendation_rule.get("help_topic")
                }

                recommendations.append(recommendation)

    # -------------------------------------------------
    # Pass 6: Miscellaneous recommendations
    # -------------------------------------------------

    miscellaneous = analysis.get("misc", {}).get("miscellaneous", [])
    misc_rules = rule_groups.get("misc", {})

    for misc_object in miscellaneous:

        for fact_name in ("vmware_tools", "usb_present"):

            fact = misc_object.get(fact_name)

            if fact is None:
                continue

            value = fact["value"]

            rule_selector = str(value).lower()

            fact_rules = misc_rules.get(fact_name, {})
            selected_rule = fact_rules.get(rule_selector)

            if selected_rule is None:
                selected_rule = fact_rules.get("default")

            if selected_rule is None:
                continue

            for index, recommendation_rule in enumerate(
                selected_rule.get("recommendations", []),
                start=1
            ):

                recommendation = {
                    "id": f"misc.{misc_object['id']}.{fact_name}.{rule_selector}.{index}",
                    "category": "misc",
                    "type": recommendation_rule.get("type", "migration"),
                    "severity": recommendation_rule.get("severity", "info"),
                    "message": recommendation_rule.get("message", "").format(
                        value=value
                    ),
                    "reason": recommendation_rule.get("reason", "").format(
                        value=value
                    ),
                    "source": fact.get("source"),
                    "source_value": value,
                    "help_topic": recommendation_rule.get("help_topic")
                }

                recommendations.append(recommendation)

    return recommendations

def get_fact(
    analysis: dict[str, Any],
    fact_name: str
) -> dict[str, Any] | None:
    """
    Returns a normalized fact from the VM analysis.

    This function hides the internal structure of the analysis data from
    the recommendation engine. This keeps rules.yaml human-readable and
    independent of the Python implementation.

    Returns None if the requested fact cannot be found.
    """

    hardware = analysis.get("hardware", {})

    if fact_name in hardware:
        return hardware[fact_name]

    miscellaneous = analysis.get("misc", {}).get("miscellaneous", [])

    for misc_object in miscellaneous:
        if fact_name in misc_object:
            return misc_object[fact_name]

    return None



def render_html_report(
    vmx_data: dict[str, str],
    findings: list[dict[str, str]],
    analysis: dict[str, Any],
    recommendations: list[dict[str, Any]],
    help_topics: dict[str, Any],
    output_file: str | Path
) -> None:

    output_file = Path(output_file)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    hardware = analysis.get("hardware", {})

    name = hardware.get(
        "name",
        {}
    ).get(
        "value",
        "Unknown VM"
    )

    guest_os = hardware.get(
        "guest_os",
        {}
    ).get(
        "value",
        "Unknown"
    )

    firmware = hardware.get(
        "firmware",
        {}
    ).get(
        "value",
        "Unknown"
    )

    cpu_count = hardware.get(
        "cpu_count",
        {}
    ).get(
        "value",
        "Unknown"
    )

    memory_mb = hardware.get(
        "memory_mb",
        {}
    ).get(
        "value",
        "Unknown"
    )

    warning_count = sum(
        1
        for recommendation in recommendations
        if recommendation.get("severity") == "warning"
    )

    recommendation_count = sum(
        1
        for recommendation in recommendations
        if recommendation.get("severity") == "recommendation"
    )

    info_count = sum(
        1
        for recommendation in recommendations
        if recommendation.get("severity") == "info"
    )

    def format_value(
        value: Any
    ) -> str:

        if isinstance(value, dict):
            return "<br>".join(
                f"{escape(str(k))}: {escape(str(v))}"
                for k, v in value.items()
            )

        if isinstance(value, list):
            return "<br>".join(
                escape(str(v))
                for v in value
            )

        return escape(str(value))

    def render_help_html(
        topic_name: str | None
    ) -> str:

        if not topic_name:
            return ""

        topic = help_topics.get(topic_name)

        if topic is None:
            return f"""
            <div class="help-missing">
                Help topic not found:
                <code>{escape(topic_name)}</code>
            </div>
            """

        title = escape(
            str(
                topic.get(
                    "title",
                    topic_name
                )
            )
        )

        category = topic.get("category")
        phase = topic.get("phase")
        description = topic.get("description")

        content = ""

        if category or phase:

            metadata = []

            if category:
                metadata.append(
                    f"<strong>Category:</strong> "
                    f"{escape(str(category))}"
                )

            if phase:
                metadata.append(
                    f"<strong>Phase:</strong> "
                    f"{escape(str(phase))}"
                )

            content += (
                '<p class="help-metadata">'
                + " &nbsp; | &nbsp; ".join(metadata)
                + "</p>"
            )

        if description:
            content += f"""
            <div class="help-section">

                <h4>
                    Description
                </h4>

                <p>
                    {escape(str(description).strip())}
                </p>

            </div>
            """

        checks = topic.get(
            "checks",
            []
        )

        if checks:

            check_content = ""

            for check in checks:

                check_description = escape(
                    str(
                        check.get(
                            "description",
                            ""
                        )
                    )
                )

                command = check.get("command")

                check_content += """
                <div class="help-check">
                """

                if check_description:
                    check_content += f"""
                    <p>
                        {check_description}
                    </p>
                    """

                if command:
                    check_content += f"""
                    <pre class="help-command">$ {escape(str(command))}</pre>
                    """

                check_content += """
                </div>
                """

            content += f"""
            <div class="help-section">

                <h4>
                    Checks
                </h4>

                {check_content}

            </div>
            """

        examples = topic.get(
            "examples",
            []
        )

        if examples:

            example_content = ""

            for number, example in enumerate(
                examples,
                start=1
            ):

                example_title = escape(
                    str(
                        example.get(
                            "title",
                            f"Example {number}"
                        )
                    )
                )

                example_text = example.get(
                    "text"
                )

                example_command = example.get(
                    "command"
                )

                example_result = example.get(
                    "result"
                )

                example_content += f"""
                <div class="help-example">

                    <div class="help-example-title">
                        Example {number}: {example_title}
                    </div>
                """

                if example_text:
                    example_content += f"""
                    <p class="help-example-text">
                        {escape(str(example_text).strip())}
                    </p>
                    """

                if example_command:
                    example_content += f"""
                    <pre class="help-command">$ {escape(str(example_command))}</pre>
                    """

                if example_result:
                    example_content += f"""
                    <div class="help-example-result">

                        <strong>
                            Result / Interpretation
                        </strong>

                        <p>
                            {escape(str(example_result).strip())}
                        </p>

                    </div>
                    """

                example_content += """
                </div>
                """

            content += f"""
            <div class="help-section help-examples-section">

                <h4>
                    Examples
                </h4>

                {example_content}

            </div>
            """

        notes = topic.get(
            "notes",
            []
        )

        if notes:

            note_content = "".join(
                f"<li>{escape(str(note).strip())}</li>"
                for note in notes
            )

            content += f"""
            <div class="help-section">

                <h4>
                    Notes
                </h4>

                <ul>
                    {note_content}
                </ul>

            </div>
            """

        warnings = topic.get(
            "warnings",
            []
        )

        if warnings:

            warning_content = "".join(
                f"<li>{escape(str(warning).strip())}</li>"
                for warning in warnings
            )

            content += f"""
            <div class="help-section help-warning-section">

                <h4>
                    Warnings
                </h4>

                <ul>
                    {warning_content}
                </ul>

            </div>
            """

        return f"""
        <details class="help-details">

            <summary>
                Help: {title}
            </summary>

            <div class="help-body">

                {content}

                <div class="help-topic-id">

                    Topic:
                    <code>
                        {escape(topic_name)}
                    </code>

                </div>

            </div>

        </details>
        """

    def render_recommendation(
        recommendation: dict[str, Any]
    ) -> str:

        severity = recommendation.get(
            "severity",
            "info"
        )

        rec_type = recommendation.get(
            "type",
            "migration"
        )

        message = escape(
            str(
                recommendation.get(
                    "message",
                    ""
                )
            )
        )

        reason = escape(
            str(
                recommendation.get(
                    "reason",
                    ""
                )
            )
        )

        source = format_value(
            recommendation.get(
                "source",
                "Unknown"
            )
        )

        source_value = format_value(
            recommendation.get(
                "source_value",
                "Unknown"
            )
        )

        help_topic = recommendation.get(
            "help_topic"
        )

        help_html = render_help_html(
            help_topic
        )

        return f"""
        <details class="recommendation {severity}">

            <summary>

                <span class="severity">
                    {escape(str(severity).upper())}
                </span>

                {message}

            </summary>

            <div class="recommendation-body">

                <p>
                    <strong>Phase:</strong>
                    {escape(str(rec_type))}
                </p>

                <p>
                    <strong>Reason:</strong>
                    {reason}
                </p>

                <p>
                    <strong>Source:</strong><br>
                    {source}
                </p>

                <p>
                    <strong>Source value:</strong><br>
                    {source_value}
                </p>

                {help_html}

            </div>

        </details>
        """

    def render_parser_findings() -> str:

        if not findings:
            return """
            <details class="parser-findings">

                <summary>
                    Parser Findings (0)
                </summary>

                <div class="parser-findings-body">

                    <p>
                        No parser findings detected.
                    </p>

                </div>

            </details>
            """

        content = ""

        for finding in findings:

            finding_type = escape(
                str(
                    finding.get(
                        "type",
                        "unknown"
                    )
                )
            )

            key = escape(
                str(
                    finding.get(
                        "key",
                        "Unknown"
                    )
                )
            )

            message = escape(
                str(
                    finding.get(
                        "message",
                        ""
                    )
                )
            )

            line = escape(
                str(
                    finding.get(
                        "line",
                        "Unknown"
                    )
                )
            )

            original_value = finding.get(
                "original_value"
            )

            duplicate_value = finding.get(
                "duplicate_value"
            )

            value_details = ""

            if original_value is not None:
                value_details += f"""
                <p>
                    <strong>First value:</strong><br>
                    <code>
                        {escape(str(original_value))}
                    </code>
                </p>
                """

            if duplicate_value is not None:
                value_details += f"""
                <p>
                    <strong>Duplicate value:</strong><br>
                    <code>
                        {escape(str(duplicate_value))}
                    </code>
                </p>
                """

            content += f"""
            <div class="parser-finding">

                <strong class="parser-finding-title">
                    WARNING — {message}
                </strong>

                <p>
                    <strong>Type:</strong>
                    {finding_type}
                </p>

                <p>
                    <strong>Key:</strong>
                    <code>{key}</code>
                </p>

                <p>
                    <strong>Duplicate found at line:</strong>
                    {line}
                </p>

                {value_details}

            </div>
            """

        return f"""
        <details class="parser-findings" open>

            <summary>
                Parser Findings ({len(findings)})
            </summary>

            <div class="parser-findings-body">
                {content}
            </div>

        </details>
        """

    validation_recommendations = []
    migration_recommendations = []
    post_migration_recommendations = []
    modernization_recommendations = []

    for recommendation in recommendations:

        rec_type = recommendation.get(
            "type"
        )

        if rec_type == "validation":
            validation_recommendations.append(
                recommendation
            )

        elif rec_type == "post_migration":
            post_migration_recommendations.append(
                recommendation
            )

        elif rec_type == "modernization":
            modernization_recommendations.append(
                recommendation
            )

        else:
            migration_recommendations.append(
                recommendation
            )

    def render_group(
        title: str,
        group: list[dict[str, Any]]
    ) -> str:

        if not group:
            return ""

        content = "".join(
            render_recommendation(
                recommendation
            )
            for recommendation in group
        )

        return f"""
        <details class="group" open>

            <summary>
                {escape(title)} ({len(group)})
            </summary>

            <div class="group-body">
                {content}
            </div>

        </details>
        """

    vmx_lines = []

    for key, value in vmx_data.items():

        vmx_lines.append(
            f'{escape(str(key))} = '
            f'"{escape(str(value))}"'
        )

    vmx_content = "\n".join(
        vmx_lines
    )

    html = f"""<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >

    <title>
        Migration Assessment - {escape(str(name))}
    </title>

    <style>

        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            background: #f4f6f8;
            color: #202124;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 32px;
        }}

        header {{
            background: #202a35;
            color: white;
            padding: 24px 32px;
            border-radius: 8px;
            margin-bottom: 24px;
        }}

        header h1 {{
            margin: 0 0 8px 0;
        }}

        header h2 {{
            margin: 0;
            font-weight: normal;
        }}

        .summary {{
            display: flex;
            gap: 16px;
            margin-bottom: 24px;
        }}

        .summary-box {{
            background: white;
            padding: 16px 24px;
            border-radius: 8px;
            flex: 1;
            text-align: center;
        }}

        .summary-number {{
            font-size: 28px;
            font-weight: bold;
            display: block;
        }}

        .source-vm {{
            background: white;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 24px;
        }}

        .source-grid {{
            display: grid;
            grid-template-columns:
                repeat(
                    auto-fit,
                    minmax(180px, 1fr)
                );
            gap: 16px;
        }}

        .source-item strong {{
            display: block;
            margin-bottom: 4px;
        }}

        details {{
            background: white;
            border-radius: 6px;
            margin-bottom: 10px;
        }}

        summary {{
            cursor: pointer;
            padding: 14px 16px;
            font-weight: bold;
        }}

        .group {{
            margin-bottom: 18px;
        }}

        .group > summary {{
            background: #e8edf2;
            font-size: 18px;
        }}

        .group-body {{
            padding: 10px 16px 16px 16px;
        }}

        .recommendation {{
            border-left: 5px solid #888;
        }}

        .recommendation.warning {{
            border-left-color: #b42318;
        }}

        .recommendation.warning > summary {{
            color: #b42318;
        }}

        .recommendation.recommendation {{
            border-left-color: #326da8;
        }}

        .recommendation.info {{
            border-left-color: #6c757d;
        }}

        .recommendation-body {{
            padding: 0 20px 16px 20px;
        }}

        .severity {{
            display: inline-block;
            min-width: 130px;
            font-size: 12px;
        }}

        .vmx-content {{
            background: #1f2933;
            color: #f5f7fa;
            padding: 20px;
            margin: 0 20px 20px 20px;
            border-radius: 6px;
            overflow-x: auto;
            font-family: "Courier New", monospace;
            font-size: 14px;
            line-height: 1.5;
            white-space: pre;
        }}

        .vmx-note {{
            margin: 0 20px 12px 20px;
            color: #666;
            font-size: 13px;
        }}

        .parser-findings {{
            background: white;
            border-radius: 8px;
            margin-bottom: 24px;
            border-left: 5px solid #b42318;
        }}

        .parser-findings > summary {{
            color: #b42318;
            font-size: 17px;
        }}

        .parser-findings-body {{
            padding: 0 20px 16px 20px;
        }}

        .parser-finding {{
            background: #fff5f5;
            padding: 14px 16px;
            margin-top: 10px;
            border-radius: 6px;
        }}

        .parser-finding-title {{
            color: #b42318;
        }}

        .parser-finding code {{
            background: #f1f3f5;
            padding: 2px 5px;
            border-radius: 3px;
            font-family: "Courier New", monospace;
        }}

        .help-details {{
            margin-top: 16px;
            background: #f7f9fb;
            border-left: 4px solid #326da8;
        }}

        .help-details > summary {{
            color: #285f96;
            font-size: 15px;
        }}

        .help-body {{
            padding: 4px 18px 18px 18px;
        }}

        .help-metadata {{
            color: #555;
            font-size: 13px;
        }}

        .help-section {{
            margin-top: 18px;
        }}

        .help-section h4 {{
            margin-bottom: 8px;
        }}

        .help-section ul {{
            padding-left: 24px;
        }}

        .help-section li {{
            margin-bottom: 8px;
            line-height: 1.5;
        }}

        .help-check {{
            margin-bottom: 14px;
        }}

        .help-check p {{
            margin-bottom: 6px;
        }}

        .help-command {{
            background: #1f2933;
            color: #f5f7fa;
            padding: 10px 12px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: "Courier New", monospace;
            line-height: 1.5;
        }}

        .help-examples-section {{
            margin-top: 22px;
        }}

        .help-example {{
            background: white;
            border: 1px solid #d8dee4;
            border-left: 4px solid #326da8;
            border-radius: 6px;
            padding: 14px 16px;
            margin-top: 12px;
        }}

        .help-example-title {{
            font-weight: bold;
            color: #285f96;
            margin-bottom: 10px;
        }}

        .help-example-text {{
            line-height: 1.5;
        }}

        .help-example-result {{
            background: #eef5fb;
            border-radius: 5px;
            padding: 10px 12px;
            margin-top: 12px;
        }}

        .help-example-result p {{
            margin-bottom: 0;
            line-height: 1.5;
        }}

        .help-warning-section {{
            border-left: 4px solid #b42318;
            padding-left: 14px;
        }}

        .help-warning-section h4 {{
            color: #b42318;
        }}

        .help-topic-id {{
            margin-top: 18px;
            padding-top: 10px;
            border-top: 1px solid #ddd;
            color: #777;
            font-size: 12px;
        }}

        .help-missing {{
            margin-top: 16px;
            padding: 12px;
            background: #fff5f5;
            border-left: 4px solid #b42318;
            color: #b42318;
        }}

        footer {{
            margin-top: 32px;
            font-size: 13px;
            color: #666;
            text-align: center;
        }}

    </style>

</head>

<body>

<div class="container">

    <header>

        <h1>
            VMware → Proxmox Migration Assessment
        </h1>

        <h2>
            {escape(str(name))}
        </h2>

    </header>

    <section class="summary">

        <div class="summary-box">

            <span class="summary-number">
                {warning_count}
            </span>

            Warnings

        </div>

        <div class="summary-box">

            <span class="summary-number">
                {recommendation_count}
            </span>

            Recommendations

        </div>

        <div class="summary-box">

            <span class="summary-number">
                {info_count}
            </span>

            Information

        </div>

    </section>

    <details class="source-vm" open>

        <summary>
            Source VM Analysis
        </summary>

        <div class="source-grid">

            <div class="source-item">
                <strong>Name</strong>
                {escape(str(name))}
            </div>

            <div class="source-item">
                <strong>Guest OS</strong>
                {escape(str(guest_os))}
            </div>

            <div class="source-item">
                <strong>Firmware</strong>
                {escape(str(firmware))}
            </div>

            <div class="source-item">
                <strong>vCPU</strong>
                {escape(str(cpu_count))}
            </div>

            <div class="source-item">
                <strong>Memory</strong>
                {escape(str(memory_mb))} MB
            </div>

        </div>

    </details>

    <details class="source-vm">

        <summary>
            Parsed VMX Configuration
        </summary>

        <p class="vmx-note">
            Parsed VMware VMX configuration used as
            input for this assessment.
            Duplicate keys are reported separately
            under Parser Findings.
        </p>

        <pre class="vmx-content">{vmx_content}</pre>

    </details>

    {render_parser_findings()}

    <h2>
        Migration Recommendations
    </h2>

    {render_group(
        "Pre-Migration / Validation",
        validation_recommendations
    )}

    {render_group(
        "Migration",
        migration_recommendations
    )}

    {render_group(
        "Post-Migration",
        post_migration_recommendations
    )}

    {render_group(
        "Modernization",
        modernization_recommendations
    )}

    <footer>
        VMware → Proxmox Migration Analyzer
    </footer>

</div>

</body>

</html>
"""

    output_file.write_text(
        html,
        encoding="utf-8"
    )


def main() -> None:

    parser = argparse.ArgumentParser(
        description="VMware to Proxmox Migration Analyzer"
    )

    parser.add_argument(
        "vmx_file",
        nargs="?",
        default="testdata/prod-app01.vmx",
        help=(
            "VMware VMX file to analyze "
            "(default: testdata/prod-app01.vmx)"
        )
    )

    parser.add_argument(
        "--show-help",
        metavar="TOPIC",
        help=(
            "Show detailed migration help for a topic "
            "and exit. Use 'list' to show all topics."
        )
    )

    args = parser.parse_args()

    config_file = Path("config.yaml")
    rules_file = Path("rules.yaml")
    help_file = Path("help.yaml")

    # Load help topics

    help_topics = load_help(help_file)

    # Handle standalone help requests

    if args.show_help:

        if args.show_help == "list":
            print_help_topics(help_topics)

        else:
            print_help_topic(
                args.show_help,
                help_topics
            )

        return

    # VMX file from command line or default test VMX

    vmx_file = Path(args.vmx_file)

    # Load and validate configuration

    config = load_config(config_file)

    validate_config(config)

    # Load recommendation rules

    rules = load_rules(rules_file)

    # Parse VMware VMX

    vmx_data, findings = parse_vmx(vmx_file)

    # Build normalized VM model

    analysis = analyze_vm(vmx_data)

    # Generate migration recommendations

    recommendations = generate_recommendations(
        analysis,
        rules,
        config
    )

    validate_recommendation_help_topics(
        recommendations,
        help_topics
    )

    output_config = config.get("output", {})

    output_format = output_config.get(
        "format",
        "text"
    )

    if output_format == "html":

        output_directory = Path(
            output_config.get(
                "directory",
                "output"
            )
        )

        vm_name = analysis.get(
            "hardware", {}
        ).get(
            "name", {}
        ).get(
            "value", "vm"
        )

        output_file = (
            output_directory /
            f"{vmx_file.stem}.html"
        )

        render_html_report(
            vmx_data,
            findings,
            analysis,
            recommendations,
            help_topics,
            output_file
        )

        print(
            f"HTML report written to: {output_file}"
        )

def print_help_topics(
    help_topics: dict[str, Any]
) -> None:

    print()
    print("Available help topics")
    print("=" * 72)

    for topic_name in sorted(help_topics):

        topic = help_topics[topic_name]

        title = topic.get(
            "title",
            topic_name
        )

        print(
            f"{topic_name:<28} {title}"
        )

    print()


def print_help_topic(
    topic_name: str,
    help_topics: dict[str, Any]
) -> None:

    topic = help_topics.get(topic_name)

    if topic is None:
        print()
        print(f"Unknown help topic: {topic_name}")
        print("Use --show-help list to show available topics.")
        print()
        return

    width = 72

    def print_wrapped(
        text: str,
        initial_indent: str = "",
        subsequent_indent: str = ""
    ) -> None:

        print(
            textwrap.fill(
                str(text).strip(),
                width=width,
                initial_indent=initial_indent,
                subsequent_indent=subsequent_indent
            )
        )

    print()
    print("=" * width)
    print(topic.get("title", topic_name))
    print("=" * width)

    category = topic.get("category")
    phase = topic.get("phase")

    if category:
        print(f"Category : {category}")

    if phase:
        print(f"Phase    : {phase}")

    description = topic.get("description")

    if description:
        print()
        print("DESCRIPTION")
        print("-" * width)
        print_wrapped(description)

    checks = topic.get("checks", [])

    if checks:
        print()
        print("CHECKS")
        print("-" * width)

        for check in checks:

            check_description = check.get(
                "description",
                ""
            )

            command = check.get("command")

            if check_description:
                print_wrapped(
                    check_description,
                    initial_indent="* ",
                    subsequent_indent="  "
                )

            if command:
                print_wrapped(
                    f"$ {command}",
                    initial_indent="    ",
                    subsequent_indent="      "
                )

            print()

    examples = topic.get("examples", [])

    if examples:
        print("EXAMPLES")
        print("-" * width)

        for number, example in enumerate(
            examples,
            start=1
        ):

            title = example.get(
                "title",
                f"Example {number}"
            )

            text = example.get("text")
            command = example.get("command")
            result = example.get("result")

            print(f"{number}. {title}")

            if text:
                print()
                print_wrapped(
                    text,
                    initial_indent="   ",
                    subsequent_indent="   "
                )

            if command:
                print()
                print_wrapped(
                    f"$ {command}",
                    initial_indent="   ",
                    subsequent_indent="     "
                )

            if result:
                print()
                print_wrapped(
                    result,
                    initial_indent="   Result: ",
                    subsequent_indent="           "
                )

            print()

    notes = topic.get("notes", [])

    if notes:
        print("NOTES")
        print("-" * width)

        for note in notes:
            print_wrapped(
                note,
                initial_indent="* ",
                subsequent_indent="  "
            )
            print()

    warnings = topic.get("warnings", [])

    if warnings:
        print("WARNINGS")
        print("-" * width)

        for warning in warnings:
            print_wrapped(
                warning,
                initial_indent="! ",
                subsequent_indent="  "
            )
            print()

if __name__ == "__main__":
    main()

