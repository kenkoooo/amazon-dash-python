import json


def load_config(filepath, *, logger):
    with open(filepath) as f:
        json_data = json.load(f)
        if "buttons" not in json_data:
            return []
        buttons = []
        for button in json_data["buttons"]:
            address = button["address"]
            if not is_valid_mac_address(address, logger=logger):
                continue
            if button["method"] != "post":
                logger.error("method %s is not supported", button["method"])
                continue
            buttons.append(button)
        return buttons


def is_valid_mac_address(mac_address, *, logger):
    """
    validate mac address
    :param logger: logger
    :param mac_address:
    :return:
    """
    nums = mac_address.split(":")
    if len(nums) != 6:
        return False
    for num in nums:
        try:
            int(num, 16)
        except ValueError as e:
            logger.error(e)
            return False
    return True
