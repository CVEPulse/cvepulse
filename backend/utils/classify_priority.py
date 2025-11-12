def classify_cve(cve):
    desc = cve.get("description", "").lower()
    cvss = cve.get("cvss", 0)
    zero_day = any(k in desc for k in ["zero day", "0day", "no patch", "vendor unaware"])
    exploit = any(k in desc for k in ["exploit", "in the wild", "poc"])
    if exploit and cvss >= 9:
        priority = "Critical"
        emergency = True
    elif exploit or zero_day:
        priority = "High"
        emergency = False
    else:
        priority = "Medium"
        emergency = False
    cve.update({"priority": priority, "emergency": emergency, "zero_day": zero_day})
    return cve
