import jsonschema


def validate(result, incident, schema):
    errors = []
    try:
        jsonschema.validate(result, schema)
    except jsonschema.ValidationError as e:
        errors.append(f"schema: {e.message}")

    known_ids = {ev["event_id"] for ev in incident.get("events", [])}

    for claim in result.get("claims", []):
        ids = claim.get("event_ids", [])
        if not ids:
            errors.append(f"claim has no event_ids: {claim.get('statement', '')[:60]}")
        for i in ids:
            if i not in known_ids:
                errors.append(f"unknown event_id '{i}' in claims (not in evidence)")

    for step in result.get("attack_chain", []):
        for i in step.get("event_ids", []):
            if i not in known_ids:
                errors.append(f"unknown event_id '{i}' in attack_chain (not in evidence)")

    return errors
