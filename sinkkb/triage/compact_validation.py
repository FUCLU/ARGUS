"""Cross-object compact protocol checks (raise even under python -O)."""

def validate_compact(packet, attack, audit):
    import copy
    evidence = {e['id']: e for e in packet['evidence_registry']}
    if not len(evidence) == len(packet['evidence_registry']):
        raise ValueError("Contract violation: len(evidence) == len(packet['evidence_registry'])")

    def check_refs(value):
        if isinstance(value, dict):
            for (key, child) in value.items():
                if key in ('refs', 'path_refs', 'evidence_refs', 'derived_from'):
                    if not set(child) <= evidence.keys():
                        raise ValueError('Contract violation: set(child) <= evidence.keys()')
                    if key != 'path_refs':
                        if not len(child) == len(set(child)):
                            raise ValueError('Contract violation: len(child) == len(set(child))')
                check_refs(child)
        elif isinstance(value, list):
            for child in value:
                check_refs(child)
    for value in (packet, attack, audit):
        check_refs(value)
    for e in evidence.values():
        loc = e['location']
        if loc:
            if not loc['line_start'] <= loc['line_end']:
                raise ValueError("Contract violation: loc['line_start'] <= loc['line_end']")
        if e['kind'] == 'SOURCE':
            if not (loc and e['source_version'] == packet['source_version']):
                raise ValueError("Contract violation: loc and e['source_version'] == packet['source_version']")
            if not len(e['text'].splitlines()) == loc['line_end'] - loc['line_start'] + 1:
                raise ValueError("Contract violation: len(e['text'].splitlines()) == loc['line_end'] - loc['line_start'] + 1")
        if e['kind'] == 'DERIVED_FLOW':
            if not e['derived_from']:
                raise ValueError("Contract violation: e['derived_from']")
    for link in packet['evidence_links']:
        if not (link['from_ref'] in evidence and link['to_ref'] in evidence):
            raise ValueError("Contract violation: link['from_ref'] in evidence and link['to_ref'] in evidence")
    mapping_ids = [m['evidence_id'] for m in packet['source_mapping']]
    if not len(mapping_ids) == len(set(mapping_ids)):
        raise ValueError('Contract violation: len(mapping_ids) == len(set(mapping_ids))')
    if not set(mapping_ids) == evidence.keys():
        raise ValueError('Contract violation: set(mapping_ids) == evidence.keys()')
    for m in packet['source_mapping']:
        if not (m['original_file'] is None) == (m['original_line_start'] is None):
            raise ValueError("Contract violation: (m['original_file'] is None) == (m['original_line_start'] is None)")
    sink = packet['sink']
    if not any((evidence[r]['kind'] == 'SOURCE' and evidence[r]['location'] == sink['location'] and (evidence[r]['text'].strip() == sink['expression'].strip()) for r in sink['evidence_refs'])):
        raise ValueError("Contract violation: any((evidence[r]['kind'] == 'SOURCE' and evidence[r]['location'] == sink['location'] and (evidence[r]['text'].strip() == sink['expression'].strip()) for r in sink['evidence_refs']))")
    tm = packet['threat_model']
    if tm['id'] == 'implementation_evidence':
        if not tm['capability_basis'] == 'IMPLEMENTATION_EVIDENCE':
            raise ValueError("Contract violation: tm['capability_basis'] == 'IMPLEMENTATION_EVIDENCE'")
        if not not tm['declared_assumptions']:
            raise ValueError("Contract violation: not tm['declared_assumptions']")
    else:
        if not tm['capability_basis'] == 'DECLARED_TASK_ASSUMPTION':
            raise ValueError("Contract violation: tm['capability_basis'] == 'DECLARED_TASK_ASSUMPTION'")
        if not tm['declared_assumptions']:
            raise ValueError("Contract violation: tm['declared_assumptions']")

    def indexed(items):
        result = {x['id']: x for x in items}
        if not len(result) == len(items):
            raise ValueError('Contract violation: len(result) == len(items)')
        return result
    original = indexed(attack['scenarios'])
    if not len(original) <= packet['budget']['max_scenarios']:
        raise ValueError("Contract violation: len(original) <= packet['budget']['max_scenarios']")
    if not (original or attack['missing_context']):
        raise ValueError("Contract violation: original or attack['missing_context']")
    effective = copy.deepcopy(original)
    for s in audit.get('added_scenarios', []):
        if not s['id'] not in effective:
            raise ValueError("Contract violation: s['id'] not in effective")
        effective[s['id']] = copy.deepcopy(s)
    if not len(effective) <= packet['budget']['max_scenarios']:
        raise ValueError("Contract violation: len(effective) <= packet['budget']['max_scenarios']")
    revisions = audit.get('revisions', [])
    if not len({r['scenario_id'] for r in revisions}) == len(revisions):
        raise ValueError("Contract violation: len({r['scenario_id'] for r in revisions}) == len(revisions)")
    for r in revisions:
        if not r['scenario_id'] in original:
            raise ValueError("Contract violation: r['scenario_id'] in original")
        if not any((k in r for k in ('scenario', 'path_refs', 'prerequisites', 'potential_protections'))):
            raise ValueError("Contract violation: any((k in r for k in ('scenario', 'path_refs', 'prerequisites', 'potential_protections')))")
        s = effective[r['scenario_id']]
        for key in ('scenario', 'path_refs'):
            if key in r:
                s[key] = copy.deepcopy(r[key])
        for key in ('prerequisites', 'potential_protections'):
            values = indexed(s[key])
            for value in indexed(r.get(key, [])).values():
                values[value['id']] = copy.deepcopy(value)
            s[key] = list(values.values())
    prerequisites = indexed([p for s in effective.values() for p in s['prerequisites']])
    protections = indexed([b for s in effective.values() for b in s['potential_protections']])
    pc = indexed(audit['prerequisite_checks'])
    bc = indexed(audit['protection_checks'])
    sc = indexed(audit['scenario_checks'])
    if not pc.keys() == prerequisites.keys():
        raise ValueError('Contract violation: pc.keys() == prerequisites.keys()')
    if not bc.keys() == protections.keys():
        raise ValueError('Contract violation: bc.keys() == protections.keys()')
    if not sc.keys() == effective.keys():
        raise ValueError('Contract violation: sc.keys() == effective.keys()')
    for p in pc.values():
        if p['status'] in ('SATISFIED', 'BLOCKED'):
            if not p['refs']:
                raise ValueError("Contract violation: p['refs']")
    for b in bc.values():
        if b['status'] in ('EFFECTIVE', 'INEFFECTIVE'):
            if not b['refs']:
                raise ValueError("Contract violation: b['refs']")
    required = {'CAPABILITY', 'REACHABILITY', 'PROPAGATION', 'TRIGGER', 'OPERATION_SEMANTICS', 'SECURITY_IMPACT'}
    for (sid, s) in effective.items():
        active = [p for p in s['prerequisites'] if pc[p['id']]['status'] != 'NOT_APPLICABLE']
        statuses = [pc[p['id']]['status'] for p in active]
        if sc[sid]['status'] == 'FEASIBLE':
            if not (active and required <= {p['kind'] for p in active}):
                raise ValueError("Contract violation: active and required <= {p['kind'] for p in active}")
            if not all((x == 'SATISFIED' for x in statuses)):
                raise ValueError("Contract violation: all((x == 'SATISFIED' for x in statuses))")
        elif sc[sid]['status'] == 'BLOCKED':
            if not 'BLOCKED' in statuses:
                raise ValueError("Contract violation: 'BLOCKED' in statuses")
    coverage = audit['scope_coverage']
    feasible = any((c['status'] == 'FEASIBLE' for c in sc.values()))
    if coverage['status'] == 'ESTABLISHED':
        if not not coverage['gaps']:
            raise ValueError("Contract violation: not coverage['gaps']")
    if audit['verdict'] == 'VULNERABLE':
        if not feasible:
            raise ValueError('Contract violation: feasible')
    elif audit['verdict'] == 'BENIGN':
        if not not feasible:
            raise ValueError('Contract violation: not feasible')
        if not (coverage['status'] == 'ESTABLISHED' and coverage['invariants']):
            raise ValueError("Contract violation: coverage['status'] == 'ESTABLISHED' and coverage['invariants']")
        if not all((c['status'] == 'BLOCKED' for c in sc.values())):
            raise ValueError("Contract violation: all((c['status'] == 'BLOCKED' for c in sc.values()))")
    else:
        if not not feasible:
            raise ValueError('Contract violation: not feasible')
        if not (audit['missing_context'] or coverage['gaps']):
            raise ValueError("Contract violation: audit['missing_context'] or coverage['gaps']")
    return list(effective.values())
