# DNS upstream architecture

## Purpose

Build one curated, comprehensive DNS filter from purpose-specific upstream components, following the production model used by AdGuard DNS Filter. The project must not create its Full list by unioning complete, already-aggregated DNS blocklists.

The target is not a predetermined rule count. A smaller list with clear source roles, controlled semantics, and defensible exceptions is preferable to a large list formed by stacking overlapping products.

## Reference model

AdGuard DNS Filter's upstream `configuration.json` is the reference for source composition. It selects individual sections (for example, Base ad servers, Mobile ad servers, Tracking Protection sections, EasyList ad-server sections, EasyPrivacy tracking-server sections, and regional ad-server sections), applies source-specific transformations and exclusions, then performs global compression and deduplication.

Reference:
- https://github.com/AdguardTeam/AdGuardSDNSFilter/blob/master/configuration.json
- https://github.com/AdguardTeam/AdGuardSDNSFilter/blob/master/Filters/exclusions.txt
- https://github.com/AdguardTeam/AdGuardSDNSFilter/blob/master/package.json

## Proposed production source roles

These are component-level upstreams, not complete third-party DNS products. They form the initial source-selection proposal for implementation and validation.

| Role | Component source | Intended contribution |
|---|---|---|
| Core advertising | AdGuard Base `adservers.txt`, `adservers_firstparty.txt`, `foreign.txt` | General advertising and first-party ad delivery |
| Mobile advertising | AdGuard Mobile Filter `sections/adservers.txt` | Mobile app and mobile advertising networks |
| Tracking | AdGuard Tracking Protection `tracking_servers.txt`, `tracking_servers_firstparty.txt`, `mobile.txt` | Third-party, first-party, and mobile trackers |
| Global ad-server coverage | EasyList `easylist_adservers.txt`, `easylist_specific_block.txt`, and third-party server section | Domain-level advertising coverage; third-party section must use the official inclusion scope |
| Tracking supplements | EasyPrivacy tracking-server sections | Tracking domains not already covered by core sections; reviewed as components, not full EasyPrivacy browser list |
| Chinese/regional ads | AdGuard Chinese Filter `adservers.txt` and `adservers_firstparty.txt`; EasyList China with DNS-safe third-party extraction | China-specific advertising and regional coverage |
| Other regional ads | Selected AdGuard regional ad-server sections, using the sections listed in the official DNS filter configuration | Regional coverage only where the section contributes meaningful, licensed, non-duplicative value |
| Threat intelligence | One dedicated, maintained threat component (initial candidate: hostsVN Threat section) plus project-reviewed manual threat entries | Malware/phishing risk; kept distinct from ad/tracker decisions |

### Component URLs

- AdGuard Base ad servers: https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/adservers.txt
- AdGuard Base first-party ad servers: https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/adservers_firstparty.txt
- AdGuard Base foreign section: https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/foreign.txt
- AdGuard Mobile ad servers: https://adguardteam.github.io/AdguardFilters/MobileFilter/sections/adservers.txt
- AdGuard Tracking Protection third-party trackers: https://adguardteam.github.io/AdguardFilters/SpywareFilter/sections/tracking_servers.txt
- AdGuard Tracking Protection first-party trackers: https://adguardteam.github.io/AdguardFilters/SpywareFilter/sections/tracking_servers_firstparty.txt
- AdGuard Tracking Protection mobile trackers: https://adguardteam.github.io/AdguardFilters/SpywareFilter/sections/mobile.txt
- EasyList ad servers: https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_adservers.txt
- EasyList specific block: https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_specific_block.txt
- EasyList third-party server section: https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_thirdparty.txt
- EasyPrivacy tracking servers: https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers.txt
- EasyPrivacy third-party tracking servers: https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_thirdparty.txt
- AdGuard Chinese ad servers: https://adguardteam.github.io/AdguardFilters/ChineseFilter/sections/adservers.txt
- AdGuard Chinese first-party ad servers: https://adguardteam.github.io/AdguardFilters/ChineseFilter/sections/adservers_firstparty.txt
- EasyList China: https://raw.githubusercontent.com/easylist/easylistchina/master/easylistchina.txt
- hostsVN Threat component: https://raw.githubusercontent.com/bigdargon/hostsVN/master/extensions/threat/filter.txt

## Complete products excluded from direct production stacking

The following complete products must not be simultaneously stacked as production inputs alongside their overlapping component sources:

- AdGuard DNS Filter complete output
- HaGeZi complete DNS lists (including Pro Mini)
- OISD Small/Big
- 1Hosts Lite
- anti-AD complete DNS output
- AWAvenue Only Ads
- StevenBlack complete hosts list

These projects remain valuable as **comparison references** for source lineage, coverage differences, and candidate discovery. Their absence from production does not mean their domains are rejected; any unique candidates require source attribution, semantic review, licensing review, and an explicit promotion decision. They are not independent votes, and a complete product's allow rule must not automatically veto a block from a different policy.

## Conflict and exception model

A global union of upstream allow rules is not an acceptable conflict policy. It can cause one source author's exception to silently override another source author's block, even though the authors apply different criteria.

The implementation must separate:

1. **Official project-wide exclusions**: reviewed exceptions applied consistently to the selected composition, with evidence and scope.
2. **Source-local exceptions**: retained for interpreting that source's own section; not automatically promoted to a global allow.
3. **Project whitelist**: evidence-based compatibility exceptions maintained by this project.
4. **Candidate product allow rules**: comparison-only; never affect production output.

Absence from a source is not an explicit allow. Source overlap is not independent confirmation. A source's allow/block disagreement is an audit event requiring a defined decision, not a silent global veto.

## Build pipeline required

1. Fetch each pinned component URL and record checksum, license, and upstream revision.
2. Apply per-source inclusion/exclusion and DNS-syntax transformations before merging.
3. Preserve supported DNS rule semantics; do not flatten record-type or scope modifiers into unconditional host blocks.
4. Apply the project-wide reviewed exclusion set and project whitelist with explicit precedence.
5. Normalize and deduplicate only after source-specific processing.
6. Compile Full with AdGuard Hostlist Compiler and validate the final output.
7. Generate Lite from the same governed rule corpus using a documented geographic/classification policy, not a second pile of sources.
8. Publish a source-by-source audit: input counts, accepted/rejected rule classes, unique contribution, overlap, allow/block conflicts, exclusions, license, and final output contribution.

## Implementation boundary

This document defines the intended source architecture. It does **not** claim that the current production `sources.json` or generator already implements it. Production source replacement must be delivered as a separate, testable code change after the parser supports source roles, per-source transformations, scoped exceptions, and deterministic inclusion/exclusion. The existing complete-product stack must not be declared final or quality-accepted in the meantime.
