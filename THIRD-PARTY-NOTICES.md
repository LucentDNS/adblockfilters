# Third-party source notices

This repository combines and transforms third-party filter lists. The repository's root `LICENSE` covers the project's own code; it does **not** replace the individual licenses or notices that apply to upstream rule data. The upstream terms remain applicable to their respective material.

The build preserves the applicable license texts and attribution references in the `licenses/` directory and republishes copies alongside the generated subscriptions, upstream source snapshots, and audit evidence. Generated outputs are modified/normalized compilations; they are not verbatim copies of any single upstream list. The project does not claim ownership of third-party entries or attempt to relicense upstream material under one blanket license.

## Production DNS/Hosts sources

| Source | Upstream license | Evidence |
|---|---|---|
| AdGuard DNS filter | GPL-3.0 | [LICENSE](https://github.com/AdguardTeam/AdGuardSDNSFilter/blob/master/LICENSE) |
| AWAvenue Ads Rule (Only.Ads) | GPL-3.0 | [LICENSE](https://github.com/TG-Twilight/AWAvenue-Ads-Rule/blob/main/LICENSE) |
| HaGeZi DNS-Blocklists (Pro Mini) | GPL-3.0 | [LICENSE and redistribution terms](https://github.com/hagezi/dns-blocklists/blob/main/LICENSE) |
| StevenBlack hosts | MIT | [license.txt](https://github.com/StevenBlack/hosts/blob/master/license.txt) |
| anti-AD (AdGuard DNS rules) | MIT | [LICENSE](https://github.com/privacy-protection-tools/anti-AD/blob/master/LICENSE) |
| 1Hosts (Lite) | MPL-2.0 | [LICENSE](https://github.com/badmojr/1Hosts/blob/master/LICENSE) |

## Browser supplement sources

| Source | Upstream license | Evidence |
|---|---|---|
| AdGuard Base filter | LGPL-3.0 | [FiltersRegistry LICENSE](https://github.com/AdguardTeam/FiltersRegistry/blob/master/LICENSE) |
| AdGuard Chinese filter | LGPL-3.0 | [FiltersRegistry LICENSE](https://github.com/AdguardTeam/FiltersRegistry/blob/master/LICENSE) |
| AdGuard Mobile Ads filter | GPL-3.0 | [AdGuardFilters LICENSE](https://github.com/AdguardTeam/AdguardFilters/blob/master/LICENSE) |
| CJX's Annoyance List | LGPL-3.0 | [LICENSE](https://github.com/cjx82630/cjxlist/blob/master/LICENSE) |
| EasyList | GPL-3.0-or-later or CC BY-SA 3.0; this project selects the GPL option | [Official licensing terms](https://easylist.to/pages/licence.html) |
| EasyList China | License reference in the source header points to the EasyList licensing page; verify any upstream-specific change before altering this classification | [Official licensing terms](https://easylist.to/pages/licence.html) |
| EasyPrivacy | GPL-3.0-or-later or CC BY-SA 3.0; this project selects the GPL option | [Official licensing terms](https://easylist.to/pages/licence.html) |

## Candidate-only comparison sources

These are not merged into production subscriptions.

- OISD Small and Big: GPL-3.0, according to the [official FAQ](https://oisd.nl/?p=faq).
- HaGeZi Pro and Normal: GPL-3.0; see the [upstream license and disclaimer](https://github.com/hagezi/dns-blocklists/blob/main/LICENSE).
- CHN AdRules DNS List: its generated-list branch is not covered by a blanket 0BSD grant. Its [source catalogue](https://github.com/Cats-Team/AdRules/blob/main/Source.md) lists upstream material with mixed terms, including unknown and non-commercial licenses. It is comparison-only, and this project deliberately does not publish extracted candidate-domain files from it.

## License files

- `licenses/GPL-3.0.txt`
- `licenses/LGPL-3.0.txt`
- `licenses/MIT-anti-AD.txt`
- `licenses/MIT-StevenBlack.txt`
- `licenses/MPL-2.0-1Hosts.txt`

The manifest in `source-licenses.json` is the machine-readable source-to-license mapping. License terms and upstream repositories can change; review the linked upstream terms before each material change to source selection or redistribution. This notice is attribution and compliance documentation, not legal advice.
