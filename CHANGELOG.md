# Changelog

## 0.2.0

### Renamed (BREAKING for anything matching on ids or tool names)

The six endpoints follow the naming convention ikigai-core's crate docs state: a
resource name is a short `kebab-case` noun, and the `Description::id` is what the MCP
projection turns into an agent's tool name (ledger #11).

| old id → new id | old IRI → new IRI |
| --- | --- |
| `httpGet` → `http-get` | `urn:httpGet` → `urn:http:get` |
| `httpHead` → `http-head` | `urn:httpHead` → `urn:http:head` |
| `httpPost` → `http-post` | `urn:httpPost` → `urn:http:post` |
| `httpPut` → `http-put` | `urn:httpPut` → `urn:http:put` |
| `httpPatch` → `http-patch` | `urn:httpPatch` → `urn:http:patch` |
| `httpDelete` → `http-delete` | `urn:httpDelete` → `urn:http:delete` |

- **The ids change outright.** An id is a name, not an IRI, and nothing resolves by
  it: MCP tool names and catalog labels move with this release.
- **The old IRIs are deprecated aliases through 0.2.x.** `urn:httpGet` resolves
  exactly as `urn:http:get`: one cache entry and one golden thread for both names,
  the new id when it describes itself, and only the new names in the catalog. So
  consumers, route configs and books migrate on their own schedule, with no flag day.
  `Method::deprecated_iri` names each one.
- **`space()` now returns core's `Alias` overlay** over the six bindings, which is how
  the aliases resolve. A host that holds it as `Arc<dyn Space>` (every known
  consumer does) is unaffected; one that names the type `EndpointSpace` changes that
  line. New: `endpoints()` (the bare `EndpointSpace`, no aliases),
  `deprecated_aliases()` (the rewrite table, for `Kernel::with_aliases` and the
  `urn:kernel:aliases` readout) and `Method::ALL`.
- `ikigai-conformance`'s `NAMES` check now runs, and is clean.

### Removal scheduled

**0.3.0 removes the deprecated aliases**, `Method::deprecated_iri` and
`deprecated_aliases()`; `urn:httpGet` … `urn:httpDelete` then miss, and `space()`
returns the `EndpointSpace` again.
