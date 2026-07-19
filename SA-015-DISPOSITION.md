# SA-015 disposition

## Status

`CONCLUSIVELY_DISPOSITIONED — RETAIN FAIL`

`SA-015` is a low-severity, exact-version cross-SDK interoperability finding.
It is not proven to be an MCP protocol violation or an authorization bypass in
a downstream host.

## Affected versions and paths

- Python: `mcp@1.28.1`
  - `JSONRPCMessage.model_validate_json`
  - `ClientRequest.model_validate`
- TypeScript: `@modelcontextprotocol/sdk@1.29.0`
  - `JSONRPCMessageSchema.parse`
  - `CallToolRequestSchema.parse`

## Minimal reproducer

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"danger","arguments":{"tenant":"a"}},"name":"safe"}
```

The exact contained execution records:

- Python accepts the envelope and selects `params.name = "danger"`.
- TypeScript rejects the envelope because its JSON-RPC request schema is
  strict about unknown top-level members.

Valid requests, an ordinary unknown field inside `params`, duplicate `method`
keys, mixed-case `Method`, and a confusable method-key variant did not produce
another authority-relevant disagreement in the bounded matrix.

## Protocol basis

The MCP tools specification places the invoked tool name at `params.name`.
JSON-RPC 2.0 enumerates the members of a Request Object and requires
case-sensitive matching, but it does not normatively require one policy for
unknown top-level members. Therefore, the observed strict-versus-permissive
choice is an implementation divergence; the available evidence does not prove
which SDK violates the protocol.

Primary sources:

- [MCP tools/call specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)
- [JSON-RPC 2.0 Request Object](https://www.jsonrpc.org/specification#request_object)
- [Python SDK v1.28.1 types](https://github.com/modelcontextprotocol/python-sdk/blob/v1.28.1/src/mcp/types.py)
- [TypeScript SDK v1.29.0 types](https://github.com/modelcontextprotocol/typescript-sdk/blob/v1.29.0/src/types.ts)

## Security consequence

A host that authorizes from an unvalidated raw envelope but executes from an
SDK-normalized request could make a different authority decision from a host
using the other SDK. This case does not show such a host or a completed bypass;
it proves that cross-SDK parser equivalence is unsafe to assume.

## Recommended upstream action

Add this envelope to the official cross-SDK conformance corpus. The SDK owners
should either align top-level unknown-member handling or document the
intentional compatibility difference and the expected server behavior.

No upstream issue was opened because this program has no publication or
disclosure authority.

## Compensating host control

Before authorization or execution, hosts should:

1. Apply one strict canonical request-envelope validator.
2. Reject unrecognized top-level fields for security-sensitive methods.
3. Derive tool identity only from the validated `tools/call` `params.name`.
4. Bind the authorized canonical request digest to the executed request.

## Closure decision

Retain `SA-015` as `FAIL`. The finding is conclusively dispositioned for this
program without claiming a local SDK repair, upstream acceptance, protocol
noncompliance, or a downstream exploit.
