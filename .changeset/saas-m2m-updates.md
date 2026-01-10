---
"@_mustachio/openauth": minor
---

- Add `M2MProvider` for service-to-service authentication using `client_credentials` grant.
- Support dynamic provider factories in `issuer` for multi-tenant (SaaS) applications.
- Add `/.well-known/openid-configuration` alias and `subject_types_supported` for AWS API Gateway JWT authorizer compatibility.
- Ensure consistent `iat` claim during token reuse interval.
- Fix dynamic routing to correctly generate provider-prefixed callback URLs.
