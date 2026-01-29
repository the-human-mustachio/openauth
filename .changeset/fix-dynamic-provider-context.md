---
"@_mustachio/openauth": patch
---

Fix context not being available in dynamic provider route handlers. When using dynamic providers (function), the `requestContext` is now properly propagated to the child Hono instances.
