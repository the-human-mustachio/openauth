/**
 * SCIM discovery documents — `/ServiceProviderConfig`, `/ResourceTypes`,
 * `/Schemas`.
 *
 * Same advertise-only-what-we-serve invariant the SAML SP metadata
 * endpoint holds: a capability we announce but do not implement is worse
 * than one we never claimed, because the client will use it. So `bulk`,
 * `sort`, `etag` and `changePassword` are all declared `false` — they
 * are optional in RFC 7644 and deliberately out of scope
 * (`SCIM-AD1` non-goals).
 *
 * `filter.supported` is `true` with a `maxResults`, which is honest: we
 * do support filtering, on the documented subset (`SCIM-AD3`). SCIM has
 * no way to advertise a partial filter grammar, so the narrowing is
 * communicated where a client can actually act on it — the `400
 * invalidFilter` response names exactly what works.
 *
 * Pure: no I/O.
 */
import {
  SCIM_ENTERPRISE_SCHEMA,
  SCIM_LIST_SCHEMA,
  SCIM_USER_SCHEMA,
} from "./resource"

export function serviceProviderConfig(
  baseUrl: string,
  maxResults: number,
): Record<string, unknown> {
  return {
    schemas: [
      "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig",
    ],
    documentationUri: "https://datatracker.ietf.org/doc/html/rfc7644",
    patch: { supported: true },
    bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
    filter: { supported: true, maxResults },
    changePassword: { supported: false },
    sort: { supported: false },
    etag: { supported: false },
    authenticationSchemes: [
      {
        type: "oauthbearertoken",
        name: "OAuth Bearer Token",
        description:
          "Authentication via the bearer token issued for this SCIM connection",
        specUri: "https://datatracker.ietf.org/doc/html/rfc6750",
        primary: true,
      },
    ],
    meta: {
      resourceType: "ServiceProviderConfig",
      location: `${baseUrl}/ServiceProviderConfig`,
    },
  }
}

export function resourceTypes(baseUrl: string): Record<string, unknown> {
  const user = {
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
    id: "User",
    name: "User",
    endpoint: "/Users",
    description: "User Account",
    schema: SCIM_USER_SCHEMA,
    schemaExtensions: [
      { schema: SCIM_ENTERPRISE_SCHEMA, required: false },
    ],
    meta: {
      resourceType: "ResourceType",
      location: `${baseUrl}/ResourceTypes/User`,
    },
  }
  return {
    schemas: [SCIM_LIST_SCHEMA],
    totalResults: 1,
    startIndex: 1,
    itemsPerPage: 1,
    Resources: [user],
  }
}

type AttributeSpec = {
  name: string
  type: string
  multiValued: boolean
  required: boolean
  caseExact?: boolean
  mutability?: string
  returned?: string
  uniqueness?: string
  subAttributes?: AttributeSpec[]
}

const str = (
  name: string,
  extra: Partial<AttributeSpec> = {},
): AttributeSpec => ({
  name,
  type: "string",
  multiValued: false,
  required: false,
  caseExact: false,
  mutability: "readWrite",
  returned: "default",
  uniqueness: "none",
  ...extra,
})

const multiValueSub: AttributeSpec[] = [
  str("value"),
  str("type"),
  {
    name: "primary",
    type: "boolean",
    multiValued: false,
    required: false,
    mutability: "readWrite",
    returned: "default",
  },
]

export function schemas(baseUrl: string): Record<string, unknown> {
  const userSchema = {
    id: SCIM_USER_SCHEMA,
    name: "User",
    description: "User Account",
    attributes: [
      str("userName", { required: true, uniqueness: "server" }),
      {
        name: "name",
        type: "complex",
        multiValued: false,
        required: false,
        mutability: "readWrite",
        returned: "default",
        subAttributes: [
          str("formatted"),
          str("familyName"),
          str("givenName"),
          str("middleName"),
          str("honorificPrefix"),
          str("honorificSuffix"),
        ],
      },
      str("displayName"),
      {
        name: "active",
        type: "boolean",
        multiValued: false,
        required: false,
        mutability: "readWrite",
        returned: "default",
      },
      {
        name: "emails",
        type: "complex",
        multiValued: true,
        required: false,
        mutability: "readWrite",
        returned: "default",
        subAttributes: multiValueSub,
      },
      {
        name: "phoneNumbers",
        type: "complex",
        multiValued: true,
        required: false,
        mutability: "readWrite",
        returned: "default",
        subAttributes: multiValueSub,
      },
    ],
    meta: {
      resourceType: "Schema",
      location: `${baseUrl}/Schemas/${SCIM_USER_SCHEMA}`,
    },
  }

  const enterpriseSchema = {
    id: SCIM_ENTERPRISE_SCHEMA,
    name: "EnterpriseUser",
    description: "Enterprise User Extension",
    attributes: [
      str("employeeNumber"),
      str("costCenter"),
      str("organization"),
      str("division"),
      str("department"),
      {
        name: "manager",
        type: "complex",
        multiValued: false,
        required: false,
        mutability: "readWrite",
        returned: "default",
        subAttributes: [str("value"), str("displayName")],
      },
    ],
    meta: {
      resourceType: "Schema",
      location: `${baseUrl}/Schemas/${SCIM_ENTERPRISE_SCHEMA}`,
    },
  }

  return {
    schemas: [SCIM_LIST_SCHEMA],
    totalResults: 2,
    startIndex: 1,
    itemsPerPage: 2,
    Resources: [userSchema, enterpriseSchema],
  }
}
