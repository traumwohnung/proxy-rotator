export { ProxyGatewayClient, type ProxyGatewayClientOptions } from "./client";
// Types
export type {
    ApiError,
    BuildProxyUsernameOptions,
    HTTPCloakSpec,
    SessionInfo,
    SessionMetadata,
    UsageFilter,
    UsageResponse,
    UsageRow,
    VerifyResult,
} from "./types";
// Zod schemas
export {
    apiErrorSchema,
    granularitySchema,
    sessionInfoSchema,
    sessionMetadataSchema,
    usageResponseSchema,
    usageRowSchema,
    verifyResultSchema,
} from "./types";
// Username helpers — pure, sync
export { buildProxyUsername, parseProxyUsername } from "./types";
// Configuration and verified username builder
export { buildAndVerifyProxyUsername, configureProxy, type ProxyConfig } from "./configure";
