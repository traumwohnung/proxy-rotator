import { z } from "zod";

/**
 * Flat JSON metadata object carried inside the username JSON.
 * All values are strings.
 */
export const sessionMetadataSchema = z.record(z.string(), z.string());

export type SessionMetadata = Record<string, string>;

export const sessionInfoSchema = z.object({
    /** Internal session ID, assigned at creation (starts at 0, increments per session). */
    session_id: z.number().int().nonnegative(),
    /** The raw base64 username string used as the affinity key. */
    username: z.string(),
    /** The proxy set name. */
    proxy_set: z.string(),
    /** The upstream proxy address (host:port). */
    upstream: z.string(),
    /** Session creation time — never changes (ISO 8601 UTC). */
    created_at: z.string(),
    /** When the current proxy assignment expires (ISO 8601 UTC). Reset on force_rotate. */
    next_rotation_at: z.string(),
    /** When the proxy was last assigned — equals created_at unless force_rotate was called (ISO 8601 UTC). */
    last_rotation_at: z.string(),
    /** The decoded metadata object from the username JSON. Values are coerced to string. */
    metadata: z.record(z.string(), z.union([z.string(), z.number()]).transform(String)),
});

export type SessionInfo = z.infer<typeof sessionInfoSchema>;

export const apiErrorSchema = z.object({
    error: z.string(),
});

export type ApiError = z.infer<typeof apiErrorSchema>;

export const verifyResultSchema = z.object({
    /** Whether all checks passed. */
    ok: z.boolean(),
    /** The proxy set name parsed from the username. */
    proxy_set: z.string(),
    /** Affinity minutes parsed from the username. */
    minutes: z.number().int().nonnegative(),
    /** The decoded metadata object. */
    metadata: z.record(z.string(), z.union([z.string(), z.number()]).transform(String)),
    /** The upstream proxy that would be used (host:port). */
    upstream: z.string(),
    /** The outbound IP address fetched through the proxy. Empty string when ok=false. */
    ip: z.string(),
    /** Error message if any check failed, absent when ok=true. */
    error: z.string().optional(),
});

export type VerifyResult = z.infer<typeof verifyResultSchema>;

// ---------------------------------------------------------------------------
// Usage query types
// ---------------------------------------------------------------------------

export const granularitySchema = z.enum(["hour", "day", "proxyset", "total"]);
export type Granularity = z.infer<typeof granularitySchema>;

export interface UsageFilter {
    /** Filter by hour_ts >= from (ISO 8601, e.g. "2026-01-15T00:00:00Z"). */
    from?: string;
    /** Filter by hour_ts <= to (ISO 8601). */
    to?: string;
    /** Exact proxy set name filter. */
    proxyset?: string;
    /**
     * JSONB containment filter on affinity_params.
     * Pass a JSON object string, e.g. `{"user":"alice"}`.
     * Matches any row whose affinity_params contains all the given key/values.
     */
    meta?: string;
    /** Controls GROUP BY aggregation. Defaults to "hour". */
    granularity?: Granularity;
    /** 1-indexed page number. Defaults to 1. */
    page?: number;
    /** Rows per page. Defaults to 100, max 1000. */
    pageSize?: number;
}

export const usageRowSchema = z.object({
    /** Set when granularity="hour" (ISO 8601 UTC). */
    hour_ts: z.string().optional(),
    /** Set when granularity="day" (YYYY-MM-DD). */
    day: z.string().optional(),
    /** Set for granularity="hour", "day", "proxyset". */
    proxyset: z.string().optional(),
    /** Set for granularity="hour" — raw JSONB string. */
    affinity_params: z.string().optional(),
    upload_bytes: z.number().int().nonnegative(),
    download_bytes: z.number().int().nonnegative(),
    total_bytes: z.number().int().nonnegative(),
});

export type UsageRow = z.infer<typeof usageRowSchema>;

export const usageResponseSchema = z.object({
    rows: z.array(usageRowSchema),
    total_count: z.number().int().nonnegative(),
    page: z.number().int().positive(),
    page_size: z.number().int().positive(),
    total_pages: z.number().int().nonnegative(),
});

export type UsageResponse = z.infer<typeof usageResponseSchema>;

// ---------------------------------------------------------------------------
// HTTPCloak types
// ---------------------------------------------------------------------------

/**
 * Configures TLS fingerprint spoofing via MITM.
 * For simple cases, pass a preset name string (e.g. "chrome-latest") instead.
 */
export interface HTTPCloakSpec {
    /** Browser fingerprint preset (e.g. "chrome-latest", "firefox-latest"). */
    preset: string;
    /** User-Agent handling: "ignore" (default), "preset", or "check". */
    user_agent?: "ignore" | "preset" | "check";
    /** Override the preset's TLS fingerprint (advanced). */
    ja3?: string;
    /** Override the preset's HTTP/2 fingerprint (advanced). */
    akamai?: string;
}

// ---------------------------------------------------------------------------
// Username construction helpers
// ---------------------------------------------------------------------------

export interface BuildProxyUsernameOptions {
    proxySet: string;
    affinityMinutes: number;
    metadata: SessionMetadata;
    /** Enable TLS fingerprint spoofing. Pass a preset name or an HTTPCloakSpec. */
    httpcloak?: HTTPCloakSpec;
}

/**
 * Build the proxy-gateway username — a base64-encoded JSON object.
 * Pure and synchronous — no verification. Use `buildAndVerifyProxyUsername`
 * to also verify that the proxy set exists and the upstream is reachable.
 *
 * @example
 * // Without httpcloak
 * buildProxyUsername({ proxySet: "residential", affinityMinutes: 60, metadata: { platform: "ka" } })
 *
 * // With httpcloak preset
 * buildProxyUsername({ proxySet: "direct", affinityMinutes: 0, metadata: {}, httpcloak: "chrome-latest" })
 *
 * // With httpcloak spec
 * buildProxyUsername({ proxySet: "direct", affinityMinutes: 0, metadata: {}, httpcloak: { preset: "chrome-latest", user_agent: "preset" } })
 */
export function buildProxyUsername(
    optsOrSet: BuildProxyUsernameOptions | string,
    affinityMinutes?: number,
    metadata?: SessionMetadata,
): string {
    // Support legacy positional args: buildProxyUsername("set", 60, { ... })
    let opts: BuildProxyUsernameOptions;
    if (typeof optsOrSet === "string") {
        opts = {
            proxySet: optsOrSet,
            affinityMinutes: affinityMinutes ?? 0,
            metadata: metadata ?? {},
        };
    } else {
        opts = optsOrSet;
    }

    const payload: Record<string, unknown> = {
        set: opts.proxySet,
        minutes: opts.affinityMinutes,
        meta: opts.metadata,
    };
    if (opts.httpcloak !== undefined) {
        payload.httpcloak = opts.httpcloak;
    }
    const json = JSON.stringify(payload);
    return btoa(json);
}

/**
 * Decode a proxy-gateway username back into its components.
 * Returns `null` if the string cannot be decoded or parsed.
 */
export function parseProxyUsername(username: string): {
    proxySet: string;
    affinityMinutes: number;
    metadata: SessionMetadata;
    httpcloak?: HTTPCloakSpec;
} | null {
    try {
        const json = atob(username);
        const obj = JSON.parse(json);
        if (typeof obj !== "object" || obj === null) return null;

        const { set, minutes, meta, httpcloak } = obj;
        if (typeof set !== "string" || typeof minutes !== "number" || typeof meta !== "object" || meta === null) {
            return null;
        }

        const metaResult = sessionMetadataSchema.safeParse(meta);
        if (!metaResult.success) return null;

        const result: {
            proxySet: string;
            affinityMinutes: number;
            metadata: SessionMetadata;
            httpcloak?: HTTPCloakSpec;
        } = {
            proxySet: set,
            affinityMinutes: minutes,
            metadata: metaResult.data,
        };
        if (httpcloak !== undefined) {
            result.httpcloak = httpcloak;
        }
        return result;
    } catch {
        return null;
    }
}
