/** Trusted server integration only. Never build this context from client headers
 * or derive record_ids from the unfiltered response being checked.
 * Select contract from the server's route configuration, not client input.
 */
export interface DisclosureRequest {
  contract: string;
  context: {
    principal: string;
    tenant: string;
    permission: string;
    record_ids: string[];
  };
  response_body: string;
}

export interface GuardBinding {
  fetch(request: Request): Promise<Response>;
}

/** Return this Response directly. An exception never falls back to the original data.
 * The guard is a PRIVATE Worker Service Binding in the caller's account.
 */
export async function protectJson(binding: GuardBinding, disclosure: DisclosureRequest): Promise<Response> {
  try {
    return await binding.fetch(new Request('https://leak-fence.internal/v1/protect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(disclosure),
      signal: AbortSignal.timeout(6000),
    }));
  } catch {
    return new Response('{"error":"guard_unavailable"}', {
      status: 503,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    });
  }
}
