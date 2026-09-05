import { z } from "zod";
import { publicProcedure, router } from "./trpc";

/**
 * Minimal system router after dead-template removal (heartbeat/llm/voice/
 * image/map modules were unreferenced Manus template code).
 *
 * The notifyOwner mutation was removed with the notification module: it
 * existed only to serve the template's heartbeat cron system, which this
 * application never wires up. No client code referenced it.
 */
export const systemRouter = router({
  health: publicProcedure
    .input(
      z.object({
        timestamp: z.number().min(0, "timestamp cannot be negative"),
      })
    )
    .query(() => ({
      ok: true,
    })),
});
