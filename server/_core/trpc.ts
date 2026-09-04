import { NOT_ADMIN_ERR_MSG, UNAUTHED_ERR_MSG } from '@shared/const';
import { initTRPC, TRPCError } from "@trpc/server";
import superjson from "superjson";
import type { TrpcContext } from "./context";

/**
 * Error masking: deliberately thrown TRPCErrors (auth, authz, validation)
 * propagate untouched so clients can act on their messages — the client
 * relies on exact strings such as UNAUTHED_ERR_MSG to trigger login.
 *
 * Unexpected errors are wrapped by tRPC into INTERNAL_SERVER_ERROR whose
 * message falls back to the original cause's message (tRPC v11 behavior),
 * which can leak stack details, SQL, or driver internals to the client.
 * Those are replaced with a generic message after being logged server-side.
 */
const GENERIC_ERROR_MESSAGE = "The request could not be completed safely.";

const t = initTRPC.context<TrpcContext>().create({
  transformer: superjson,
  errorFormatter({ error, shape, path }) {
    const cause = error.cause;
    // Only mask when tRPC auto-derived the message from an unexpected
    // (non-TRPCError) cause — i.e. message === cause.message. A developer
    // who wrote an explicit differing message intended it to be shown.
    const isUnexpectedInternal =
      error.code === "INTERNAL_SERVER_ERROR" &&
      cause !== undefined &&
      cause !== null &&
      !(cause instanceof TRPCError) &&
      error.message === cause.message;

    if (!isUnexpectedInternal) {
      return shape;
    }

    console.error(
      JSON.stringify({
        event: "trpc_internal_error",
        path,
        originalMessage: String(cause.message ?? error.message).slice(0, 300),
      })
    );

    return {
      ...shape,
      message: GENERIC_ERROR_MESSAGE,
      data: {
        ...shape.data,
        stack: undefined,
      },
    };
  },
});

export const router = t.router;
export const publicProcedure = t.procedure;

const requireUser = t.middleware(async opts => {
  const { ctx, next } = opts;

  if (!ctx.user) {
    throw new TRPCError({ code: "UNAUTHORIZED", message: UNAUTHED_ERR_MSG });
  }

  return next({
    ctx: {
      ...ctx,
      user: ctx.user,
    },
  });
});

export const protectedProcedure = t.procedure.use(requireUser);

export const adminProcedure = t.procedure.use(
  t.middleware(async opts => {
    const { ctx, next } = opts;

    if (!ctx.user || ctx.user.role !== 'admin') {
      throw new TRPCError({ code: "FORBIDDEN", message: NOT_ADMIN_ERR_MSG });
    }

    return next({
      ctx: {
        ...ctx,
        user: ctx.user,
      },
    });
  }),
);
