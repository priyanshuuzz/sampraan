import { trpc } from "@/lib/trpc";
import { toast } from "sonner";

export function useAuth() {
  // Session identity must never be served stale for long: the session cookie
  // is browser-wide, so a second tab logging in REPLACES this tab's session
  // server-side. With a long staleTime this tab kept rendering the previous
  // user (the reported "all tabs became the same user" symptom). The server
  // remains the sole authority — this only controls how fast the UI learns
  // who the server currently says we are. stаleTime is 0 and the query
  // revalidates on window focus, so switching to a tab shows the correct
  // identity within one round trip; data hooks keep their own short staleness.
  const { data: user, isLoading, error, refetch } = trpc.auth.me.useQuery(undefined, {
    retry: false,
    staleTime: 0,
    refetchOnWindowFocus: true,
  });

  const logoutMutation = trpc.auth.logout.useMutation({
    onSuccess: () => {
      toast.success("Signed out successfully");
      window.location.reload();
    },
    onError: (err) => {
      console.error("Logout error:", err);
      // Still reload even if mutation fails
      window.location.reload();
    },
  });

  const isAuthenticated = !!user;

  const logout = () => {
    logoutMutation.mutate();
  };

  return {
    user,
    loading: isLoading,
    error,
    isAuthenticated,
    logout,
    refetch,
  };
}
