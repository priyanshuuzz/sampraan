import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { startLogin } from "@/const";

export function useAuth() {
  const { data: user, isLoading, error, refetch } = trpc.auth.me.useQuery(undefined, {
    retry: false,
    staleTime: 5 * 60 * 1000, // 5 minutes
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
