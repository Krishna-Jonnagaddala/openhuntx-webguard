import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  apiKeysApi,
  assetsApi,
  auditApi,
  authApi,
  dashboardApi,
  findingsApi,
  jobsApi,
  permitsApi,
  reportsApi,
  schedulesApi,
  scansApi,
  settingsApi,
  teamApi,
} from "../lib/api";

export function useChangePassword() {
  return useMutation({
    mutationFn: (body: { current_password: string; new_password: string }) => authApi.changePassword(body),
  });
}

export function useSignOutAllSessions() {
  return useMutation({ mutationFn: authApi.logoutAll });
}

export function useRequestEmailVerification() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: authApi.requestEmailVerification,
    onSuccess: () => client.invalidateQueries({ queryKey: ["settings"] }),
  });
}

export function useDashboardSummary() {
  return useQuery({ queryKey: ["dashboard-summary"], queryFn: dashboardApi.summary, refetchInterval: 15_000 });
}

export function useAssets() {
  return useQuery({ queryKey: ["assets"], queryFn: () => assetsApi.list() });
}

export function useAsset(id: string | undefined) {
  return useQuery({
    queryKey: ["asset", id],
    queryFn: () => assetsApi.get(id as string),
    enabled: !!id,
    refetchInterval: 5_000,
  });
}

export function useCreateAsset() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: assetsApi.create,
    onSuccess: () => client.invalidateQueries({ queryKey: ["assets"] }),
  });
}

export function useUpdateAsset() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: { label?: string | null; default_mode?: string | null } }) =>
      assetsApi.update(id, body),
    onSuccess: (_data, variables) => {
      client.invalidateQueries({ queryKey: ["assets"] });
      client.invalidateQueries({ queryKey: ["asset", variables.id] });
    },
  });
}

export function useStartVerification() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: assetsApi.startVerification,
    onSuccess: (_data, id) => client.invalidateQueries({ queryKey: ["asset", id] }),
  });
}

export function useCheckVerification() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: assetsApi.checkVerification,
    onSuccess: (_data, id) => client.invalidateQueries({ queryKey: ["asset", id] }),
  });
}

export function useScans(params?: { status?: string; target?: string }) {
  return useQuery({ queryKey: ["scans", params], queryFn: () => scansApi.list(params), refetchInterval: 5_000 });
}

export function useScan(id: string | undefined) {
  return useQuery({
    queryKey: ["scan", id],
    queryFn: () => scansApi.get(id as string),
    enabled: !!id,
    refetchInterval: 4_000,
  });
}

export function useIssuePermitAndSubmitJob() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async (params: { target: string; authorizationId: string; mode: "single_page" | "crawl" }) => {
      const permit = await permitsApi.issue(params);
      await new Promise((resolve) => setTimeout(resolve, 4000)); // permit not_before buffer (see permitsApi.issue)
      const job = await jobsApi.submit({
        target: params.target,
        authorizationId: params.authorizationId,
        mode: params.mode,
        permitId: permit.permit.claims.permit_id,
        idempotencyKey: `web-${crypto.randomUUID()}`,
      });
      return job;
    },
    onSuccess: () => {
      client.invalidateQueries({ queryKey: ["scans"] });
      client.invalidateQueries({ queryKey: ["jobs"] });
      client.invalidateQueries({ queryKey: ["dashboard-summary"] });
    },
  });
}

export function useCancelJob() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: jobsApi.cancel,
    onSuccess: () => client.invalidateQueries({ queryKey: ["scans"] }),
  });
}

export function useFindings(params?: {
  status?: string;
  severity?: string;
  scan_id?: string;
  cwe_id?: string;
  asset?: string;
}) {
  return useQuery({ queryKey: ["findings", params], queryFn: () => findingsApi.list(params) });
}

export function useFinding(id: string | undefined) {
  return useQuery({ queryKey: ["finding", id], queryFn: () => findingsApi.get(id as string), enabled: !!id });
}

export function useFindingEvents(id: string | undefined) {
  return useQuery({
    queryKey: ["finding-events", id],
    queryFn: () => findingsApi.events(id as string),
    enabled: !!id,
  });
}

export function useUpdateFindingStatus() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ id, status, reason }: { id: string; status: string; reason?: string }) =>
      findingsApi.updateStatus(id, status, reason),
    onSuccess: (_data, variables) => {
      client.invalidateQueries({ queryKey: ["findings"] });
      client.invalidateQueries({ queryKey: ["finding", variables.id] });
      client.invalidateQueries({ queryKey: ["finding-events", variables.id] });
      client.invalidateQueries({ queryKey: ["dashboard-summary"] });
    },
  });
}

export function useSchedules() {
  return useQuery({ queryKey: ["schedules"], queryFn: () => schedulesApi.list() });
}

export function useCreateSchedule() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async (params: {
      name: string;
      target: string;
      authorizationId: string;
      mode: "single_page" | "crawl";
      intervalSeconds: number;
    }) => {
      const permit = await permitsApi.issue(params);
      await new Promise((resolve) => setTimeout(resolve, 4000)); // permit not_before buffer (see permitsApi.issue)
      return schedulesApi.create({ ...params, permitId: permit.permit.claims.permit_id });
    },
    onSuccess: () => client.invalidateQueries({ queryKey: ["schedules"] }),
  });
}

export function useToggleSchedule() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ id, action }: { id: string; action: "pause" | "resume" }) =>
      action === "pause" ? schedulesApi.pause(id) : schedulesApi.resume(id),
    onSuccess: () => client.invalidateQueries({ queryKey: ["schedules"] }),
  });
}

export function useReports() {
  return useQuery({ queryKey: ["reports"], queryFn: () => reportsApi.list() });
}

export function useCreateReport() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: reportsApi.create,
    onSuccess: () => client.invalidateQueries({ queryKey: ["reports"] }),
  });
}

export function useTeam() {
  return useQuery({ queryKey: ["team"], queryFn: teamApi.list });
}

export function useInviteMember() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: teamApi.invite,
    onSuccess: () => client.invalidateQueries({ queryKey: ["team"] }),
  });
}

export function useUpdateMemberRole() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ id, role }: { id: string; role: string }) => teamApi.updateRole(id, role),
    onSuccess: () => client.invalidateQueries({ queryKey: ["team"] }),
  });
}

export function useRemoveMember() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: teamApi.remove,
    onSuccess: () => client.invalidateQueries({ queryKey: ["team"] }),
  });
}

export function useApiKeys() {
  return useQuery({ queryKey: ["api-keys"], queryFn: apiKeysApi.list });
}

export function useCreateApiKey() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ label, validityDays }: { label: string; validityDays?: number }) =>
      apiKeysApi.create(label, validityDays),
    onSuccess: () => client.invalidateQueries({ queryKey: ["api-keys"] }),
  });
}

export function useRevokeApiKey() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: apiKeysApi.revoke,
    onSuccess: () => client.invalidateQueries({ queryKey: ["api-keys"] }),
  });
}

export function useAuditLog(params?: { outcome?: string }) {
  return useQuery({ queryKey: ["audit-log", params], queryFn: () => auditApi.list(params) });
}

export function useSettings() {
  return useQuery({ queryKey: ["settings"], queryFn: settingsApi.get });
}
