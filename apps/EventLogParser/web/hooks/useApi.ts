"use client";

import { useQuery, UseQueryOptions } from "@tanstack/react-query";
import { api } from "../lib/api";

export function useApi<T>(
  key: unknown[],
  fn: () => Promise<T>,
  options?: Omit<UseQueryOptions<T>, "queryKey" | "queryFn">
) {
  return useQuery<T>({
    queryKey: key,
    queryFn: fn,
    ...options
  });
}

export { api };
