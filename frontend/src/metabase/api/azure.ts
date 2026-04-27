import type { EnterpriseSettings } from "metabase-types/api";

import { Api } from "./api";
import { invalidateTags, tag } from "./tags";

export type AzureAuthSettings = Partial<
  Pick<
    EnterpriseSettings,
    | "azure-attribute-email"
    | "azure-attribute-firstname"
    | "azure-attribute-lastname"
    | "azure-attribute-groups"
    | "azure-group-sync"
    | "azure-group-mappings"
    | "azure-user-provisioning-enabled?"
  >
>;

export const azureApi = Api.injectEndpoints({
  endpoints: (builder) => ({
    updateAzureAuth: builder.mutation<void, AzureAuthSettings>({
      query: (settings) => ({
        method: "PUT",
        url: `/api/azure/settings`,
        body: settings,
      }),
      invalidatesTags: (_, error) =>
        invalidateTags(error, [tag("session-properties")]),
    }),
  }),
});

export const { useUpdateAzureAuthMutation } = azureApi;
