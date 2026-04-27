import { t } from "ttag";

import { useSetting } from "metabase/common/hooks";

import { AuthCardBody } from "../../components/AuthCard";

export function AzureAuthCard() {
  const isConfigured = useSetting("azure-auth-configured");
  const isEnabled = useSetting("azure-auth-enabled");

  return (
    <AuthCardBody
      type="azure"
      title={t`Sign in with Microsoft`}
      description={t`Authenticate Metabase users against Microsoft Entra ID (Azure AD). Tenant, client ID, client secret, and the enable flag are set via environment variables.`}
      isEnabled={isEnabled}
      isConfigured={isConfigured}
    />
  );
}
