import { useMemo } from "react";
import { t } from "ttag";

import {
  SettingsPageWrapper,
  SettingsSection,
} from "metabase/admin/components/SettingsSection";
import {
  type AzureAuthSettings,
  useGetSettingsQuery,
  useUpdateAzureAuthMutation,
} from "metabase/api";
import { useSetting } from "metabase/common/hooks";
import {
  Form,
  FormErrorMessage,
  FormProvider,
  FormSubmitButton,
  FormSwitch,
  FormTextInput,
  FormTextarea,
} from "metabase/forms";
import { Alert, Flex, Stack, Text, Title } from "metabase/ui";

type FormShape = {
  "azure-attribute-email": string;
  "azure-attribute-firstname": string;
  "azure-attribute-lastname": string;
  "azure-attribute-groups": string;
  "azure-group-sync": boolean;
  "azure-group-mappings": string;
  "azure-user-provisioning-enabled?": boolean;
};

class InvalidMappingsError extends Error {}

const parseMappings = (raw: string): Record<string, number[]> => {
  const trimmed = raw.trim();
  if (trimmed.length === 0) {
    return {};
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    throw new InvalidMappingsError(t`Mappings must be valid JSON.`);
  }
  if (typeof parsed !== "object" || parsed == null || Array.isArray(parsed)) {
    throw new InvalidMappingsError(t`Mappings must be a JSON object.`);
  }
  return parsed as Record<string, number[]>;
};

const stringifyMappings = (value: Record<string, number[]> | undefined) =>
  value && Object.keys(value).length > 0 ? JSON.stringify(value, null, 2) : "";

export const SettingsAzureForm = (): JSX.Element => {
  const { data: settingValues } = useGetSettingsQuery();
  const [updateAzureAuth] = useUpdateAzureAuthMutation();

  const tenantId = useSetting("azure-tenant-id");
  const clientId = useSetting("azure-client-id");
  const isEnvEnabled = useSetting("azure-auth-enabled");
  const isConfigured = useSetting("azure-auth-configured");
  const siteUrl = useSetting("site-url");
  const redirectUri = `${siteUrl ?? ""}/auth/sso/azure/callback`;

  const initialValues = useMemo<FormShape>(
    () => ({
      "azure-attribute-email":
        settingValues?.["azure-attribute-email"] ?? "preferred_username",
      "azure-attribute-firstname":
        settingValues?.["azure-attribute-firstname"] ?? "given_name",
      "azure-attribute-lastname":
        settingValues?.["azure-attribute-lastname"] ?? "family_name",
      "azure-attribute-groups":
        settingValues?.["azure-attribute-groups"] ?? "groups",
      "azure-group-sync": settingValues?.["azure-group-sync"] ?? false,
      "azure-group-mappings": stringifyMappings(
        settingValues?.["azure-group-mappings"],
      ),
      "azure-user-provisioning-enabled?":
        settingValues?.["azure-user-provisioning-enabled?"] ?? true,
    }),
    [settingValues],
  );

  const onSubmit = async (
    values: FormShape,
    {
      setFieldError,
    }: {
      setFieldError: (field: string, message: string | undefined) => void;
    },
  ) => {
    let mappings: Record<string, number[]>;
    try {
      mappings = parseMappings(values["azure-group-mappings"]);
    } catch (err) {
      if (err instanceof InvalidMappingsError) {
        setFieldError("azure-group-mappings", err.message);
        return;
      }
      throw err;
    }
    const payload: AzureAuthSettings = {
      "azure-attribute-email": values["azure-attribute-email"],
      "azure-attribute-firstname": values["azure-attribute-firstname"],
      "azure-attribute-lastname": values["azure-attribute-lastname"],
      "azure-attribute-groups": values["azure-attribute-groups"],
      "azure-group-sync": values["azure-group-sync"],
      "azure-group-mappings": mappings,
      "azure-user-provisioning-enabled?":
        values["azure-user-provisioning-enabled?"],
    };
    await updateAzureAuth(payload).unwrap();
  };

  return (
    <SettingsPageWrapper title={t`Microsoft Azure AD`}>
      <SettingsSection>
        <Stack gap="md">
          <Title order={2}>{t`Sign in with Microsoft`}</Title>
          <Text c="text-secondary">
            {t`Tenant ID, Client ID, Client Secret, and the master enable flag are configured via environment variables only. Admins can fine-tune claim mappings, group sync, and auto-provisioning here.`}
          </Text>
          <EnvStatusAlert
            isEnvEnabled={isEnvEnabled}
            isConfigured={isConfigured}
            tenantId={tenantId}
            clientId={clientId}
          />
          <Alert
            color="info"
            title={t`Register this redirect URI in Microsoft Entra`}
          >
            <Text size="sm" ff="monospace">
              {redirectUri}
            </Text>
          </Alert>
        </Stack>
      </SettingsSection>

      <SettingsSection>
        <FormProvider
          initialValues={initialValues}
          enableReinitialize
          onSubmit={onSubmit}
        >
          {({ dirty }) => (
            <Form disabled={!dirty}>
              <Stack gap="md">
                <Title order={3}>{t`Attribute claim mapping`}</Title>
                <FormTextInput
                  name="azure-attribute-email"
                  label={t`Email claim`}
                  description={t`Default: preferred_username. Change to 'email' if the tenant emits a verified 'email' claim.`}
                />
                <FormTextInput
                  name="azure-attribute-firstname"
                  label={t`First name claim`}
                />
                <FormTextInput
                  name="azure-attribute-lastname"
                  label={t`Last name claim`}
                />
                <FormTextInput
                  name="azure-attribute-groups"
                  label={t`Groups claim`}
                />

                <Title order={3}>{t`Group synchronisation`}</Title>
                <FormSwitch
                  name="azure-group-sync"
                  label={t`Synchronise group memberships from Azure AD`}
                />
                <FormTextarea
                  name="azure-group-mappings"
                  label={t`Group mappings (JSON)`}
                  description={t`Map Azure AD group object IDs to Metabase group IDs. Example: {"aaaa-bbbb-...": [3, 4]}`}
                  autosize
                  minRows={4}
                />

                <Title order={3}>{t`User provisioning`}</Title>
                <FormSwitch
                  name="azure-user-provisioning-enabled?"
                  label={t`Auto-create Metabase accounts for new Azure users`}
                />

                <Flex justify="end">
                  <FormSubmitButton
                    label={t`Save changes`}
                    variant="filled"
                    disabled={!dirty}
                  />
                </Flex>
                <FormErrorMessage />
              </Stack>
            </Form>
          )}
        </FormProvider>
      </SettingsSection>
    </SettingsPageWrapper>
  );
};

interface EnvStatusAlertProps {
  isEnvEnabled: boolean;
  isConfigured: boolean;
  tenantId: string | null;
  clientId: string | null;
}

const EnvStatusAlert = ({
  isEnvEnabled,
  isConfigured,
  tenantId,
  clientId,
}: EnvStatusAlertProps) => {
  if (!isConfigured) {
    return (
      <Alert color="warning" title={t`Azure SSO is not configured`}>
        {t`Set MB_AZURE_TENANT_ID, MB_AZURE_CLIENT_ID, and MB_AZURE_CLIENT_SECRET in the environment, then restart Metabase.`}
      </Alert>
    );
  }
  if (!isEnvEnabled) {
    return (
      <Alert color="warning" title={t`Azure SSO is configured but disabled`}>
        {t`Set MB_AZURE_AUTH_ENABLED=true to enable login.`}
      </Alert>
    );
  }
  return (
    <Alert color="success" title={t`Azure SSO is active`}>
      <Stack gap="xs">
        <Text size="sm">
          {t`Tenant:`} {tenantId}
        </Text>
        <Text size="sm">
          {t`Client:`} {clientId}
        </Text>
      </Stack>
    </Alert>
  );
};
