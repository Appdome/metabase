import { t } from "ttag";

import { useSelector } from "metabase/redux";
import { Group, Icon } from "metabase/ui";
import * as Urls from "metabase/utils/urls";

import { getIsLdapEnabled } from "../../selectors";
import { AuthButton } from "../AuthButton";

interface PasswordButtonProps {
  redirectUrl?: string;
}

export const PasswordButton = ({ redirectUrl }: PasswordButtonProps) => {
  const isLdapEnabled = useSelector(getIsLdapEnabled);

  return (
    <AuthButton link={Urls.password(redirectUrl)}>
      <Group gap="sm" justify="center" wrap="nowrap">
        <Icon name="mail" />
        {isLdapEnabled
          ? t`Sign in with username or email`
          : t`Sign in with email`}
      </Group>
    </AuthButton>
  );
};
