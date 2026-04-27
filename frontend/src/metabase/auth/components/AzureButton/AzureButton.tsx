import { t } from "ttag";

import { Link } from "metabase/common/components/Link";
import { Box } from "metabase/ui";

import S from "./AzureButton.module.css";

interface AzureButtonProps {
  redirectUrl?: string;
  isCard?: boolean;
}

export const buildSsoUrl = (redirectUrl?: string) => {
  const base = "/auth/sso/azure";
  return redirectUrl
    ? `${base}?redirect=${encodeURIComponent(redirectUrl)}`
    : base;
};

export const AzureButton = ({ redirectUrl, isCard }: AzureButtonProps) => {
  const href = buildSsoUrl(redirectUrl);
  return (
    <Box ta="center">
      <Link className={isCard ? S.CardLink : S.Link} to={href}>
        {t`Sign in with Microsoft`}
      </Link>
    </Box>
  );
};
